import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import semver from 'semver';

const defaultRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const digestPattern = /^[a-f0-9]{64}$/;
const packageIdPattern = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const maxArtifactBytes = 32 * 1024 * 1024;
const knownPermissions = new Set([
  'commands.register', 'commands.execute', 'contributions.register', 'services.read',
  'sourceControl.register', 'scm.git.read', 'scm.git.write', 'fileDecorations.scm',
  'documentViews.register', 'documents.read', 'agents.register', 'models.generate',
  'workspace.read', 'workspace.write', 'process.execute', 'skills.read', 'storage.local'
]);
let schemaValidatorsPromise;

function fail(message) {
  throw new Error('Registry validation failed: ' + message);
}

async function schemaValidators() {
  if (!schemaValidatorsPromise) {
    schemaValidatorsPromise = (async () => {
      const schemaNames = ['registry', 'package-index', 'version'];
      const schemas = await Promise.all(schemaNames.map(async (name) => (
        JSON.parse(await fs.readFile(path.join(defaultRoot, 'schemas', name + '.schema.json'), 'utf8'))
      )));
      const ajv = new Ajv2020({ allErrors: true, strict: true });
      addFormats(ajv);
      return Object.fromEntries(schemaNames.map((name, index) => [name, ajv.compile(schemas[index])]));
    })();
  }
  return schemaValidatorsPromise;
}

function assertSchema(validate, value, label) {
  if (validate(value)) return;
  const detail = validate.errors && validate.errors[0]
    ? (validate.errors[0].instancePath || '/') + ' ' + validate.errors[0].message
    : 'schema mismatch';
  fail(label + ' does not match its schema: ' + detail + '.');
}

function safeRelative(value, label) {
  if (typeof value !== 'string' || !value || value.includes('\\')) fail(label + ' is not a POSIX relative path.');
  const normalized = path.posix.normalize(value);
  if (normalized !== value || normalized.startsWith('../') || normalized === '..' || normalized.startsWith('/')) fail(label + ' escapes the registry.');
  return normalized;
}

async function readJson(registryRoot, relative) {
  const normalized = safeRelative(relative, 'Path');
  const absolute = path.join(registryRoot, ...normalized.split('/'));
  const text = await fs.readFile(absolute, 'utf8');
  try { return JSON.parse(text); } catch (error) { fail(normalized + ' is invalid JSON: ' + error.message); }
}

async function digest(registryRoot, relative) {
  const normalized = safeRelative(relative, 'Digest path');
  const source = await fs.readFile(path.join(registryRoot, ...normalized.split('/')));
  // Registry metadata is committed as UTF-8 JSON. Normalize checkout line
  // endings so an index validated on Windows hashes the same canonical content
  // as a GitHub raw download or a Linux checkout. Binary plugin artifacts are
  // not part of this metadata chain and always use their literal bytes.
  const canonical = normalized.endsWith('.json')
    ? Buffer.from(source.toString('utf8').replace(/\r\n/g, '\n'), 'utf8')
    : source;
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

function assertDigest(value, label) {
  if (typeof value !== 'string' || !digestPattern.test(value)) fail(label + ' must be a lowercase SHA-256 digest.');
}

function assertObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(label + ' must be an object.');
}

function assertString(value, label) {
  if (typeof value !== 'string' || !value.trim()) fail(label + ' must be a non-empty string.');
}

function assertBoundedString(value, label, maximum) {
  assertString(value, label);
  if (value.length > maximum) fail(label + ' exceeds the supported length.');
  return value;
}

function assertTimestamp(value, label) {
  assertBoundedString(value, label, 96);
  if (Number.isNaN(Date.parse(value))) fail(label + ' is not a valid timestamp.');
}

function assertStringList(value, label, maximumEntries, maximumLength, pattern, allowed) {
  if (!Array.isArray(value) || value.length > maximumEntries) fail(label + ' is invalid.');
  const seen = new Set();
  for (const item of value) {
    if (typeof item !== 'string' || !item.trim() || item.length > maximumLength ||
        (pattern && !pattern.test(item)) || (allowed && !allowed.has(item)) || seen.has(item)) {
      fail(label + ' is invalid.');
    }
    seen.add(item);
  }
}

function assertLocalizedMap(value, label, maximumLength) {
  assertObject(value, label);
  const entries = Object.entries(value);
  if (entries.length === 0 || entries.length > 16) fail(label + ' is invalid.');
  for (const [locale, message] of entries) {
    if (!/^[A-Za-z0-9-]{2,32}$/.test(locale) || typeof message !== 'string' ||
        !message.trim() || message.length > maximumLength) fail(label + ' is invalid.');
  }
}

function expectedPackagePath(id) {
  const [publisher, name] = id.split('.');
  return 'packages/' + publisher + '/' + name + '/index.json';
}

function expectedVersionPath(id, version) {
  const [publisher, name] = id.split('.');
  return 'packages/' + publisher + '/' + name + '/versions/' + version + '.json';
}

export function isCanonicalSemanticVersion(value) {
  if (typeof value !== 'string') return false;
  return semver.valid(value) === value.split('+', 1)[0];
}

function assertSemanticVersion(value, label) {
  if (!isCanonicalSemanticVersion(value)) {
    fail(label + ' has an invalid semantic version: ' + String(value));
  }
}

function validateSummary(summary, label) {
  assertObject(summary, label);
  assertLocalizedMap(summary.displayName, label + ' displayName', 160);
  assertLocalizedMap(summary.description, label + ' description', 1200);
  assertStringList(summary.categories, label + ' categories', 16, 64, /^[a-z0-9-]+$/);
}

function validateEngines(engines, label) {
  assertObject(engines, label);
  for (const key of ['bobocloud', 'pluginApi']) {
    const range = assertBoundedString(engines[key], label + ' ' + key, 160).trim();
    if (semver.validRange(range) === null) fail(label + ' ' + key + ' is not a valid semantic-version range.');
  }
}

function validateArtifact(artifact, label) {
  assertObject(artifact, label);
  if (artifact.format !== 'boboplugin') fail(label + ' must describe a .boboplugin artifact.');
  assertBoundedString(artifact.url, label + ' URL', 2048);
  let parsed;
  try { parsed = new URL(artifact.url); } catch (_) { fail(label + ' URL is invalid.'); }
  const segments = parsed.pathname.split('/').filter(Boolean);
  const reference = segments[2] || '';
  if (parsed.protocol !== 'https:' || parsed.hostname !== 'raw.githubusercontent.com' || parsed.port ||
      parsed.username || parsed.password || parsed.search || parsed.hash || segments.length < 4 ||
      !parsed.pathname.endsWith('.boboplugin') ||
      !(reference === '' ? false : (/^[a-f0-9]{40}$/.test(reference) || /^v?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/.test(reference))) ||
      segments.some((segment) => !/^[A-Za-z0-9._-]+$/.test(segment))) {
    fail(label + ' URL is not an approved immutable GitHub Raw artifact endpoint.');
  }
  assertDigest(artifact.sha256, label + ' digest');
  if (!Number.isSafeInteger(artifact.size) || artifact.size < 1 || artifact.size > maxArtifactBytes) {
    fail(label + ' size is invalid.');
  }
}

function validateSource(source, label) {
  assertObject(source, label);
  assertBoundedString(source.repository, label + ' repository', 2048);
  let parsed;
  try { parsed = new URL(source.repository); } catch (_) { fail(label + ' repository is invalid.'); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash) {
    fail(label + ' repository is invalid.');
  }
  assertBoundedString(source.ref, label + ' ref', 160);
}

async function validateVersion(registryRoot, id, version, record, validators) {
  assertObject(record, id + '@' + version);
  const versionPath = safeRelative(record.path, id + '@' + version + ' path');
  if (versionPath !== expectedVersionPath(id, version)) fail(id + '@' + version + ' path is not canonical.');
  assertDigest(record.sha256, id + '@' + version + ' digest');
  if (await digest(registryRoot, versionPath) !== record.sha256) fail(id + '@' + version + ' digest does not match its descriptor.');
  const descriptor = await readJson(registryRoot, versionPath);
  assertSchema(validators.version, descriptor, versionPath);
  if (descriptor.schemaVersion !== 1 || descriptor.id !== id || descriptor.version !== version) fail(versionPath + ' has inconsistent identity.');
  assertTimestamp(descriptor.publishedAt, versionPath + ' publishedAt');
  validateEngines(descriptor.engines, versionPath + ' engines');
  validateArtifact(descriptor.artifact, versionPath + ' artifact');
  validateSource(descriptor.source, versionPath + ' source');
  assertStringList(descriptor.permissions, versionPath + ' permissions', 32, 120, /^[A-Za-z0-9.-]+$/, knownPermissions);
  assertStringList(descriptor.locales, versionPath + ' locales', 16, 32, /^[A-Za-z0-9-]+$/);
}

async function validatePackage(registryRoot, entry, validators) {
  assertObject(entry, 'Shard package entry');
  const id = entry.id;
  if (!packageIdPattern.test(id || '')) fail('Package id is invalid: ' + String(id));
  assertSemanticVersion(entry.latest, id + ' shard latest');
  const packagePath = safeRelative(entry.path, id + ' index path');
  if (packagePath !== expectedPackagePath(id)) fail(id + ' package index path is not canonical.');
  assertDigest(entry.sha256, id + ' index digest');
  if (await digest(registryRoot, packagePath) !== entry.sha256) fail(id + ' package index digest does not match.');
  const index = await readJson(registryRoot, packagePath);
  assertSchema(validators['package-index'], index, packagePath);
  if (index.schemaVersion !== 1 || index.id !== id || index.latest !== entry.latest) fail(packagePath + ' has inconsistent package identity.');
  const [publisher, name] = id.split('.');
  if (index.publisher !== publisher || index.name !== name) fail(packagePath + ' has inconsistent publisher or name.');
  validateSummary(index.summary, packagePath + ' summary');
  assertObject(index.versions, id + ' versions');
  const versions = Object.keys(index.versions);
  for (const version of versions) assertSemanticVersion(version, id);
  if (!Object.hasOwn(index.versions, index.latest)) fail(id + ' latest version is not indexed.');
  const higherVersion = versions.find((version) => semver.gt(version, index.latest));
  if (higherVersion) {
    const highest = versions.reduce((candidate, version) => semver.gt(version, candidate) ? version : candidate);
    fail(id + ' latest version ' + index.latest + ' is lower than indexed version ' + highest + '.');
  }
  for (const [version, record] of Object.entries(index.versions)) await validateVersion(registryRoot, id, version, record, validators);
}

export async function validateRegistry(registryRoot = defaultRoot) {
  const resolvedRoot = path.resolve(registryRoot);
  const validators = await schemaValidators();
  const registry = await readJson(resolvedRoot, 'registry.json');
  assertSchema(validators.registry, registry, 'registry.json');
  if (registry.schemaVersion !== 1 || registry.registryId !== 'bobocloud.marketplace') fail('Root registry identity is invalid.');
  assertTimestamp(registry.updatedAt, 'Root registry updatedAt');
  if (!registry.format || registry.format.shardPath !== 'indexes/<shard>.json' ||
      registry.format.packagePath !== 'packages/<publisher>/<name>/index.json' ||
      registry.format.versionPath !== 'packages/<publisher>/<name>/versions/<semver>.json') {
    fail('Root registry format is invalid.');
  }
  if (!registry.policy || registry.policy.artifactProtocol !== 'https' || registry.policy.artifactDigest !== 'sha256' ||
      registry.policy.immutableVersionDocuments !== true || !Array.isArray(registry.policy.artifactHosts) ||
      registry.policy.artifactHosts.length !== 1 || registry.policy.artifactHosts[0] !== 'raw.githubusercontent.com') {
    fail('Root registry artifact policy is invalid.');
  }
  if (!Array.isArray(registry.shards) || registry.shards.length === 0) fail('Root registry has no shards.');
  const ids = new Set();
  const shardIds = new Set();
  for (const shardEntry of registry.shards) {
    assertObject(shardEntry, 'Shard entry');
    const shardPath = safeRelative(shardEntry.path, 'Shard path');
    if (typeof shardEntry.id !== 'string' || !/^[a-z0-9-]+$/.test(shardEntry.id) || shardIds.has(shardEntry.id)) {
      fail('Shard id is invalid or duplicated: ' + String(shardEntry.id));
    }
    shardIds.add(shardEntry.id);
    if (shardPath !== 'indexes/' + shardEntry.id + '.json') fail('Shard path is not canonical: ' + shardPath);
    assertDigest(shardEntry.sha256, 'Shard digest');
    if (await digest(resolvedRoot, shardPath) !== shardEntry.sha256) fail(shardPath + ' digest does not match.');
    const shard = await readJson(resolvedRoot, shardPath);
    if (shard.schemaVersion !== 1 || shard.id !== shardEntry.id || !Array.isArray(shard.packages) ||
        Object.keys(shard).some((key) => key !== 'schemaVersion' && key !== 'id' && key !== 'packages')) {
      fail(shardPath + ' is invalid.');
    }
    if (shard.packages.length !== shardEntry.count) fail(shardPath + ' count does not match root registry.');
    for (const entry of shard.packages) {
      if (ids.has(entry.id)) fail('Package id appears in more than one shard: ' + entry.id);
      ids.add(entry.id);
      await validatePackage(resolvedRoot, entry, validators);
    }
  }
  return ids.size;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const count = await validateRegistry();
  console.log('Registry validation passed for ' + count + ' package(s).');
}
