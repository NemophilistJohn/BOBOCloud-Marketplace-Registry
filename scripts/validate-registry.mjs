import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const digestPattern = /^[a-f0-9]{64}$/;
const packageIdPattern = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const semverPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

function fail(message) {
  throw new Error('Registry validation failed: ' + message);
}

function safeRelative(value, label) {
  if (typeof value !== 'string' || !value || value.includes('\\')) fail(label + ' is not a POSIX relative path.');
  const normalized = path.posix.normalize(value);
  if (normalized !== value || normalized.startsWith('../') || normalized === '..' || normalized.startsWith('/')) fail(label + ' escapes the registry.');
  return normalized;
}

async function readJson(relative) {
  const normalized = safeRelative(relative, 'Path');
  const absolute = path.join(root, ...normalized.split('/'));
  const text = await fs.readFile(absolute, 'utf8');
  try { return JSON.parse(text); } catch (error) { fail(normalized + ' is invalid JSON: ' + error.message); }
}

async function digest(relative) {
  const normalized = safeRelative(relative, 'Digest path');
  const source = await fs.readFile(path.join(root, ...normalized.split('/')));
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

async function validateVersion(id, version, record) {
  if (!semverPattern.test(version)) fail(id + ' has an invalid semantic version: ' + version);
  assertObject(record, id + '@' + version);
  const versionPath = safeRelative(record.path, id + '@' + version + ' path');
  assertDigest(record.sha256, id + '@' + version + ' digest');
  if (await digest(versionPath) !== record.sha256) fail(id + '@' + version + ' digest does not match its descriptor.');
  const descriptor = await readJson(versionPath);
  if (descriptor.schemaVersion !== 1 || descriptor.id !== id || descriptor.version !== version) fail(versionPath + ' has inconsistent identity.');
  assertObject(descriptor.artifact, versionPath + ' artifact');
  if (descriptor.artifact.format !== 'boboplugin') fail(versionPath + ' must describe a .boboplugin artifact.');
  assertString(descriptor.artifact.url, versionPath + ' artifact URL');
  if (!descriptor.artifact.url.startsWith('https://raw.githubusercontent.com/')) fail(versionPath + ' artifact URL must use the approved GitHub Raw host.');
  assertDigest(descriptor.artifact.sha256, versionPath + ' artifact digest');
  if (!Number.isSafeInteger(descriptor.artifact.size) || descriptor.artifact.size <= 0) fail(versionPath + ' artifact size must be a positive integer.');
}

async function validatePackage(entry) {
  assertObject(entry, 'Shard package entry');
  const id = entry.id;
  if (!packageIdPattern.test(id || '')) fail('Package id is invalid: ' + String(id));
  const packagePath = safeRelative(entry.path, id + ' index path');
  assertDigest(entry.sha256, id + ' index digest');
  if (await digest(packagePath) !== entry.sha256) fail(id + ' package index digest does not match.');
  const index = await readJson(packagePath);
  if (index.schemaVersion !== 1 || index.id !== id || index.latest !== entry.latest) fail(packagePath + ' has inconsistent package identity.');
  assertObject(index.versions, id + ' versions');
  if (!Object.hasOwn(index.versions, index.latest)) fail(id + ' latest version is not indexed.');
  for (const [version, record] of Object.entries(index.versions)) await validateVersion(id, version, record);
}

const registry = await readJson('registry.json');
if (registry.schemaVersion !== 1 || registry.registryId !== 'bobocloud.marketplace') fail('Root registry identity is invalid.');
if (!registry.policy || registry.policy.artifactProtocol !== 'https' || registry.policy.artifactDigest !== 'sha256' ||
    registry.policy.immutableVersionDocuments !== true || !Array.isArray(registry.policy.artifactHosts) ||
    registry.policy.artifactHosts.length !== 1 || registry.policy.artifactHosts[0] !== 'raw.githubusercontent.com') {
  fail('Root registry artifact policy is invalid.');
}
if (!Array.isArray(registry.shards) || registry.shards.length === 0) fail('Root registry has no shards.');
const ids = new Set();
for (const shardEntry of registry.shards) {
  assertObject(shardEntry, 'Shard entry');
  const shardPath = safeRelative(shardEntry.path, 'Shard path');
  assertDigest(shardEntry.sha256, 'Shard digest');
  if (await digest(shardPath) !== shardEntry.sha256) fail(shardPath + ' digest does not match.');
  const shard = await readJson(shardPath);
  if (shard.schemaVersion !== 1 || shard.id !== shardEntry.id || !Array.isArray(shard.packages)) fail(shardPath + ' is invalid.');
  if (shard.packages.length !== shardEntry.count) fail(shardPath + ' count does not match root registry.');
  for (const entry of shard.packages) {
    if (ids.has(entry.id)) fail('Package id appears in more than one shard: ' + entry.id);
    ids.add(entry.id);
    await validatePackage(entry);
  }
}
console.log('Registry validation passed for ' + ids.size + ' package(s).');
