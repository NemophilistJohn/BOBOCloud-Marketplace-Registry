import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import semver from 'semver';
import { isCanonicalSemanticVersion, validateRegistry } from '../scripts/validate-registry.mjs';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

async function readJson(root, relative) {
  return JSON.parse(await readFile(path.join(root, ...relative.split('/')), 'utf8'));
}

async function writeJson(root, relative, value) {
  await writeFile(path.join(root, ...relative.split('/')), JSON.stringify(value, null, 2) + '\n');
}

async function digest(root, relative) {
  const bytes = await readFile(path.join(root, ...relative.split('/')));
  const canonical = Buffer.from(bytes.toString('utf8').replace(/\r\n/g, '\n'), 'utf8');
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

async function createRegistryFixture(t) {
  const fixtureRoot = await mkdtemp(path.join(os.tmpdir(), 'bobocloud-registry-'));
  await cp(path.join(repositoryRoot, 'registry.json'), path.join(fixtureRoot, 'registry.json'));
  await cp(path.join(repositoryRoot, 'indexes'), path.join(fixtureRoot, 'indexes'), { recursive: true });
  await cp(path.join(repositoryRoot, 'packages'), path.join(fixtureRoot, 'packages'), { recursive: true });
  t.after(() => rm(fixtureRoot, { recursive: true, force: true }));
  return fixtureRoot;
}

async function mutatePackageIndex(root, packageId, mutate) {
  const registry = await readJson(root, 'registry.json');
  for (const shardEntry of registry.shards) {
    const shard = await readJson(root, shardEntry.path);
    const packageEntry = shard.packages.find((entry) => entry.id === packageId);
    if (!packageEntry) continue;
    const index = await readJson(root, packageEntry.path);
    mutate(index);
    packageEntry.latest = index.latest;
    await writeJson(root, packageEntry.path, index);
    packageEntry.sha256 = await digest(root, packageEntry.path);
    await writeJson(root, shardEntry.path, shard);
    shardEntry.sha256 = await digest(root, shardEntry.path);
    await writeJson(root, 'registry.json', registry);
    return;
  }
  throw new Error('Fixture package not found: ' + packageId);
}

async function mutateVersionDescriptor(root, packageId, version, mutate) {
  const registry = await readJson(root, 'registry.json');
  for (const shardEntry of registry.shards) {
    const shard = await readJson(root, shardEntry.path);
    const packageEntry = shard.packages.find((entry) => entry.id === packageId);
    if (!packageEntry) continue;
    const index = await readJson(root, packageEntry.path);
    const versionEntry = index.versions[version];
    if (!versionEntry) throw new Error('Fixture version not found: ' + packageId + '@' + version);
    const descriptor = await readJson(root, versionEntry.path);
    mutate(descriptor);
    await writeJson(root, versionEntry.path, descriptor);
    versionEntry.sha256 = await digest(root, versionEntry.path);
    await writeJson(root, packageEntry.path, index);
    packageEntry.sha256 = await digest(root, packageEntry.path);
    await writeJson(root, shardEntry.path, shard);
    shardEntry.sha256 = await digest(root, shardEntry.path);
    await writeJson(root, 'registry.json', registry);
    return;
  }
  throw new Error('Fixture package not found: ' + packageId);
}

test('the committed registry passes strict offline validation', async () => {
  assert.equal(await validateRegistry(repositoryRoot), 3);
});

test('numeric prerelease identifiers with leading zeroes are rejected', async (t) => {
  const fixtureRoot = await createRegistryFixture(t);
  await mutatePackageIndex(fixtureRoot, 'bobocloud.ai-agent', (index) => {
    index.versions['1.3.1-01'] = index.versions['1.3.1'];
  });
  await assert.rejects(
    validateRegistry(fixtureRoot),
    /does not match its schema|invalid semantic version: 1\.3\.1-01/
  );
});

test('latest must be the highest indexed semantic version', async (t) => {
  const fixtureRoot = await createRegistryFixture(t);
  let lowerVersion = '';
  let highestVersion = '';
  await mutatePackageIndex(fixtureRoot, 'bobocloud.ai-agent', (index) => {
    const versions = Object.keys(index.versions).sort(semver.compare);
    lowerVersion = versions.at(-2);
    highestVersion = versions.at(-1);
    index.latest = lowerVersion;
  });
  await assert.rejects(
    validateRegistry(fixtureRoot),
    (error) => error.message.includes(
      'latest version ' + lowerVersion + ' is lower than indexed version ' + highestVersion
    )
  );
});

test('rehashed package and version paths must remain canonical for their identities', async (t) => {
  const fixtureRoot = await createRegistryFixture(t);
  await mutatePackageIndex(fixtureRoot, 'bobocloud.ai-agent', (index) => {
    index.versions['1.3.1'].path = 'packages/bobocloud/ai-agent/versions/1.3.0.json';
  });
  await assert.rejects(
    validateRegistry(fixtureRoot),
    /bobocloud\.ai-agent@1\.3\.1 path is not canonical/
  );
});

test('rehashed package identity fields must match the canonical plugin id', async (t) => {
  const fixtureRoot = await createRegistryFixture(t);
  await mutatePackageIndex(fixtureRoot, 'bobocloud.ai-agent', (index) => {
    index.publisher = 'different';
  });
  await assert.rejects(
    validateRegistry(fixtureRoot),
    /inconsistent publisher or name/
  );
});

test('rehashed descriptors still reject permissions the host does not implement', async (t) => {
  const fixtureRoot = await createRegistryFixture(t);
  await mutateVersionDescriptor(fixtureRoot, 'bobocloud.ai-agent', '1.3.1', (descriptor) => {
    descriptor.permissions.push('host.everything');
  });
  await assert.rejects(
    validateRegistry(fixtureRoot),
    /permissions is invalid/
  );
});

test('schema patterns match strict SemVer prerelease rules', async () => {
  const packageSchema = await readJson(repositoryRoot, 'schemas/package-index.schema.json');
  const versionSchema = await readJson(repositoryRoot, 'schemas/version.schema.json');
  const patterns = [
    packageSchema.properties.latest.pattern,
    packageSchema.properties.versions.propertyNames.pattern,
    versionSchema.properties.version.pattern
  ].map((pattern) => new RegExp(pattern));
  const valid = ['0.0.0', '1.2.3-0', '1.2.3-alpha.0', '1.2.3-01a', '1.2.3+build.01'];
  const invalid = ['v1.2.3', '01.2.3', '1.02.3', '1.2.03', '1.2.3-01', '1.2.3-alpha.01', '1.2.3-'];
  for (const version of valid) assert.equal(isCanonicalSemanticVersion(version), true, version);
  for (const version of invalid) assert.equal(isCanonicalSemanticVersion(version), false, version);
  for (const pattern of patterns) {
    for (const version of valid) assert.match(version, pattern);
    for (const version of invalid) assert.doesNotMatch(version, pattern);
  }
});
