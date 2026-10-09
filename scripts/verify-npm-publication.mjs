// Offline compatibility check of the pinned npm implementation, not a publish.
// npm's real Publish, pacote, libnpmpack, and libnpmpublish run against a local
// tarball; registry, OIDC, and signing boundaries are replaced with assertions.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import console from 'node:console';
import { createHash } from 'node:crypto';
import {
  accessSync, constants, mkdirSync, mkdtempSync, readFileSync, realpathSync,
  rmSync, writeFileSync,
} from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import Module, { createRequire } from 'node:module';
import net from 'node:net';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import process from 'node:process';

assert.equal(process.argv.length, 3, 'Usage: node scripts/verify-npm-publication.mjs <npm-package-root>');
const npmRoot = realpathSync(resolve(process.argv[2]));
assert.equal(JSON.parse(readFileSync(join(npmRoot, 'package.json'), 'utf8')).version,
  '11.11.0', 'This verification is specific to npm@11.11.0');
const npmRequire = createRequire(join(npmRoot, 'package.json'));
const tempRoot = tmpdir();
accessSync(tempRoot, constants.W_OK);
const scratch = mkdtempSync(join(tempRoot, 'codex-npm-publication-'));
const originalEnv = { ...process.env };
const originalLoad = Module._load;
const originalFetch = globalThis.fetch;
const networkTargets = [[http, 'request'], [http, 'get'], [https, 'request'],
  [https, 'get'], [net, 'connect'], [net, 'createConnection']];
const originalNetwork = networkTargets.map(([target, key]) => target[key]);
const attempts = { lifecycle: [], oidc: 0, signing: 0, registry: 0, network: 0 };
const denyNetwork = () => {
  attempts.network += 1;
  throw new Error('Unexpected network access during offline npm verification');
};
const sourceFiles = ['lib/commands/publish.js', 'node_modules/libnpmpack/lib/index.js',
  'node_modules/libnpmpublish/lib/publish.js', 'node_modules/libnpmpublish/lib/provenance.js'];
let statement;
let metadata;

try {
  globalThis.fetch = denyNetwork;
  networkTargets.forEach(([target, key]) => { target[key] = denyNetwork; });
  Object.assign(process.env, {
    GITHUB_ACTIONS: 'true', GITHUB_SERVER_URL: 'https://github.com',
    GITHUB_REPOSITORY: 'abruption/codex-unlock', GITHUB_REPOSITORY_ID: '123',
    GITHUB_REPOSITORY_OWNER_ID: '456', GITHUB_EVENT_NAME: 'push',
    GITHUB_REF: 'refs/heads/main', GITHUB_SHA: 'a'.repeat(40),
    GITHUB_WORKFLOW_REF: 'abruption/codex-unlock/.github/workflows/release-please.yml@refs/heads/main',
    GITHUB_RUN_ID: '123456', GITHUB_RUN_ATTEMPT: '1', RUNNER_ENVIRONMENT: 'github-hosted',
    ACTIONS_ID_TOKEN_REQUEST_URL: 'https://oidc.invalid/offline-only',
  });
  // Do not expose inherited credentials to the synthetic npm invocation.
  for (const key of ['NPM_TOKEN', 'NODE_AUTH_TOKEN', 'NPM_ID_TOKEN', 'SIGSTORE_ID_TOKEN',
    'ACTIONS_ID_TOKEN_REQUEST_TOKEN']) {
    delete process.env[key];
  }

  const registry = 'https://registry.npmjs.org/';
  const actualNpmFetch = npmRequire('npm-registry-fetch');
  const mockedFetch = Object.assign(async (url, options) => {
    attempts.registry += 1;
    assert.equal(url, 'codex-unlock');
    assert.equal(options.method, 'PUT');
    assert.equal(options.registry, registry);
    metadata = options.body;
    return {};
  }, actualNpmFetch, {
    pickRegistry: () => registry,
    json: () => { throw new Error('Unexpected registry JSON request'); },
  });
  const mockedSigstore = {
    attest: async (payload, payloadType) => {
      attempts.signing += 1;
      assert.equal(payloadType, 'application/vnd.in-toto+json');
      statement = JSON.parse(payload.toString('utf8'));
      return { mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.3',
        dsseEnvelope: { payloadType, payload: payload.toString('base64') },
        verificationMaterial: { tlogEntries: [] } };
    },
    verify: () => { throw new Error('Unexpected provenance-file verification'); },
  };
  const mockedOidc = { oidc: async ({ packageName, registry: target }) => {
    attempts.oidc += 1;
    assert.equal(packageName, 'codex-unlock');
    assert.equal(target, registry);
  } };
  Module._load = function (request, parent, isMain) {
    if (request === 'npm-registry-fetch') return mockedFetch;
    if (request === 'sigstore') return mockedSigstore;
    if (request === 'ci-info') return { GITHUB_ACTIONS: true, GITLAB: false, name: 'GitHub Actions' };
    if (request === '@npmcli/run-script') return async (options) => {
      attempts.lifecycle.push(options.event);
      throw new Error(`Unexpected lifecycle script: ${options.event}`);
    };
    if (request.endsWith('/utils/oidc.js')) return mockedOidc;
    return originalLoad.call(this, request, parent, isMain);
  };

  const packageDirectory = join(scratch, 'build', 'package');
  const publicationDirectory = join(scratch, 'publication');
  mkdirSync(packageDirectory, { recursive: true, mode: 0o700 });
  mkdirSync(publicationDirectory, { mode: 0o700 });
  const manifest = { name: 'codex-unlock', version: '0.0.0-offline',
    description: 'Offline publication boundary fixture',
    // Deliberately differs from the workflow SHA: provenance must use the
    // workflow environment rather than trusting package-supplied gitHead.
    gitHead: 'b'.repeat(40), scripts: Object.fromEntries(
      ['prepare', 'prepack', 'postpack', 'prepublishOnly', 'publish', 'postpublish']
        .map(event => [event, 'node -e "process.exit(99)"'])) };
  writeFileSync(join(packageDirectory, 'package.json'), `${JSON.stringify(manifest)}\n`);
  writeFileSync(join(packageDirectory, 'README.md'), 'Offline publication fixture.\n');
  const tarballPath = join(publicationDirectory, 'codex-unlock-0.0.0-offline.tgz');
  await npmRequire('tar').c({ cwd: join(scratch, 'build'), file: tarballPath,
    gzip: true, portable: true, mtime: new Date('2000-01-01T00:00:00Z') }, ['package']);
  const transferredBytes = readFileSync(tarballPath);
  const expectedDigest = createHash('sha512').update(transferredBytes).digest('hex');
  // Only a transferred tarball exists at the publication prefix: no checkout,
  // installed package tree, or local package.json is needed for this path.
  const pacote = npmRequire('pacote');
  pacote.packument = async () => ({ versions: {} });
  const settings = { unicode: false, 'dry-run': false, json: true, tag: 'offline-check',
    'ignore-scripts': true, force: false, workspaces: false, workspace: [],
    'foreground-scripts': false };
  const npm = {
    localPrefix: publicationDirectory, silent: true,
    flatOptions: { ignoreScripts: true, registry, access: 'public', provenance: true,
      defaultTag: 'offline-check', npmVersion: '11.11.0', cache: join(scratch, 'cache') },
    config: { get: key => settings[key], isDefault: () => false, validate: () => {},
      getCredentialsByURI: () => ({ token: 'offline-placeholder-never-transmitted' }) },
  };
  const Publish = npmRequire(join(npmRoot, 'lib/commands/publish.js'));
  await new Publish(npm).exec([tarballPath]);

  assert.deepEqual(attempts, { lifecycle: [], oidc: 1, signing: 1, registry: 1, network: 0 });
  const attachment = metadata._attachments['codex-unlock-0.0.0-offline.tgz'];
  assert.equal(attachment.length, transferredBytes.length);
  assert.deepEqual(Buffer.from(attachment.data, 'base64'), transferredBytes);
  assert.deepEqual(readFileSync(tarballPath), transferredBytes);
  assert.equal(metadata.versions[manifest.version].dist.integrity,
    `sha512-${createHash('sha512').update(transferredBytes).digest('base64')}`);
  assert.deepEqual(statement.subject, [{ name: 'pkg:npm/codex-unlock@0.0.0-offline',
    digest: { sha512: expectedDigest } }]);
  assert.equal(statement.predicateType, 'https://slsa.dev/provenance/v1');
  assert.deepEqual(statement.predicate.buildDefinition.externalParameters.workflow,
    { ref: 'refs/heads/main', repository: 'https://github.com/abruption/codex-unlock',
      path: '.github/workflows/release-please.yml' });
  assert.deepEqual(statement.predicate.buildDefinition.resolvedDependencies,
    [{ uri: 'git+https://github.com/abruption/codex-unlock@refs/heads/main',
      digest: { gitCommit: 'a'.repeat(40) } }]);
  assert.equal(statement.predicate.runDetails.metadata.invocationId,
    'https://github.com/abruption/codex-unlock/actions/runs/123456/attempts/1');
  console.log(JSON.stringify({ status: 'ok', npmVersion: '11.11.0', attempts,
    tarballBytes: transferredBytes.length, sha512: expectedDigest,
    sourceSha256: Object.fromEntries(sourceFiles.map(file => [file,
      createHash('sha256').update(readFileSync(join(npmRoot, file))).digest('hex')])),
    limitations: ['Synthetic tarball and GitHub environment; no actual trusted-publisher authorization.',
      'Registry transport, OIDC exchange, and Sigstore signing are mocked; no cryptographic verification.',
      'Publish.exec receives explicit configuration; npm bin flag parsing and config discovery are not exercised.',
      'Provenance identifies the workflow run and its GITHUB_SHA, not an independently verified build.'],
  }, null, 2));
} finally {
  Module._load = originalLoad;
  globalThis.fetch = originalFetch;
  networkTargets.forEach(([target, key], index) => { target[key] = originalNetwork[index]; });
  for (const key of Object.keys(process.env)) {
    if (!(key in originalEnv)) delete process.env[key];
  }
  Object.assign(process.env, originalEnv);
  rmSync(scratch, { recursive: true, force: true });
}
