import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { log } from "node:console";
import {
  constants, copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync,
  rmSync, writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import process from "node:process";

import { marked } from "marked";
import { parseFragment } from "parse5";
import { parseSrcset } from "srcset";

import { assertConsumerShrinkwrap, consumerShrinkwrap } from "./consumer-shrinkwrap.mjs";

const npmCli = process.env.npm_execpath;
assert.ok(npmCli, "Run through npm run smoke:package");
const args = process.argv.slice(2);
assert.ok(args.length === 0 ||
  (args.length === 2 && args[0] === "--release-artifact-directory"),
"Usage: npm run smoke:package [-- --release-artifact-directory <new-directory>]");
const releaseDirectory = args.length === 2 ? resolve(args[1]) : null;

// package-lock.json is the repository lockfile. The published
// npm-shrinkwrap.json is generated from it with only the runtime tree, and it
// pins that tree for consumers, so the published manifest must match it.
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const htmlLinkDestinations = (html) => {
  const destinations = [];
  const visit = (node) => {
    for (const attribute of node.attrs ?? []) {
      if ((attribute.name === "href" || attribute.name === "src") && attribute.value) {
        destinations.push(attribute.value);
      } else if (attribute.name === "srcset") {
        destinations.push(...parseSrcset(attribute.value, { strict: true }).map(({ url }) => url));
      }
    }
    for (const child of node.childNodes ?? []) visit(child);
  };
  visit(parseFragment(html));
  return destinations;
};
const markdownLinkDestinations = (markdown) => {
  const destinations = [];
  marked.walkTokens(marked.lexer(markdown), (token) => {
    if (token.type === "link" || token.type === "image") destinations.push(token.href);
    if (token.type === "html") destinations.push(...htmlLinkDestinations(token.raw));
  });
  return destinations;
};
const isExternalLink = (href) => /^(?:[a-z][a-z\d+.-]*:|\/\/)/i.test(href);
const decodeLinkPath = (path) =>
  path.replace(/(?:%[\da-f]{2})+/gi, (escapeSequence) => {
    try {
      return decodeURIComponent(escapeSequence);
    } catch {
      return escapeSequence;
    }
  });
assert.deepEqual(
  markdownLinkDestinations("[![platform](badge.svg)](docs/platform-support.md)"),
  ["docs/platform-support.md", "badge.svg"],
  "Markdown link extraction must include destinations around nested images",
);
assert.deepEqual(
  markdownLinkDestinations("[guide][docs]\n\n[docs]: docs/guide.md"),
  ["docs/guide.md"],
  "Markdown link extraction must include reference-style destinations",
);
assert.deepEqual(
  markdownLinkDestinations("![demo][asset]\n\n[asset]: <docs/assets/demo image.gif>"),
  ["docs/assets/demo image.gif"],
  "Markdown link extraction must include angle-bracket reference destinations",
);
assert.deepEqual(
  markdownLinkDestinations("[^1]: More details\n\n~~~text\n[not a link](missing.md)\n~~~\n\n````md\n![not an image](missing.gif)\n````"),
  [],
  "Markdown link extraction must ignore footnote-like text and fenced code blocks",
);
const schemeExamples = markdownLinkDestinations(
  "[web](web+codex://open) [client](x-github-client://open)",
);
assert.deepEqual(schemeExamples, ["web+codex://open", "x-github-client://open"]);
assert.ok(schemeExamples.every(isExternalLink), "Valid URI schemes must not be resolved as files");
assert.deepEqual(
  markdownLinkDestinations(
    '<a href="docs/guide.md">Guide</a> <img alt="demo" src=\'docs/assets/demo.gif\'>',
  ),
  ["docs/guide.md", "docs/assets/demo.gif"],
  "Markdown link extraction must include relative targets in raw HTML",
);
assert.deepEqual(
  markdownLinkDestinations(
    '<a href="README&#46;ko&#46;md">한국어</a><picture><source srcset="docs/dark.png 1x, docs/dark@2x.png 2x"><img srcset="docs/light.png 1x, docs/light@2x.png 2x"></picture>',
  ),
  ["README.ko.md", "docs/dark.png", "docs/dark@2x.png", "docs/light.png", "docs/light@2x.png"],
  "Markdown link extraction must decode HTML references and collect every srcset candidate",
);
assert.deepEqual(
  markdownLinkDestinations("<!-- <a href=\"missing.md\"> -->\n~~~html\n<img src=\"missing.gif\">\n~~~"),
  [],
  "Markdown link extraction must ignore HTML comments and code examples",
);
assert.equal(decodeLinkPath("docs/100%-coverage.md"), "docs/100%-coverage.md");
assert.equal(decodeLinkPath("docs/a%20b.md"), "docs/a b.md");
const workspaceManifest = readJson(resolve("package.json"));
const shrinkwrap = consumerShrinkwrap(readJson(resolve("package-lock.json")));
assertConsumerShrinkwrap(shrinkwrap, workspaceManifest);
assert.deepEqual(
  Object.keys(shrinkwrap.packages).sort(),
  ["", "node_modules/fs-ext-extra-prebuilt", "node_modules/nan"],
  "The published shrinkwrap must contain only the native runtime tree",
);
const shrinkwrapPath = resolve("npm-shrinkwrap.json");
const previousShrinkwrap = existsSync(shrinkwrapPath) ? readFileSync(shrinkwrapPath) : null;
const pinnedRuntime = {
  "fs-ext-extra-prebuilt": shrinkwrap.packages["node_modules/fs-ext-extra-prebuilt"]?.version,
  nan: shrinkwrap.packages["node_modules/nan"]?.version,
};
for (const [name, version] of Object.entries(pinnedRuntime)) {
  assert.match(version ?? "", /^\d+\.\d+\.\d+$/, `package-lock.json must pin ${name}`);
}
assert.deepEqual(
  workspaceManifest.dependencies,
  { "fs-ext-extra-prebuilt": pinnedRuntime["fs-ext-extra-prebuilt"] },
  "The native runtime dependency must be an exact version equal to package-lock.json",
);

// Every package directory under node_modules, including nested copies, so an
// extraneous tree installed from the shrinkwrap cannot hide behind hoisting.
const installedPackages = (root) => {
  const found = [];
  const walk = (modules) => {
    if (!existsSync(modules)) return;
    for (const entry of readdirSync(modules, { withFileTypes: true })) {
      if (!entry.isDirectory() || entry.name.startsWith(".")) continue;
      const scoped = entry.name.startsWith("@");
      const directories = scoped
        ? readdirSync(join(modules, entry.name), { withFileTypes: true })
          .filter((child) => child.isDirectory())
          .map((child) => join(modules, entry.name, child.name))
        : [join(modules, entry.name)];
      for (const directory of directories) {
        if (existsSync(join(directory, "package.json"))) {
          found.push(readJson(join(directory, "package.json")).name);
        }
        walk(join(directory, "node_modules"));
      }
    }
  };
  walk(join(root, "node_modules"));
  return found.sort();
};

const directory = mkdtempSync(join(tmpdir(), "codex-unlock-package-smoke-"));
const npm = (args, cwd = process.cwd()) =>
  execFileSync(process.execPath, [npmCli, ...args], {
    cwd,
    encoding: "utf8",
    timeout: 120_000,
    stdio: ["ignore", "pipe", "pipe"],
  });

try {
  // Written only for packing; restored or removed below so a stale
  // shrinkwrap never overrides package-lock.json for local installs.
  writeFileSync(shrinkwrapPath, `${JSON.stringify(shrinkwrap, null, 2)}\n`);
  const [packed] = JSON.parse(
    npm(["pack", "--json", "--ignore-scripts", "--pack-destination", directory]),
  );
  const expectedFiles = [
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "README.ja.md",
    "README.ko.md",
    "README.md",
    "README.zh-CN.md",
    "SECURITY.md",
    "dist/cli.js",
    "dist/coordination.js",
    "dist/doctor.js",
    "dist/inspection.js",
    "dist/json-types.d.ts",
    "dist/lock.js",
    "dist/native-coordination.js",
    "dist/options.js",
    "dist/policy.js",
    "dist/process.js",
    "dist/transcript.js",
    "dist/types.js",
    "dist/types.d.ts",
    "dist/unlock.js",
    "dist/update.js",
    "dist/util.js",
    "docs/cli-reference.md",
    "docs/json-v1.md",
    "docs/maintainer-release.md",
    "docs/platform-support.md",
    "docs/safety-race-matrix.md",
    "docs/update-security.md",
    "docs/upstream-handoff-proposal.md",
    "docs/v0.2-migration.md",
    "npm-shrinkwrap.json",
    "package.json",
    "schemas/codex-unlock-v1.schema.json",
  ].sort();
  assert.deepEqual(
    packed.files.map(({ path }) => path).sort(),
    expectedFiles,
    "Package contents must match the explicit public artifact allowlist",
  );

  const cacheDirectory = join(directory, "npm-cache");
  const primeDirectory = join(directory, "cache-prime");
  mkdirSync(primeDirectory);
  npm(
    [
      "install",
      "--prefix",
      primeDirectory,
      "--cache",
      cacheDirectory,
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      join(directory, packed.filename),
    ],
    primeDirectory,
  );
  rmSync(primeDirectory, { recursive: true, force: true });

  const installDirectory = join(directory, "installation");
  mkdirSync(installDirectory);
  npm(
    [
      "install",
      "--prefix",
      installDirectory,
      "--cache",
      cacheDirectory,
      "--offline",
      "--no-audit",
      "--no-fund",
      join(directory, packed.filename),
    ],
    installDirectory,
  );

  // A regular dependency install (not --omit=dev) must install only the
  // runtime tree: npm installs every entry of a dependency's shrinkwrap.
  assert.deepEqual(
    installedPackages(installDirectory),
    ["codex-unlock", "fs-ext-extra-prebuilt", "nan"],
    "A dependency install must not add development packages from the shrinkwrap",
  );
  const packageRoot = join(installDirectory, "node_modules", "codex-unlock");
  const manifest = readJson(join(packageRoot, "package.json"));
  const readmes = ["README.md", "README.ko.md", "README.ja.md", "README.zh-CN.md"];
  for (const readme of readmes) {
    const source = readFileSync(resolve(readme), "utf8");
    const artifact = readFileSync(join(packageRoot, readme), "utf8");
    assert.equal(artifact, source, `${readme} content must be preserved in the packed artifact`);
    const destinations = markdownLinkDestinations(artifact);
    for (const localeReadme of readmes) {
      if (localeReadme === readme) continue;
      assert.ok(
        destinations.includes(localeReadme),
        `${readme} must link to the ${localeReadme} language version`,
      );
    }
    for (const href of destinations) {
      if (isExternalLink(href) || href.startsWith("#")) continue;
      const target = decodeLinkPath(href.split(/[?#]/, 1)[0]);
      if (!target) continue;
      const targetPath = resolve(packageRoot, target);
      assert.ok(
        !relative(packageRoot, targetPath).startsWith(".."),
        `${readme} link must stay within the packed artifact: ${href}`,
      );
      assert.ok(
        existsSync(targetPath),
        `${readme} relative link target must be included in the packed artifact: ${href}`,
      );
    }
  }
  assertConsumerShrinkwrap(readJson(join(packageRoot, "npm-shrinkwrap.json")), manifest);

  // Resolve the way the installed CLI does, so a hoisted or nested copy is checked.
  const installedVersion = (name, fromPackageRoot) => {
    const manifestPath = createRequire(join(fromPackageRoot, "package.json"))
      .resolve(`${name}/package.json`);
    assert.ok(
      !relative(realpathSync(installDirectory), manifestPath).startsWith(".."),
      `${name} must resolve inside the clean installation`,
    );
    return { root: dirname(manifestPath), version: readJson(manifestPath).version };
  };
  const nativeDependency = installedVersion("fs-ext-extra-prebuilt", packageRoot);
  assert.deepEqual(
    {
      "fs-ext-extra-prebuilt": nativeDependency.version,
      nan: installedVersion("nan", nativeDependency.root).version,
    },
    pinnedRuntime,
    "Installed runtime dependencies must equal the package-lock.json runtime pins",
  );
  assert.equal(manifest.bin["codex-unlock"], "dist/cli.js");
  assert.deepEqual(manifest.exports, {
    "./types": { types: "./dist/json-types.d.ts" },
    "./package.json": "./package.json",
  });
  assert.equal(manifest.main, undefined);
  assert.equal(manifest.types, "dist/json-types.d.ts");
  assert.match(readFileSync(resolve(packageRoot, manifest.types), "utf8"), /export type/);
  assert.equal(manifest.scripts.prepare, "npm run build");
  assert.equal(manifest.scripts.prepack, undefined);
  assert.match(
    readFileSync(resolve(packageRoot, manifest.bin["codex-unlock"]), "utf8"),
    /^#!\/usr\/bin\/env node/,
  );
  assert.equal(
    npm(["exec", "--offline", "--", "codex-unlock", "--version"], installDirectory).trim(),
    manifest.version,
  );
  assert.match(
    npm(["exec", "--offline", "--", "codex-unlock", "--help"], installDirectory),
    /codex-unlock/,
  );
  const emptyHome = join(directory, "empty-home");
  mkdirSync(emptyHome);
  const jsonOutput = npm(
    ["exec", "--offline", "--", "codex-unlock", "list", "--json", "--codex-home", emptyHome],
    installDirectory,
  );
  assert.equal(JSON.parse(jsonOutput).schemaVersion, 1);

  assert.throws(
    () => execFileSync(
      process.execPath,
      ["--input-type=module", "--eval", "await import('codex-unlock')"],
      { cwd: installDirectory, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    ),
    (error) => error?.stderr?.includes("ERR_PACKAGE_PATH_NOT_EXPORTED"),
  );
  assert.throws(
    () => execFileSync(
      process.execPath,
      ["--input-type=module", "--eval", "await import('codex-unlock/dist/doctor.js')"],
      { cwd: installDirectory, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    ),
    (error) => error?.stderr?.includes("ERR_PACKAGE_PATH_NOT_EXPORTED"),
  );
  for (const subpath of ["types", "dist/types.js", "dist/types.d.ts"]) {
    assert.throws(
      () => execFileSync(
        process.execPath,
        ["--input-type=module", "--eval", `await import('codex-unlock/${subpath}')`],
        { cwd: installDirectory, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
      ),
      (error) => error?.stderr?.includes("ERR_PACKAGE_PATH_NOT_EXPORTED"),
    );
  }

  // Compile against the installed tarball, not workspace source or declarations.
  const consumer = join(installDirectory, "json-types-consumer.mts");
  copyFileSync(resolve("scripts/fixtures/json-types-consumer.mts"), consumer);
  const emptyTypeRoots = join(installDirectory, "empty-types");
  mkdirSync(emptyTypeRoots);
  for (const [module, moduleResolution] of [["NodeNext", "NodeNext"], ["ESNext", "Bundler"]]) {
    execFileSync(
      process.execPath,
      [
        resolve("node_modules/typescript/bin/tsc"), "--noEmit", "--strict",
        "--target", "ES2022", "--lib", "ES2022", "--module", module,
        "--moduleResolution", moduleResolution, "--typeRoots", emptyTypeRoots,
        "--verbatimModuleSyntax", consumer,
      ],
      { cwd: installDirectory, encoding: "utf8", timeout: 30_000, stdio: ["ignore", "pipe", "pipe"] },
    );
  }
  log("Packed artifact passes README content/link, pinned-dependency, offline CLI/JSON, and type-only consumer boundary checks.");
  if (releaseDirectory !== null) {
    // Preserve the exact bytes just installed and verified, never repack after
    // the checks. A pre-existing destination refuses rather than replacing it.
    mkdirSync(releaseDirectory, { mode: 0o700 });
    copyFileSync(join(directory, packed.filename), join(releaseDirectory, packed.filename),
      constants.COPYFILE_EXCL);
    log(`Verified release artifact: ${packed.filename}`);
  }
} finally {
  rmSync(directory, { recursive: true, force: true });
  if (previousShrinkwrap === null) rmSync(shrinkwrapPath, { force: true });
  else writeFileSync(shrinkwrapPath, previousShrinkwrap);
}
