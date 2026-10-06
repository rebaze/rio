#!/usr/bin/env bash
# Runs inside the demo's pinned Node image. No host Node/npm installation needed.
set -euxo pipefail
cd /work
git clone --depth 1 --branch v20.2.0 https://github.com/juice-shop/juice-shop.git source
cd source
test "$(git rev-parse HEAD)" = "$JUICE_SOURCE_REV"
# Juice Shop 20.2.0's SBOM script expects the stats.json format/name from
# Angular 22.0.1. Pin these build tools instead of accepting later 22.x changes.
node <<'JS'
const fs = require('node:fs');
const path = 'frontend/package.json';
const pkg = JSON.parse(fs.readFileSync(path));
pkg.dependencies['@angular/build'] = '22.0.1';
pkg.dependencies['@angular/cli'] = '22.0.1';
fs.writeFileSync(path, JSON.stringify(pkg, null, 2) + '\n');
JS
git diff -- frontend/package.json > /work/build-overrides.patch
node --version
npm --version

# The install lifecycle builds the frontend and generates its esbuild SBOM.
# Preserve lockfiles even though upstream's .npmrc disables them by default.
npm install --package-lock --no-audit --no-fund
# Upstream postinstall tolerates server compilation failure; this demo does not.
npm run build:server
npm run sbom -- --spec-version 1.6 --output-reproducible

test -s build/app.js
test -s frontend/dist/frontend/index.html
test -s bom.json
test -s frontend/dist/bom/bom.json
test -s package-lock.json
test -s frontend/package-lock.json
node <<'JS'
const fs = require('node:fs');
const {execFileSync} = require('node:child_process');
fs.writeFileSync('../build-info.json', JSON.stringify({
  revision: execFileSync('git', ['rev-parse', 'HEAD'], {encoding:'utf8'}).trim(),
  node: process.version,
  platform: process.platform,
  architecture: process.arch,
  workspace: "dirty",
  buildToolPins: {"@angular/build": "22.0.1", "@angular/cli": "22.0.1"},
  npm: execFileSync('npm', ['--version'], {encoding:'utf8'}).trim(),
  generators: {
    backend: JSON.parse(fs.readFileSync('node_modules/@cyclonedx/cyclonedx-npm/package.json')).version,
    frontend: JSON.parse(fs.readFileSync('frontend/node_modules/@cyclonedx/cyclonedx-esbuild/package.json')).version
  }
}, null, 2) + '\n');
JS
