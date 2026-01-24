'use strict';

const fs = require('fs');
const path = require('path');

const cargoPath = path.resolve(__dirname, '..', 'Cargo.toml');
const packagePath = path.resolve(__dirname, '..', 'npm', 'base', 'package.json');

function readCargoVersion() {
  const contents = fs.readFileSync(cargoPath, 'utf8');
  const packageSection = contents.split(/\n\s*\[package\]\s*\n/)[1];
  if (!packageSection) {
    throw new Error('Failed to find [package] section in Cargo.toml');
  }
  const versionMatch = packageSection.match(/\nversion\s*=\s*"([^"]+)"/);
  if (!versionMatch) {
    throw new Error('Failed to find version in [package] section');
  }
  return versionMatch[1];
}

function readPackageVersion() {
  const pkg = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
  if (!pkg.version) {
    throw new Error('package.json missing version');
  }
  return pkg.version;
}

const cargoVersion = readCargoVersion();
const npmVersion = readPackageVersion();

if (cargoVersion !== npmVersion) {
  console.error(`Version mismatch: Cargo.toml=${cargoVersion} package.json=${npmVersion}`);
  process.exit(1);
}

console.log(`Version sync ok: ${cargoVersion}`);
