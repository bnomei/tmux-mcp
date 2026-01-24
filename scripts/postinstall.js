'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const { execFileSync } = require('child_process');

const BIN_NAME = 'tmux-mcp-rs';
const PACKAGE_ROOT = path.resolve(__dirname, '..');
const PACKAGE_JSON = path.join(PACKAGE_ROOT, 'package.json');

function readPackageVersion() {
  const pkg = JSON.parse(fs.readFileSync(PACKAGE_JSON, 'utf8'));
  return pkg.version;
}

function resolveTarget() {
  const platform = process.platform;
  const arch = process.arch;

  if (platform === 'linux' && arch === 'x64') return 'x86_64-unknown-linux-musl';
  if (platform === 'linux' && arch === 'arm64') return 'aarch64-unknown-linux-musl';
  if (platform === 'darwin' && arch === 'x64') return 'x86_64-apple-darwin';
  if (platform === 'darwin' && arch === 'arm64') return 'aarch64-apple-darwin';
  if (platform === 'win32' && arch === 'x64') return 'x86_64-pc-windows-msvc';

  return null;
}

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, (response) => {
      if ([301, 302, 307, 308].includes(response.statusCode || 0)) {
        const redirect = response.headers.location;
        if (!redirect) {
          reject(new Error(`Redirect missing location for ${url}`));
          return;
        }
        download(redirect, dest).then(resolve).catch(reject);
        return;
      }

      if (response.statusCode !== 200) {
        reject(new Error(`Download failed (${response.statusCode}) for ${url}`));
        return;
      }

      const file = fs.createWriteStream(dest);
      response.pipe(file);
      file.on('finish', () => file.close(resolve));
      file.on('error', (err) => {
        fs.unlink(dest, () => reject(err));
      });
    });

    request.on('error', reject);
  });
}

function ensureExecutable(filePath) {
  if (process.platform !== 'win32') {
    fs.chmodSync(filePath, 0o755);
  }
}

function findBinary(rootDir, exeName) {
  const matches = [];
  const stack = [rootDir];

  while (stack.length) {
    const current = stack.pop();
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
        continue;
      }
      if (entry.isFile() && entry.name === exeName) {
        matches.push(fullPath);
      }
    }
  }

  return matches;
}

async function main() {
  if (process.env.TMUX_MCP_RS_SKIP_DOWNLOAD === '1') {
    console.log('Skipping tmux-mcp-rs binary download (TMUX_MCP_RS_SKIP_DOWNLOAD=1).');
    return;
  }

  const target = resolveTarget();
  if (!target) {
    throw new Error(`Unsupported platform/arch: ${process.platform}/${process.arch}`);
  }

  const exeName = process.platform === 'win32' ? `${BIN_NAME}.exe` : BIN_NAME;
  const binDir = path.join(PACKAGE_ROOT, 'bin', target);
  const binPath = path.join(binDir, exeName);

  fs.mkdirSync(binDir, { recursive: true });

  if (process.env.TMUX_MCP_RS_LOCAL_BIN) {
    const source = path.resolve(process.env.TMUX_MCP_RS_LOCAL_BIN);
    if (!fs.existsSync(source)) {
      throw new Error(`Local binary not found: ${source}`);
    }
    fs.copyFileSync(source, binPath);
    ensureExecutable(binPath);
    console.log(`Installed local tmux-mcp-rs binary to ${binPath}`);
    return;
  }

  const version = readPackageVersion();
  const repo = process.env.TMUX_MCP_RS_REPO || 'bnomei/tmux-mcp';
  const ext = process.platform === 'win32' ? 'zip' : 'tar.gz';
  const asset = `${BIN_NAME}-v${version}-${target}.${ext}`;
  const url = `https://github.com/${repo}/releases/download/v${version}/${asset}`;

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tmux-mcp-rs-'));
  const archivePath = path.join(tmpDir, asset);

  console.log(`Downloading ${url}`);
  await download(url, archivePath);

  if (process.platform === 'win32') {
    execFileSync('powershell', [
      '-NoProfile',
      '-Command',
      `Expand-Archive -Path "${archivePath}" -DestinationPath "${tmpDir}" -Force`
    ], { stdio: 'inherit' });
  } else {
    execFileSync('tar', ['-xzf', archivePath, '-C', tmpDir], { stdio: 'inherit' });
  }

  let extractedPath = path.join(tmpDir, exeName);
  if (!fs.existsSync(extractedPath)) {
    const matches = findBinary(tmpDir, exeName);
    if (matches.length === 1) {
      extractedPath = matches[0];
    } else if (matches.length > 1) {
      throw new Error(`Multiple extracted binaries found: ${matches.join(', ')}`);
    } else {
      throw new Error(`Extracted binary not found at ${extractedPath}`);
    }
  }

  fs.copyFileSync(extractedPath, binPath);
  ensureExecutable(binPath);
  console.log(`Installed tmux-mcp-rs binary to ${binPath}`);
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
