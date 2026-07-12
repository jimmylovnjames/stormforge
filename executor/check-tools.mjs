#!/usr/bin/env node
// Quick check: which offensive tools are installed and accessible.

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const execFileAsync = promisify(execFile);

const TOOLS = [
  { name: 'nmap', bin: 'nmap', versionFlag: '--version' },
  { name: 'nuclei', bin: 'nuclei', versionFlag: '-version' },
  { name: 'httpx', bin: 'httpx', versionFlag: '-version' },
  { name: 'subfinder', bin: 'subfinder', versionFlag: '-version' },
  { name: 'katana', bin: 'katana', versionFlag: '-version' },
  { name: 'ffuf', bin: 'ffuf', versionFlag: '-V' },
  { name: 'sqlmap', bin: 'sqlmap', versionFlag: '--version' },
  { name: 'gobuster', bin: 'gobuster', versionFlag: 'version' },
];

console.log('StormForge Executor — Tool Check\n');

let available = 0;
for (const tool of TOOLS) {
  try {
    const { stdout } = await execFileAsync(tool.bin, [tool.versionFlag], { timeout: 5000 });
    const version = stdout.split('\n')[0].trim().slice(0, 60);
    console.log(`  ✓ ${tool.name.padEnd(12)} ${version}`);
    available++;
  } catch (err) {
    console.log(`  ✗ ${tool.name.padEnd(12)} NOT FOUND`);
  }
}

console.log(`\n  ${available}/${TOOLS.length} tools available.`);
if (available < TOOLS.length) {
  console.log('  See INSTALL.md for installation instructions.');
}
process.exit(available > 0 ? 0 : 1);
