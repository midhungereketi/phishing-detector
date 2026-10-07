import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const python = path.join(root, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
if (!existsSync(python)) {
  console.error('Python environment missing. Follow README.md setup or run scripts/setup.ps1 on Windows.');
  process.exit(1);
}
const processes = [];
let stopping = false;
function stop(code = 0) {
  if (stopping) return;
  stopping = true;
  for (const child of processes) child.kill();
  process.exitCode = code;
}
for (const [command, args] of [
  [python, ['-m', 'uvicorn', 'backend.app:app', '--host', '127.0.0.1', '--port', '8000']],
  [process.execPath, [path.join(root, 'node_modules/vite/bin/vite.js')]],
]) {
  const child = spawn(command, args, { cwd: root, stdio: 'inherit', windowsHide: true });
  processes.push(child);
  child.on('error', error => { console.error(error.message); stop(1); });
  child.on('exit', code => { if (!stopping) stop(code || 0); });
}
process.on('SIGINT', () => stop());
process.on('SIGTERM', () => stop());
