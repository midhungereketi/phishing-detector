import { spawnSync } from 'node:child_process';
import path from 'node:path';
const python = path.join('.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
const result = spawnSync(python, ['-m', 'pytest', 'backend/tests', '-q', '--basetemp', path.join('artifacts', `pytest-${Date.now()}`)], { stdio: 'inherit', windowsHide: true });
if (result.error) console.error(result.error.message);
process.exit(result.status ?? 1);
