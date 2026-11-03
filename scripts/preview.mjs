import {spawn} from 'node:child_process';
import {existsSync} from 'node:fs';
const python = process.platform === 'win32' ? '.venv/Scripts/python.exe' : '.venv/bin/python';
if(!existsSync(python)){console.error('Create .venv and install backend dependencies first.');process.exit(1);}
const child=spawn(python,['scripts/run_services.py'],{stdio:'inherit',env:{...process.env,PORT:process.env.PORT||'8000'}});
for(const signal of ['SIGTERM','SIGINT'])process.on(signal,()=>child.kill(signal));
child.on('exit',code=>process.exit(code??1));
