// Tara desktop shell (Electron).
//
// Launches the Python backend (the same `main.py --mode both --ui` the CLI runs)
// as a child process, waits for its loopback console to answer, then opens it in
// a native window. No browser involved. The backend is bound to 127.0.0.1 and is
// killed when the app quits.
//
//   npm install      (in this electron/ folder)
//   npm start
//
// Env overrides: TARA_PYTHON (python exe), TARA_PORT, TARA_MODE, TARA_CONFIG.

const { app, BrowserWindow, shell } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const http = require('http');

const PORT = parseInt(process.env.TARA_PORT || '8799', 10);
const PY = process.env.TARA_PYTHON || (process.platform === 'win32' ? 'python' : 'python3');
const MODE = process.env.TARA_MODE || 'both';
const CONFIG = process.env.TARA_CONFIG || 'config/default.yaml';
const ROOT = path.join(__dirname, '..');           // the project root (ctf_agent/)

let backend = null;
let win = null;

function startBackend() {
  const args = ['main.py', '--config', CONFIG, '--mode', MODE, '--ui', '--ui-port', String(PORT)];
  backend = spawn(PY, args, { cwd: ROOT, stdio: 'inherit', env: process.env });
  backend.on('error', (e) => console.error('[tara] failed to start backend:', e.message));
  backend.on('exit', (code) => {
    console.error('[tara] backend exited with code', code);
    if (code && win) win.webContents.executeJavaScript(
      "document.title='Tara — backend stopped'").catch(() => {});
  });
}

function waitForServer(cb, tries = 60) {
  const req = http.get(
    { host: '127.0.0.1', port: PORT, path: '/api/snapshot', timeout: 1000 },
    (res) => { res.resume(); cb(null); }
  );
  req.on('error', () => {
    if (tries <= 0) return cb(new Error('backend did not come up on port ' + PORT));
    setTimeout(() => waitForServer(cb, tries - 1), 500);
  });
  req.on('timeout', () => req.destroy());
}

function createWindow() {
  win = new BrowserWindow({
    width: 1180, height: 840, minWidth: 720, minHeight: 540,
    title: 'Tara', backgroundColor: '#f7f7f6', autoHideMenuBar: true,
    webPreferences: { contextIsolation: true, nodeIntegration: false },
  });
  win.setMenuBarVisibility(false);
  win.loadURL(`http://127.0.0.1:${PORT}/`);
  // external links (if any) open in the real browser, not inside the app
  win.webContents.setWindowOpenHandler(({ url }) => { shell.openExternal(url); return { action: 'deny' }; });
  win.on('closed', () => { win = null; });
}

app.whenReady().then(() => {
  startBackend();
  waitForServer((err) => {
    if (err) console.error('[tara]', err.message);
    createWindow();
  });
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

function shutdown() { if (backend) { try { backend.kill(); } catch (_) {} backend = null; } }
app.on('window-all-closed', () => { shutdown(); app.quit(); });
app.on('before-quit', shutdown);
process.on('exit', shutdown);
