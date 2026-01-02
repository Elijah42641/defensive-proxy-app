// openapp.js

const { app, Tray, Menu, BrowserWindow, ipcMain, dialog } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');

// Define the correct shell based on the operating system
const shell = os.platform() === 'win32' ? 'powershell.exe' : 'bash';

let tray = null;
let win;
let goProcess = null;
let proxyProcess = null; // Separate variable for proxy process
let terminalShell = null; // Variable to hold the child_process for the terminal




function createWindow() {
  win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      // This is the CRUCIAL change. Node.js integration needs to be ON.
      contextIsolation: false,
      nodeIntegration: true,
    },
  });

  win.loadFile('index.html');
}

app.whenReady().then(() => {
  createWindow();

  try {
    tray = new Tray(path.join(__dirname, 'icon.png'));
    // You can add tray menu if you want here
  } catch (error) {
    console.warn('Failed to create tray icon:', error.message);
    // Continue without tray
  }
});

// IPC listener: open folder dialog
ipcMain.on('open-folder-dialog', async (event) => {
  const result = await dialog.showOpenDialog(win, {
    properties: ['openDirectory'],
  });
  if (!result.canceled && result.filePaths.length > 0) {
    event.sender.send('folder-selected', result.filePaths[0]);
  } else {
    event.sender.send('folder-selected', null);
  }
});



// IPC listener: start the Go server (Your original logic)
ipcMain.on('run-go-server', (event, projectPath) => {
  if (goProcess) {
    console.log('Go process is already running.');
    event.sender.send('terminal-output', 'Go server is already running.');
    return;
  }

  goProcess = spawn('go', ['run', 'server.go'], { cwd: projectPath });

  goProcess.stdout.on('data', (data) => {
    event.sender.send('terminal-output', data.toString());
  });

  goProcess.stderr.on('data', (data) => {
    event.sender.send('terminal-output', data.toString());
  });

  goProcess.on('close', (code) => {
    event.sender.send('terminal-output', `Go server process exited with code ${code}`);
    goProcess = null;
  });

  goProcess.on('error', (err) => {
    event.sender.send('terminal-output', `Failed to start Go server: ${err.message}`);
    goProcess = null;
  });
});

// IPC listener: kill the Go server process
ipcMain.on('kill-go-server', () => {
  if (goProcess) {
    goProcess.kill('SIGTERM');
    console.log('Go process killed.');
  }
});

// --- New Logic for the Terminal ---

// IPC listener to start the interactive terminal
ipcMain.on('start-terminal', (event, projectPath) => {
  // If a terminal is already running, kill it before starting a new one
  if (terminalShell) {
    terminalShell.kill();
  }

  // Create the interactive shell process
  terminalShell = spawn(shell, [], { cwd: projectPath });

  // Send the shell's output to the renderer
  terminalShell.stdout.on('data', (data) => {
    event.sender.send('terminal-output', data.toString());
  });

  // Send the shell's errors to the renderer
  terminalShell.stderr.on('data', (data) => {
    event.sender.send('terminal-output', data.toString());
  });

  terminalShell.on('close', (code) => {
    event.sender.send('terminal-output', `Shell exited with code ${code}`);
    terminalShell = null;
  });

  terminalShell.on('error', (err) => {
    event.sender.send('terminal-output', `Failed to start shell: ${err.message}`);
    terminalShell = null;
  });
});

// IPC listener: takes input from the renderer and writes it to the shell's stdin
ipcMain.on('terminal-input', (event, input) => {
  if (terminalShell) {
    terminalShell.stdin.write(input);
  }
});

ipcMain.on('start-proxy', (event, { projectPath, proxyPort, serverPort, currentProject }) => {
  if (proxyProcess) {
    try {
      process.kill(proxyProcess.pid, 0);
    } catch (e) {
      proxyProcess = null;
    }
  }
  if (proxyProcess) {
    console.log('Proxy process is already running.');
    event.sender.send('terminal-output', 'Proxy server is already running.');
    return;
  }

  // Use the projectPath sent from main.js as the cwd for the proxy process
  // The projectPath should be the application directory path
  const proxyCwd = projectPath || path.join(__dirname, 'application');

  proxyProcess = spawn('/usr/local/go/bin/go', ['run', 'proxy.go'], {
    cwd: proxyCwd,
    env: {
      ...process.env,
      PROXY_PORT: proxyPort,
      SERVER_PORT: serverPort,
      CURRENT_PROJECT: currentProject
    }
  });

  proxyProcess.stdout.on('data', (data) => {
    console.log('Proxy stdout:', data.toString());
  });

  proxyProcess.stderr.on('data', (data) => {
    console.log('Proxy stderr:', data.toString());
  });

  proxyProcess.on('close', (code) => {
    console.log('Proxy process closed with code:', code);
    proxyProcess = null;
    // Notify renderer that proxy stopped
    win.webContents.send('proxy-stopped');
  });

  proxyProcess.on('error', (err) => {
    console.log('Proxy process error:', err);
    proxyProcess = null;
    // Notify renderer that proxy stopped
    win.webContents.send('proxy-stopped');
  });
});

// IPC listener to stop the proxy process
ipcMain.on('stop-proxy', (event) => {
  if (proxyProcess) {
    try {
      process.kill(proxyProcess.pid, 'SIGTERM');
      proxyProcess = null;
      win.webContents.send('proxy-stopped');
    } catch (e) {
      console.log('Failed to kill proxy process:', e);
      proxyProcess = null;
    }
    console.log('Proxy process stopped.');
    event.sender.send('terminal-output', 'Proxy server stopped.');
  } else {
    console.log('No proxy process running.');
    event.sender.send('terminal-output', 'No proxy server running.');
  }
});
