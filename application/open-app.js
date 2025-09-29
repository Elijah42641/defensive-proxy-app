const { app, Tray, Menu, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');

let tray = null;
let win;

function createWindow() {
  win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'), // preload script here
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  win.loadFile('index.html');
}

app.whenReady().then(() => {
  createWindow();

  tray = new Tray(path.join(__dirname, 'icon.png')); // your icon path

  // You can add tray menu if you want here
});

// IPC listener example: open folder dialog
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

// Add other ipcMain listeners for proxy start etc.
ipcMain.on('start-proxy', (event, project) => {
  console.log('Starting proxy for:', project);
  // Your proxy start logic here
});
