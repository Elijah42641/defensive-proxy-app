// preload.js

const { ipcRenderer } = require('electron');

// Expose ipcRenderer directly to the renderer process
window.ipcRenderer = ipcRenderer;