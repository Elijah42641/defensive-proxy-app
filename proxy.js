const { ipcMain } = require('electron');
const { spawn } = require('child_process');
const path = require('path');

ipcMain.on('start-proxy', (event, project) => {
  const { serverPort, proxyPort } = project;

  // Assume proxy.go is in the root folder of your Electron app
  const goFilePath = path.join(__dirname, 'proxy.go');

  // Run: go run proxy.go <serverPort> <proxyPort>
  const goProcess = spawn('go', ['run', goFilePath, serverPort, proxyPort], {
    cwd: __dirname,
  });

  goProcess.stdout.on('data', (data) => {
    console.log(`[proxy.go stdout]: ${data}`);
  });

  goProcess.stderr.on('data', (data) => {
    console.error(`[proxy.go stderr]: ${data}`);
  });

  goProcess.on('close', (code) => {
    console.log(`proxy.go process exited with code ${code}`);
  });
});
