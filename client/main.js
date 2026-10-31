const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('node:path');

let userData = { name: false, password: false };
let win = null;

function createWindow() {
    win = new BrowserWindow({
        width: 800,
        height: 600,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false
        },
    });

    win.loadFile('public/login.html');
    return win;
}

app.whenReady().then(() => {
    createWindow();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

ipcMain.on('open-chat', (event, data) => {
    userData = { name: data.name, password: data.password, encryptedPrivateKey: data.encryptedPrivateKey || null };
    win.loadFile('public/chat.html');
});


ipcMain.on('get-user-data', (event) => {
    event.sender.send('user-data', userData);
});
