// SYNTHETIC demo app — main process.
const { app, BrowserWindow, ipcMain } = require("electron");
const path = require("node:path");
const license = require("./licensing/license-client.js");

function createWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
    },
  });
  win.loadFile(path.join(__dirname, "renderer", "index.html"));
}

ipcMain.handle("license:activate", async (event, code) => {
  // Narrow IPC surface: validate the sender before acting.
  if (!event.senderFrame || !event.senderFrame.url.startsWith("file://")) throw new Error("untrusted sender");
  return license.activate(String(code));
});

app.whenReady().then(createWindow);
