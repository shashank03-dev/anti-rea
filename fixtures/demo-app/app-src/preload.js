// SYNTHETIC demo app — preload: exposes a narrow, typed bridge only.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("ledger", {
  activateLicense: (code) => ipcRenderer.invoke("license:activate", code),
});
