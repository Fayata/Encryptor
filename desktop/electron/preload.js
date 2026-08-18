const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('electronAPI', {
  minimize: () => ipcRenderer.send('window:minimize'),
  toggleMaximize: () => ipcRenderer.send('window:toggle-maximize'),
  close: () => ipcRenderer.send('window:close'),
  selectFolder: () => ipcRenderer.invoke('dialog:openDirectory'),
  selectFile: () => ipcRenderer.invoke('dialog:openFile'),
  readFile: (filePath) => ipcRenderer.invoke('file:read', filePath),
  openWithSystem: (filePath) => ipcRenderer.invoke('file:openSystem', filePath),
})
