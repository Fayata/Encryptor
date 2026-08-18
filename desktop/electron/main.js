const { app, BrowserWindow, ipcMain, shell, Tray, Menu, nativeImage } = require('electron')
const path = require('path')

let mainWindow
let tray = null
let isQuitting = false
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    frame: false,
    backgroundColor: '#0D0D0F',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  })

  // Dev: load Vite dev server. Prod: load built files
  if (!app.isPackaged) {
    mainWindow.loadURL('http://localhost:5173')
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'))
  }

  // Prevent closing, hide instead
  mainWindow.on('close', (e) => {
    if (!isQuitting) {
      e.preventDefault()
      mainWindow.hide()
    }
  })
}

// Window controls IPC
ipcMain.on('window:minimize', () => mainWindow?.minimize())
ipcMain.on('window:toggle-maximize', () => {
  if (mainWindow?.isMaximized()) {
    mainWindow.unmaximize()
  } else {
    mainWindow?.maximize()
  }
})
ipcMain.on('window:close', () => mainWindow?.close())

ipcMain.handle('dialog:openFile', async () => {
  const { dialog } = require('electron')
  const { canceled, filePaths } = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile']
  })
  if (canceled) return null
  return filePaths[0]
})

ipcMain.handle('file:read', async (_, filePath) => {
  const fs = require('fs')
  try {
    const buf = fs.readFileSync(filePath)
    return buf.toString('base64')
  } catch (e) {
    throw new Error('Gagal membaca file: ' + e.message)
  }
})

ipcMain.handle('file:openSystem', async (_, filePath) => {
  await shell.openPath(filePath)
})

ipcMain.handle('dialog:openDirectory', async () => {
  const { dialog } = require('electron')
  const { canceled, filePaths } = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory']
  })
  if (canceled) {
    return null
  } else {
    return filePaths[0]
  }
})

app.whenReady().then(() => {
  createWindow()

  // Base64 placeholder icon (blue square)
  const iconBase64 = 'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAADFJREFUOE9jZKAQMFKon2HUAAY0DBBgYGDoYGFgYBh1ACMYRzWAbAA2w6hZjFqAlQAAp8YDFR4170wAAAAASUVORK5CYII='
  const icon = nativeImage.createFromDataURL(`data:image/png;base64,${iconBase64}`)
  
  tray = new Tray(icon)
  tray.setToolTip('Faycryptor')
  
  const contextMenu = Menu.buildFromTemplate([
    { label: 'Buka Faycryptor', click: () => { mainWindow.show(); mainWindow.focus(); } },
    { type: 'separator' },
    { label: 'Keluar', click: () => {
        isQuitting = true
        app.quit()
      } 
    }
  ])
  
  tray.setContextMenu(contextMenu)
  
  tray.on('click', () => {
    if (mainWindow) {
      mainWindow.show()
      mainWindow.focus()
    }
  })
})

app.on('window-all-closed', () => {
  // Do not quit when windows are closed (handled by Tray)
  if (process.platform !== 'darwin') {}
})

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow()
})
