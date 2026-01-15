const { contextBridge, ipcRenderer } = require('electron');

// 包装loginMasterPassword调用，添加日志
function wrappedLoginMasterPassword(password) {
  console.log('preload.js: loginMasterPassword called with password:', password);
  return ipcRenderer.invoke('login-master-password', password);
}

contextBridge.exposeInMainWorld('passwordManager', {
  // 主密码相关
  checkMasterPasswordSetup: () => ipcRenderer.invoke('check-master-password-setup'),
  setupMasterPassword: (password) => ipcRenderer.invoke('setup-master-password', password),
  loginMasterPassword: wrappedLoginMasterPassword,
  forgotMasterPassword: () => ipcRenderer.invoke('forgot-master-password'),
  
  // 密码管理相关
  savePassword: (data) => ipcRenderer.invoke('save-password', data),
  getPasswords: () => ipcRenderer.invoke('get-passwords'),
  deletePassword: (id) => ipcRenderer.invoke('delete-password', id),
  
  // 二次安全验证相关
  verifySecondaryPassword: (data) => ipcRenderer.invoke('verify-secondary-password', data),
  updateSecondaryAuth: (data) => ipcRenderer.invoke('update-secondary-auth', data)
});