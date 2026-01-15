const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const Store = require('electron-store');
const crypto = require('crypto');

// 初始化存储
const store = new Store();
const ALGORITHM = 'aes-256-gcm';

// 存储当前会话密钥（内存中，应用关闭后消失）
let CURRENT_ENCRYPTION_KEY = null;

// 生成盐值
function generateSalt() {
  return crypto.randomBytes(16).toString('hex');
}

// 生成主密码哈希
function hashMasterPassword(password, salt) {
  // 验证password参数
  if (!password || typeof password !== 'string') {
    throw new TypeError('Password must be a non-empty string');
  }
  const hash = crypto.scryptSync(password, salt, 32).toString('hex');
  console.log('hashMasterPassword:', {
    password: password,
    salt: salt,
    hash: hash
  });
  return hash;
}

// 检查是否已设置主密码
function hasMasterPassword() {
  const hasHash = !!store.get('masterPasswordHash');
  const hasSalt = !!store.get('masterPasswordSalt');
  console.log('hasMasterPassword:', { hasHash, hasSalt, result: hasHash && hasSalt });
  return hasHash && hasSalt;
}

// 验证主密码
function verifyMasterPassword(password) {
  // 验证password参数
  if (!password || typeof password !== 'string') {
    console.log('verifyMasterPassword: Invalid password input', password);
    return false;
  }
  
  const storedHash = store.get('masterPasswordHash');
  const storedSalt = store.get('masterPasswordSalt');
  
  console.log('verifyMasterPassword:', {
    password: password,
    storedHash: storedHash,
    storedSalt: storedSalt
  });
  
  if (!storedHash || !storedSalt) {
    console.log('verifyMasterPassword: No stored master password found');
    return false;
  }
  
  try {
    const hash = hashMasterPassword(password, storedSalt);
    const result = hash === storedHash;
    console.log('verifyMasterPassword result:', result, { generatedHash: hash, storedHash: storedHash });
    return result;
  } catch (error) {
    console.error('Failed to verify master password:', error);
    return false;
  }
}

// 使用主密码生成加密密钥
function generateEncryptionKeyFromMasterPassword(password) {
  // 验证password参数
  if (!password || typeof password !== 'string') {
    throw new TypeError('Password must be a non-empty string');
  }
  
  const salt = store.get('encryptionSalt', 'default-encryption-salt');
  return crypto.scryptSync(password, salt, 32);
}

// 加密函数
function encrypt(text) {
  if (!CURRENT_ENCRYPTION_KEY) {
    throw new Error('Encryption key not initialized. Please login first.');
  }
  
  const iv = crypto.randomBytes(16); // 16字节IV
  const cipher = crypto.createCipheriv(ALGORITHM, CURRENT_ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return {
    iv: iv.toString('hex'),
    encryptedData: encrypted,
    authTag: authTag
  };
}

// 解密函数
function decrypt(encryptedData) {
  if (!CURRENT_ENCRYPTION_KEY) {
    throw new Error('Encryption key not initialized. Please login first.');
  }
  
  const iv = Buffer.from(encryptedData.iv, 'hex');
  const authTag = Buffer.from(encryptedData.authTag, 'hex');
  const decipher = crypto.createDecipheriv(ALGORITHM, CURRENT_ENCRYPTION_KEY, iv);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encryptedData.encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function createWindow() {
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    resizable: false, // 禁止调整窗口大小
    maximizable: false, // 禁止最大化
    minimizable: true, // 允许最小化
    fullscreenable: false, // 禁止全屏
    autoHideMenuBar: true, // 自动隐藏菜单栏
    menuBarVisible: false, // 初始状态下菜单栏不可见
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true
    }
  });

  // 隐藏菜单栏
  win.setMenu(null);

  win.loadFile('index.html');
}

// IPC 处理程序
ipcMain.handle('check-master-password-setup', () => {
  return hasMasterPassword();
});

ipcMain.handle('setup-master-password', (event, password) => {
  if (hasMasterPassword()) {
    throw new Error('Master password already set.');
  }
  
  // 生成盐值
  const masterSalt = generateSalt();
  const encryptionSalt = generateSalt();
  
  // 哈希主密码
  const hash = hashMasterPassword(password, masterSalt);
  
  // 存储主密码哈希和盐值
  store.set('masterPasswordHash', hash);
  store.set('masterPasswordSalt', masterSalt);
  store.set('encryptionSalt', encryptionSalt);
  
  // 初始化会话密钥
  CURRENT_ENCRYPTION_KEY = generateEncryptionKeyFromMasterPassword(password);
  
  return { success: true };
});

ipcMain.handle('login-master-password', (event, password) => {
  // 首先检查主密码是否已设置
  if (!hasMasterPassword()) {
    return { success: false, message: 'Master password not set. Please set it first.' };
  }
  
  // 验证password参数
  if (!password || typeof password !== 'string') {
    console.error('login-master-password: Invalid password input', password);
    return { success: false, message: 'Invalid password input.' };
  }
  
  if (!verifyMasterPassword(password)) {
    return { success: false, message: 'Incorrect master password.' };
  }
  
  // 初始化会话密钥
  CURRENT_ENCRYPTION_KEY = generateEncryptionKeyFromMasterPassword(password);
  
  return { success: true };
});

ipcMain.handle('save-password', (event, passwordData) => {
  if (!CURRENT_ENCRYPTION_KEY) {
    throw new Error('Please login first.');
  }
  
  const passwords = store.get('passwords', []);
  
  // 加密密码
  const encryptedPassword = encrypt(passwordData.password);
  
  // 加密二次安全密码（如果有）
  let encryptedSecondaryPassword = null;
  if (passwordData.secondaryPassword && passwordData.enableSecondaryAuth) {
    encryptedSecondaryPassword = encrypt(passwordData.secondaryPassword);
  }
  
  const newPassword = {
    id: Date.now().toString(),
    service: passwordData.service,
    username: passwordData.username,
    password: encryptedPassword, // 存储加密后的密码对象
    enableSecondaryAuth: passwordData.enableSecondaryAuth || false,
    secondaryPassword: encryptedSecondaryPassword // 存储加密后的二次安全密码对象
  };
  
  passwords.push(newPassword);
  store.set('passwords', passwords);
  
  // 返回给前端时解密密码
  return {
    ...newPassword,
    password: passwordData.password,
    secondaryPassword: passwordData.secondaryPassword || ''
  };
});

ipcMain.handle('get-passwords', () => {
  if (!CURRENT_ENCRYPTION_KEY) {
    throw new Error('Please login first.');
  }
  
  const encryptedPasswords = store.get('passwords', []);
  
  // 解密所有密码后返回给前端
  return encryptedPasswords.map(password => {
    const decryptedPassword = {
      ...password,
      password: decrypt(password.password),
      enableSecondaryAuth: password.enableSecondaryAuth || false,
      secondaryPassword: '' // 不返回解密后的二次安全密码，只返回状态
    };
    
    return decryptedPassword;
  });
});

ipcMain.handle('delete-password', (event, id) => {
  if (!CURRENT_ENCRYPTION_KEY) {
    throw new Error('Please login first.');
  }
  
  const passwords = store.get('passwords', []);
  const updatedPasswords = passwords.filter(password => password.id !== id);
  store.set('passwords', updatedPasswords);
  
  // 解密返回给前端
  return updatedPasswords.map(password => ({
    ...password,
    password: decrypt(password.password),
    enableSecondaryAuth: password.enableSecondaryAuth || false,
    secondaryPassword: ''
  }));
});

// 验证二次安全密码
ipcMain.handle('verify-secondary-password', (event, { id, secondaryPassword }) => {
  if (!CURRENT_ENCRYPTION_KEY) {
    throw new Error('Please login first.');
  }
  
  const passwords = store.get('passwords', []);
  const passwordItem = passwords.find(item => item.id === id);
  
  if (!passwordItem || !passwordItem.enableSecondaryAuth || !passwordItem.secondaryPassword) {
    return { success: false, message: 'Secondary authentication not enabled for this password.' };
  }
  
  try {
    // 解密存储的二次安全密码
    const storedSecondaryPassword = decrypt(passwordItem.secondaryPassword);
    const isValid = storedSecondaryPassword === secondaryPassword;
    
    return {
      success: isValid,
      message: isValid ? 'Secondary password verified.' : 'Invalid secondary password.'
    };
  } catch (error) {
    console.error('Error verifying secondary password:', error);
    return { success: false, message: 'Error verifying secondary password.' };
  }
});

// 更新密码项的二次安全验证设置
ipcMain.handle('update-secondary-auth', (event, { id, enableSecondaryAuth, secondaryPassword }) => {
  if (!CURRENT_ENCRYPTION_KEY) {
    throw new Error('Please login first.');
  }
  
  const passwords = store.get('passwords', []);
  const passwordIndex = passwords.findIndex(item => item.id === id);
  
  if (passwordIndex === -1) {
    throw new Error('Password not found.');
  }
  
  // 加密二次安全密码（如果有）
  let encryptedSecondaryPassword = null;
  if (secondaryPassword && enableSecondaryAuth) {
    encryptedSecondaryPassword = encrypt(secondaryPassword);
  }
  
  // 更新密码项
  passwords[passwordIndex] = {
    ...passwords[passwordIndex],
    enableSecondaryAuth,
    secondaryPassword: encryptedSecondaryPassword
  };
  
  store.set('passwords', passwords);
  
  // 返回更新后的密码列表
  return passwords.map(password => ({
    ...password,
    password: decrypt(password.password),
    enableSecondaryAuth: password.enableSecondaryAuth || false,
    secondaryPassword: ''
  }));
});

ipcMain.handle('forgot-master-password', async (event) => {
  try {
    // 注意：如果用户忘记了主密码，我们无法解密存储的密码
    // 因为解密需要主密码生成的密钥
    
    // 1. 直接清除本地缓存
    store.clear();
    
    // 2. 清除当前会话密钥
    CURRENT_ENCRYPTION_KEY = null;
    
    return {
      success: true,
      message: 'All data has been cleared. You can now set a new master password.'
    };
  } catch (error) {
    console.error('Forgot password error:', error);
    return {
      success: false,
      message: error.message
    };
  }
});

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  // 清除会话密钥
  CURRENT_ENCRYPTION_KEY = null;
  
  if (process.platform !== 'darwin') {
    app.quit();
  }
});