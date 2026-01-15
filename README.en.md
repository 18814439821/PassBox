# PassBox

PassBox is a local password manager built with Electron, helping you securely store and manage various passwords.

## Features

- 🔐 **Master Password Protection** - Encrypt and protect all stored passwords with a master password
- 🔒 **Local Encrypted Storage** - Uses AES encryption to securely store password data locally
- 📝 **Password Management** - Easily add, view, and manage saved passwords
- 🖥️ **Cross-Platform Support** - Built with Electron, supporting Windows, macOS, and Linux

## Installation

### Prerequisites

- Node.js (recommended v14 or higher)
- npm or yarn

### Installation Steps

1. Clone the repository

```bash
git clone https://gitee.com/chenyonghonggit/pass-box.git
cd pass-box
```

2. Install dependencies

```bash
npm install
```

3. Run the application

```bash
npm start
```

## Usage Instructions

1. **First Use** - Upon first launch, set a master password
2. **Login** - Subsequently, enter the master password to authenticate
3. **Add Passwords** - After logging in, add new password entries including website/app name, username, password, etc.
4. **View Passwords** - Browse and manage all stored passwords in the saved list

## Technology Stack

- **Electron** - Cross-platform desktop application framework
- **electron-store** - Local data persistence storage
- **Node.js crypto** - Password encryption

## Security Notes

- All passwords are encrypted using the AES algorithm
- The master password is salted and hashed for enhanced security
- Data is stored locally only and never uploaded to any server

## License

This project is open-sourced under the MIT License.

## Contributions

Issues and Pull Requests are welcome to help improve this project.