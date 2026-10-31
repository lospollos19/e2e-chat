const ipcRenderer = require('electron').ipcRenderer;
const { SERVER_URL, SOCKET_OPTIONS } = require('./config.js');
const socket      = require('socket.io-client')(SERVER_URL, SOCKET_OPTIONS);
const crypto      = require('crypto');
const { deriveAuthSecret } = require('./auth.js');

let currentName              = null;
let currentPassword          = null;
let pendingEncryptedPrivKey  = null;

function login() {
    currentName     = document.getElementById("inputUserName").value;
    currentPassword = document.getElementById("inputPassword").value;
    socket.emit('login', { name: currentName, password: deriveAuthSecret(currentName, currentPassword) });
}

function validate(name, password) {
    if (!/^[A-Za-z0-9_]{3,20}$/.test(name))
        return 'Username must be 3-20 letters, digits or _';
    if (password.length < 8)
        return 'Password must be at least 8 characters';
    if (!/[A-Z]/.test(password))
        return 'Password must contain at least one uppercase letter';
    if (!/[0-9]/.test(password))
        return 'Password must contain at least one digit';
    if (!/[^A-Za-z0-9]/.test(password))
        return 'Password must contain at least one special character';
    return null;
}

function register() {
    currentName     = document.getElementById("inputUserName").value;
    currentPassword = document.getElementById("inputPassword").value;
    const err = validate(currentName, currentPassword);
    if (err) {
        document.getElementById('error-msg').textContent = err;
        return;
    }
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength:      2048,
        publicKeyEncoding:  { type: 'spki',  format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    const salt   = crypto.randomBytes(16);
    const aesKey = crypto.pbkdf2Sync(currentPassword, salt, 100000, 32, 'sha256');
    const iv     = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    let encData  = cipher.update(privateKey, 'utf8', 'hex');
    encData     += cipher.final('hex');
    pendingEncryptedPrivKey = {
        iv:      iv.toString('hex'),
        data:    encData,
        authTag: cipher.getAuthTag().toString('hex'),
        salt:    salt.toString('hex')
    };
    socket.emit('register', {
        name:                currentName,
        password:            deriveAuthSecret(currentName, currentPassword),
        publicKey:           publicKey,
        encryptedPrivateKey: pendingEncryptedPrivKey
    });
}

socket.on('login_ok', (data) => {
    ipcRenderer.send('open-chat', {
        name:                currentName,
        password:            currentPassword,
        encryptedPrivateKey: data.encryptedPrivateKey || null
    });
});

socket.on('login_error', (err) => {
    document.getElementById('error-msg').textContent = err.message;
});

socket.on('register_ok', () => {
    ipcRenderer.send('open-chat', {
        name:                currentName,
        password:            currentPassword,
        encryptedPrivateKey: pendingEncryptedPrivKey
    });
});

socket.on('register_error', (err) => {
    document.getElementById('error-msg').textContent = err.message;
});
    

window.addEventListener('DOMContentLoaded', () => {
    document.getElementById('btn-login').addEventListener('click', login);
    document.getElementById('btn-register').addEventListener('click', register);
});
