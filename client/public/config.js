const fs   = require('node:fs');
const path = require('node:path');

// Server address, override with the CHAT_SERVER environment variable
const SERVER_URL = process.env.CHAT_SERVER || 'https://localhost:3000';

// The server uses a self-signed certificate. socket.io-client runs on Node here (nodeIntegration),
// so passing it as `ca` makes the connection trust exactly that certificate and nothing else.
const CERT_FILE = process.env.CHAT_CERT || path.join(__dirname, '..', '..', 'server', 'certs', 'cert.pem');
const SERVER_CA = fs.existsSync(CERT_FILE) ? fs.readFileSync(CERT_FILE) : undefined;

const SOCKET_OPTIONS = { transports: ['websocket'], ca: SERVER_CA };

module.exports = { SERVER_URL, SOCKET_OPTIONS };
