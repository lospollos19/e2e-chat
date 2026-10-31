// Starts the real server over TLS on a temporary database and replays attacks against it.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn, execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const io = require('socket.io-client');

const SERVER_DIR = path.join(__dirname, '..');
const PASSWORD = 'Passw0rd!';

let tmp, cert, port, server;
const sockets = [];

function startServer() {
  return new Promise((resolve, reject) => {
    server = spawn(process.execPath, ['src/index.js'], {
      cwd: SERVER_DIR,
      env: {
        ...process.env,
        PORT: String(port),
        DB_FILE_NAME: path.join(tmp, 'test.db'),
        TLS_CERT: path.join(tmp, 'cert.pem'),
        TLS_KEY: path.join(tmp, 'key.pem')
      }
    });
    server.stdout.on('data', d => { if (d.toString().includes('Server listening')) resolve(); });
    server.on('exit', code => reject(new Error(`server exited with ${code}`)));
  });
}

function stopServer() {
  return new Promise(resolve => {
    server.removeAllListeners('exit');
    server.on('exit', resolve);
    server.kill();
  });
}

function connect() {
  const s = io(`https://localhost:${port}`, { transports: ['websocket'], ca: cert, reconnection: false });
  sockets.push(s);
  return s;
}

function waitFor(socket, event, ms = 2000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`no '${event}' within ${ms} ms`)), ms);
    socket.once(event, data => { clearTimeout(timer); resolve(data); });
  });
}

function expectNone(socket, event, ms = 400) {
  return new Promise((resolve, reject) => {
    const handler = data => reject(new Error(`unexpected '${event}': ${JSON.stringify(data)}`));
    socket.once(event, handler);
    setTimeout(() => { socket.off(event, handler); resolve(); }, ms);
  });
}

const keyPairs = {};

function keyPair(name) {
  if (!keyPairs[name]) {
    keyPairs[name] = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
  }
  return keyPairs[name];
}

const wrap = (name, key) =>
  crypto.publicEncrypt({ key: keyPair(name).publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, key)
    .toString('base64');

function fakeCiphertext(extra = {}) {
  return { iv: 'a'.repeat(24), authTag: 'b'.repeat(32), ciphertext: 'Y2lwaGVy', ...extra };
}

async function register(name) {
  const s = connect();
  await waitFor(s, 'connect');
  s.emit('register', {
    name,
    password: PASSWORD,
    publicKey: keyPair(name).publicKey,
    encryptedPrivateKey: { iv: 'a'.repeat(24), authTag: 'b'.repeat(32), salt: 'c'.repeat(32), data: 'd'.repeat(64) }
  });
  return { s, data: await waitFor(s, 'register_ok') };
}

async function login(name, password = PASSWORD) {
  const s = connect();
  await waitFor(s, 'connect');
  s.emit('login', { name, password });
  return s;
}

async function createPrivateChannel(owner, ownerName, name) {
  owner.emit('add_channel', { name, description: '', private: true, encryptedRoomKey: wrap(ownerName, crypto.randomBytes(32)) });
  return (await waitFor(owner, 'update_room')).room;
}

before(async () => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'e2e-chat-test-'));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', path.join(tmp, 'key.pem'), '-out', path.join(tmp, 'cert.pem'), '-days', '1',
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' });
  cert = fs.readFileSync(path.join(tmp, 'cert.pem'));
  port = 40000 + Math.floor(Math.random() * 10000);
  await startServer();
});

after(async () => {
  sockets.forEach(s => s.close());
  await stopServer();
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('wrong passwords are rejected and the account gets locked', async () => {
  const { s } = await register('locky');
  s.close();

  for (let i = 0; i < 5; i++) {
    const bad = await login('locky', 'Wrong-pass1');
    assert.equal((await waitFor(bad, 'login_error')).message, 'invalid credentials');
  }
  const locked = await login('locky');
  assert.match((await waitFor(locked, 'login_error')).message, /too many failed attempts/);
});

test('a non-member cannot add himself to a private channel', async () => {
  const alice = (await register('alice')).s;
  const mallory = (await register('mallory')).s;
  const room = await createPrivateChannel(alice, 'alice', 'secret');

  mallory.emit('add_user_to_channel', { user: 'mallory', channel: room.id, encryptedRoomKey: 'AAAA' });
  assert.equal((await waitFor(mallory, 'error_message')).message, 'unknown channel');

  mallory.emit('new message', { room: room.id, ...fakeCiphertext({ keyVersion: 1 }) });
  assert.equal((await waitFor(mallory, 'error_message')).message, 'unknown room');
  await expectNone(alice, 'new message');
});

test('malformed requests do not crash the server', async () => {
  const { s } = await register('fuzzer');
  s.emit('join_channel', { id: 9999 });
  s.emit('leave_channel', { id: '1' });
  s.emit('add_user_to_channel', {});
  s.emit('new message', null);
  s.emit('request_direct_room', { to: { toString: 1 } });
  s.emit('add_channel', { name: 'general' });
  s.emit('add_channel', { name: '<script>' });
  await new Promise(r => setTimeout(r, 300));

  const other = (await register('stillup')).s;
  assert.ok(other.connected);
});

test('plaintext is refused in private channels and direct messages', async () => {
  const owner = (await register('owner')).s;
  const room = await createPrivateChannel(owner, 'owner', 'plain');

  owner.emit('new message', { room: room.id, content: 'hello' });
  assert.equal((await waitFor(owner, 'error_message')).message, 'messages in this room must be encrypted');

  await register('friend');
  owner.emit('request_direct_room', { to: 'friend' });
  const dm = (await waitFor(owner, 'update_room')).room;
  owner.emit('new message', { room: dm.id, content: 'hello' });
  assert.equal((await waitFor(owner, 'error_message')).message, 'messages in this room must be encrypted');
});

test('leaving a private channel rotates its key without the leaver', async () => {
  const a = (await register('rot_a')).s;
  const b = (await register('rot_b')).s;
  const room = await createPrivateChannel(a, 'rot_a', 'rotating');

  a.emit('add_user_to_channel', { user: 'rot_b', channel: room.id, encryptedRoomKey: wrap('rot_b', crypto.randomBytes(32)) });
  await waitFor(b, 'room_key_update');

  const rekeyRequest = waitFor(a, 'rekey_request');
  const leaverRequest = expectNone(b, 'rekey_request');
  b.emit('leave_channel', { id: room.id });
  const request = await rekeyRequest;
  await leaverRequest;
  assert.deepEqual(request.members, ['rot_a']);
  assert.equal(request.version, 2);

  // messages with the old key are refused while the rotation is pending
  a.emit('new message', { room: room.id, ...fakeCiphertext({ keyVersion: 1 }) });
  assert.match((await waitFor(a, 'error_message')).message, /being rotated/);

  // the new key cannot be handed to the user who left
  const newKey = crypto.randomBytes(32);
  a.emit('rotate_room_key', { roomId: room.id, version: 2, keys: { rot_a: wrap('rot_a', newKey), rot_b: wrap('rot_b', newKey) } });
  assert.match((await waitFor(a, 'error_message')).message, /every member/);

  a.emit('rotate_room_key', { roomId: room.id, version: 2, keys: { rot_a: wrap('rot_a', newKey) } });
  const update = await waitFor(a, 'room_key_update');
  assert.equal(update.version, 2);

  a.emit('new message', { room: room.id, ...fakeCiphertext({ keyVersion: 2 }) });
  assert.equal((await waitFor(a, 'new message')).keyVersion, 2);
});

test('memberships and key versions survive a restart', async () => {
  const a = (await register('keep_a')).s;
  const b = (await register('keep_b')).s;
  const room = await createPrivateChannel(a, 'keep_a', 'persistent');
  a.emit('add_user_to_channel', { user: 'keep_b', channel: room.id, encryptedRoomKey: wrap('keep_b', crypto.randomBytes(32)) });
  await waitFor(b, 'room_key_update');
  a.close();
  b.close();

  await stopServer();
  await startServer();

  const again = await login('keep_b');
  const data = await waitFor(again, 'login_ok');
  assert.ok(data.rooms.some(r => r.id === room.id), 'private channel is still in the room list');
  assert.ok(data.roomKeys[room.id] && data.roomKeys[room.id][1], 'channel key is still available');
  assert.ok(data.rooms.some(r => r.name === 'general'));
});
