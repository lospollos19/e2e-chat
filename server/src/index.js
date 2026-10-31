require('dotenv').config({ quiet: true });
const fs       = require('fs');
const path     = require('path');
const { drizzle } = require('drizzle-orm/better-sqlite3');
const { migrate } = require('drizzle-orm/better-sqlite3/migrator');
const Database = require('better-sqlite3');

const sqlite = new Database(process.env.DB_FILE_NAME || 'chat.db');
sqlite.pragma('foreign_keys = ON');

const db = drizzle(sqlite);
migrate(db, { migrationsFolder: path.join(__dirname, '..', 'drizzle') });


// Setup HTTPS + socket.io server
const certFile = process.env.TLS_CERT || path.join(__dirname, '..', 'certs', 'cert.pem');
const keyFile  = process.env.TLS_KEY  || path.join(__dirname, '..', 'certs', 'key.pem');

if (!fs.existsSync(certFile) || !fs.existsSync(keyFile)) {
  console.error(`TLS certificate not found (${certFile}). Run "npm run gen-cert" first.`);
  process.exit(1);
}

const server = require('https').createServer({
  cert: fs.readFileSync(certFile),
  key:  fs.readFileSync(keyFile)
});
const io   = require('socket.io')(server, { maxHttpBufferSize: 1e5 });
const port = process.env.PORT || 3000;

const Rooms = require('./rooms.js')(db);
Rooms.init(); // load from the database
const Users   = require('./users.js')(db);

// Load application config/state
require('./basicstate.js').setup(Users, Rooms);

server.listen(port, () => {
  console.log('Server listening on port %d', port);
});


//////////////////////
// Input validation //
//////////////////////

const USERNAME_RE     = /^[A-Za-z0-9_]{3,20}$/;
const CHANNEL_RE      = /^[A-Za-z0-9_-]{1,30}$/;
const HEX_RE          = /^[0-9a-f]*$/i;
const BASE64_RE       = /^[A-Za-z0-9+/]*={0,2}$/;
const MAX_MESSAGE     = 4000;
const MAX_CIPHERTEXT  = 8000;
const MAX_WRAPPED_KEY = 700;   // RSA-2048 OAEP output in base64 is 344 chars

const isHex    = (v, max) => typeof v === 'string' && v.length > 0 && v.length <= max && HEX_RE.test(v);
const isBase64 = (v, max) => typeof v === 'string' && v.length > 0 && v.length <= max && BASE64_RE.test(v);
const isObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);

// The client sends a PBKDF2 secret derived from the password, never the password itself,
// so the password policy can only be checked on the client
function validAuthSecret(p) {
  return typeof p === 'string' && p.length === 64 && HEX_RE.test(p);
}

function validPublicKey(k) {
  return typeof k === 'string' && k.length <= 1000 && k.startsWith('-----BEGIN PUBLIC KEY-----');
}

function validEncryptedPrivateKey(k) {
  return isObject(k) && isHex(k.iv, 24) && isHex(k.authTag, 32) && isHex(k.salt, 32) && isHex(k.data, 8000);
}

// keys must be a {username: wrappedKey} map for exactly the given members
function validKeyMap(keys, members) {
  if (!isObject(keys)) return false;
  const names = Object.keys(keys);
  return names.length === members.length &&
    members.every(m => Object.hasOwn(keys, m) && isBase64(keys[m], MAX_WRAPPED_KEY));
}

// Returns what gets stored for a message, or an error string
function cleanMessage(msg, room) {
  if (!room.private && !room.direct) {
    if (typeof msg.content !== 'string' || msg.content.length === 0 || msg.content.length > MAX_MESSAGE)
      return 'invalid message';
    return { content: msg.content };
  }

  // private channels and direct messages only accept ciphertext
  if (!isHex(msg.iv, 24) || !isHex(msg.authTag, 32) || !isBase64(msg.ciphertext, MAX_CIPHERTEXT))
    return 'messages in this room must be encrypted';

  const data = { iv: msg.iv, authTag: msg.authTag, ciphertext: msg.ciphertext };

  if (room.direct) {
    if (!validKeyMap(msg.keys, room.getMembers()))
      return 'invalid message keys';
    data.keys = msg.keys;
  } else {
    if (room.needsRekey)
      return 'channel key is being rotated, try again';
    if (msg.keyVersion !== room.keyVersion)
      return 'message encrypted with an outdated channel key';
    data.keyVersion = room.keyVersion;
  }
  return data;
}


///////////////////////////////
// Chatroom helper functions //
///////////////////////////////

const socketmap = Object.create(null);

function sendToRoom(room, event, data) {
  io.to('room' + room.getId()).emit(event, data);
}

function getOrLoadUser(name) {
  if (typeof name !== 'string' || !USERNAME_RE.test(name))
    return undefined;
  return Users.getUser(name) || (Users.getUsers(), Users.getUser(name));
}

function newRoom(name, user, options) {
  const room = Rooms.addRoom(name, options);
  addUserToRoom(user, room);
  return room;
}

function newChannel(name, _description, _private, user) {
  return newRoom(name, user, {
    description: _description,
    private: _private
  });
}

function newDirectRoom(user_a, user_b) {
  const room = Rooms.addDmRoom(user_a, user_b)
  addUserToRoom(user_a, room);
  addUserToRoom(user_b, room);
  return room;
}

function getDirectRoom(user_a, user_b) {
  const rooms = Rooms.getRooms().filter(r => r.direct
    && (
      (r.members[0] == user_a.name && r.members[1] == user_b.name) ||
      (r.members[1] == user_a.name && r.members[0] == user_b.name)
    ));

  if (rooms.length == 1)
    return rooms[0];
  else
    return newDirectRoom(user_a, user_b);
}

function addUserToRoom(user, room) {
  user.addSubscription(room);
  Rooms.addMemberToRoom(user.name, room)
  sendToRoom(room, 'update_user', {
    room: room.getId(),
    username: user.name,
    action: 'added',
    members: room.getMembers()
  });
}

function removeUserFromRoom(user, room) {
  user.removeSubscription(room);
  Rooms.removeMemberFromRoom(user.name, room);

  sendToRoom(room, 'update_user', {
    room: room.getId(),
    username: user.name,
    action: 'removed',
    members: room.getMembers()
  });
}

function addMessageToRoom(room, username, msgData) {
  const time = new Date().getTime();

  sendToRoom(room, 'new message', {
    username,
    room: room.getId(),
    time,
    direct: room.direct,
    ...msgData
  });

  Rooms.addMessageToRoom(msgData, room, username, time);
}

// Ask one online member that stays in the channel to generate and distribute a new key.
// The member who left never sees it.
function requestRekey(room) {
  if (!room.needsRekey) return;
  const member = room.getMembers().find(m => socketmap[m]);
  if (member) {
    socketmap[member].emit('rekey_request', {
      roomId:  room.getId(),
      version: room.keyVersion + 1,
      members: room.getMembers()
    });
  }
}

function setUserActiveState(socket, username, state) {
  const user = Users.getUser(username);

  if (user)
    user.setActiveState(state);

  socket.broadcast.emit('user_state_change', {
    username:  username,
    active:    state,
    publicKey: user ? user.publicKey : null
  });
}

///////////////////////////
// IO connection handler //
///////////////////////////

io.on('connection', (socket) => {
  let userLoggedIn = false;
  let username = false;

  // Every handler gets an object, only runs when logged in (unless public),
  // and a bad request can never crash the server.
  function on(event, handler, { requireLogin = true } = {}) {
    socket.on(event, (req) => {
      if (requireLogin && !userLoggedIn)
        return;
      if (!isObject(req))
        req = {};
      try {
        handler(req);
      } catch (e) {
        console.error(`[${event}] ${e.message}`);
        socket.emit('error_message', { message: 'request failed' });
      }
    });
  }

  function fail(message) {
    socket.emit('error_message', { message });
  }

  // returns the room if the current user is a member of it
  function memberRoom(id) {
    const room = Rooms.getRoom(id);
    return room && room.hasMember(username) ? room : undefined;
  }

  function startSession(name) {
    username = name;
    userLoggedIn = true;
    socketmap[username] = socket;

    const memUser = Users.getUser(username) || Users.loadUser(username);
    Rooms.getForcedRooms().forEach(room => {
      if (!room.hasMember(username))
        addUserToRoom(memUser, room);
    });

    const rooms = memUser.getSubscriptions().map(s => {
      socket.join('room' + s);
      return Rooms.getRoom(s);
    }).filter(Boolean);

    return {
      users:          Users.getUsers().map(u => ({ username: u.name, active: u.active, publicKey: u.publicKey })),
      rooms,
      publicChannels: Rooms.getRooms().filter(r => !r.direct && !r.private)
    };
  }

  ///////////////////////
  // incomming message //
  ///////////////////////

  on('new message', (msg) => {
    const room = memberRoom(msg.room);
    if (!room)
      return fail('unknown room');

    const msgData = cleanMessage(msg, room);
    if (typeof msgData === 'string')
      return fail(msgData);

    addMessageToRoom(room, username, msgData);
  });

  /////////////////////////////
  // request for direct room //
  /////////////////////////////

  on('request_direct_room', req => {
    const user_a = getOrLoadUser(req.to);
    const user_b = Users.getUser(username);

    if (!user_a || user_a === user_b)
      return fail('unknown user');

    const room = getDirectRoom(user_a, user_b);
    const roomCID = 'room' + room.getId();
    socket.join(roomCID);
    if (socketmap[user_a.name]) {
      socketmap[user_a.name].join(roomCID);
      socketmap[user_a.name].emit('update_room', { room, moveto: false });
    }

    socket.emit('update_room', {
      room: room,
      moveto: true
    });
  });

  on('add_channel', req => {
    const user = Users.getUser(username);
    const isPrivate = req.private === true;

    if (typeof req.name !== 'string' || !CHANNEL_RE.test(req.name) || req.name.startsWith('Direct-'))
      return fail('channel names are 1-30 letters, digits, - or _');
    if (Rooms.getRoomByName(req.name))
      return fail('channel name already taken');
    if (req.description !== undefined && (typeof req.description !== 'string' || req.description.length > 200))
      return fail('description is too long');
    if (isPrivate && !isBase64(req.encryptedRoomKey, MAX_WRAPPED_KEY))
      return fail('private channels need an encrypted channel key');

    const room = newChannel(req.name, req.description || '', isPrivate, user);
    const roomCID = 'room' + room.getId();
    socket.join(roomCID);

    if (isPrivate)
      Rooms.storeRoomKey(room.getId(), username, room.keyVersion, req.encryptedRoomKey);

    socket.emit('update_room', { room, moveto: true });

    if (!room.private) {
      const publicChannels = Rooms.getRooms().filter(r => !r.direct && !r.private);
      socket.broadcast.emit('update_public_channels', { publicChannels });
    }
  });

  on('join_channel', req => {
    const user = Users.getUser(username);
    const room = Rooms.getRoom(req.id)

    if (!room || room.direct || room.private)
      return fail('unknown channel');

    addUserToRoom(user, room);

    const roomCID = 'room' + room.getId();
    socket.join(roomCID);

    socket.emit('update_room', {
      room: room,
      moveto: true
    });
  });

  // only members can add someone, and for a private channel they hand over the channel key
  on('add_user_to_channel', req => {
    const room = memberRoom(req.channel);
    const user = getOrLoadUser(req.user);

    if (!room || room.direct)
      return fail('unknown channel');
    if (!user)
      return fail('unknown user');
    if (room.hasMember(user.name))
      return;
    if (room.private && room.needsRekey)
      return fail('channel key is being rotated, try again');
    if (room.private && !isBase64(req.encryptedRoomKey, MAX_WRAPPED_KEY))
      return fail('missing encrypted channel key');

    if (room.private)
      Rooms.storeRoomKey(room.getId(), user.name, room.keyVersion, req.encryptedRoomKey);
    addUserToRoom(user, room);

    if (socketmap[user.name]) {
      const roomCID = 'room' + room.getId();
      socketmap[user.name].join(roomCID);
      socketmap[user.name].emit('update_room', { room, moveto: false });

      if (room.private) {
        socketmap[user.name].emit('room_key_update', {
          roomId:       room.getId(),
          version:      room.keyVersion,
          encryptedKey: req.encryptedRoomKey
        });
      }
    }
  });

  on('leave_channel', req => {
    const user = Users.getUser(username);
    const room = memberRoom(req.id);

    if (!room || room.direct || room.forceMembership)
      return fail('cannot leave this channel');

    removeUserFromRoom(user, room);
    Rooms.deleteRoomKeys(room.getId(), username);
    socket.leave('room' + room.getId());
    socket.emit('remove_room', { room: room.getId() });

    // the old key is known by the user who left: the channel needs a new one
    if (room.private && room.getMemberCount() > 0) {
      Rooms.setNeedsRekey(room);
      sendToRoom(room, 'channel_rekeying', { roomId: room.getId() });
      requestRekey(room);
    }
  });

  // answer to 'rekey_request': the new key, wrapped for every current member
  on('rotate_room_key', req => {
    const room = memberRoom(req.roomId);

    if (!room || !room.private || room.direct || !room.needsRekey)
      return fail('no key rotation pending for this channel');
    if (req.version !== room.keyVersion + 1)
      return fail('wrong key version');
    if (!validKeyMap(req.keys, room.getMembers()))
      return fail('the new key must be wrapped for every member');

    for (const [member, encKey] of Object.entries(req.keys))
      Rooms.storeRoomKey(room.getId(), member, req.version, encKey);
    Rooms.setKeyVersion(room, req.version);

    for (const [member, encKey] of Object.entries(req.keys)) {
      if (socketmap[member]) {
        socketmap[member].emit('room_key_update', {
          roomId:       room.getId(),
          version:      req.version,
          encryptedKey: encKey
        });
      }
    }
  });

  ///////////////
  // user join //
  ///////////////

  on('login', req => {
    if (userLoggedIn)
      return;

    if (typeof req.name !== 'string' || typeof req.password !== 'string' ||
        req.name.length > 20 || req.password.length > 128)
      return socket.emit('login_error', { message: 'invalid credentials' });

    const user = Users.login(req.name, req.password);

    if (user === 'locked')
      return socket.emit('login_error', { message: 'too many failed attempts, try again in a minute' });
    if (!user)
      return socket.emit('login_error', { message: 'invalid credentials' });

    const state = startSession(req.name);

    // User get his keys (every version) to decrypt the history of messages
    const roomKeys = {};
    Rooms.getRoomKeysForUser(username).forEach(rk => {
      roomKeys[rk.roomId] = roomKeys[rk.roomId] || {};
      roomKeys[rk.roomId][rk.version] = rk.encryptedKey;
    });

    socket.emit('login_ok', {
      ...state,
      encryptedPrivateKey: user.encrypted_private_key ? JSON.parse(user.encrypted_private_key) : null,
      roomKeys
    });

    setUserActiveState(socket, username, true);

    // rotations that could not happen while nobody was online
    Rooms.getRoomsOfUser(username).forEach(requestRekey);
  }, { requireLogin: false });


  on('register', req => {
    if (userLoggedIn)
      return socket.emit('register_error', { message: 'already logged in' });

    console.log(`[register] attempt: ${req.name}`);

    // Double check of the username and password
    if (typeof req.name !== 'string' || !USERNAME_RE.test(req.name))
      return socket.emit('register_error', { message: 'usernames are 3-20 letters, digits or _' });
    if (!validAuthSecret(req.password))
      return socket.emit('register_error', { message: 'invalid password' });
    if (!validPublicKey(req.publicKey) || !validEncryptedPrivateKey(req.encryptedPrivateKey))
      return socket.emit('register_error', { message: 'invalid key material' });

    // Usernames are unique
    try {
      Users.addUser(req.name, req.password, req.publicKey, req.encryptedPrivateKey);
    } catch (e) {
      socket.emit('register_error', { message: 'username already taken' });
      return;
    }

    const state = startSession(req.name);
    socket.emit('register_ok', state);

    console.log(`[register] success: ${username}, rooms: ${state.rooms.length}`);
    setUserActiveState(socket, username, true);
  }, { requireLogin: false });

  /////////////////
  // disconnects //
  /////////////////

  socket.on('disconnect', () => {
    if (!userLoggedIn)
      return;

    if (socketmap[username] === socket)
      delete socketmap[username];
    setUserActiveState(socket, username, false);

    // if this user was asked to rotate a key, ask someone else
    Rooms.getRoomsOfUser(username).forEach(requestRekey);
  });

});
