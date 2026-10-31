const io       = require('socket.io-client');
const electron = require('electron');

const SERVER = "localhost";
const PORT   = 3000;

$(function() {
  electron.ipcRenderer.send('get-user-data');
  electron.ipcRenderer.on('user-data', function (event, data) {
    load(data);
  });
});

function load(userdata) {
  const $window        = $(window);
  const $messages      = $('.messages');
  const $inputMessage  = $('#input-message');
  const $usernameLabel = $('#user-name');
  const $roomList      = $('#room-list');
  const $userList      = $('#user-list');

  const crypto = require('crypto');

  let username   = userdata.name;
  let privateKey = null;

  const publicKeys         = {};  // username → RSA PEM public key
  const roomKeys           = {};  // roomId   → Buffer (plaintext AES-256 channel key)
  const pendingChannelKeys = {};  // channelName → Buffer (key generated before server confirms room id)
  const rekeyingRooms      = new Set(); // roomIds currently rotating key — block sends

  if (userdata.encryptedPrivateKey && userdata.password) {
    try {
      const epk    = userdata.encryptedPrivateKey;
      const salt   = Buffer.from(epk.salt,    'hex');
      const iv     = Buffer.from(epk.iv,      'hex');
      const aesKey = crypto.pbkdf2Sync(userdata.password, salt, 100000, 32, 'sha256');
      const dec    = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
      dec.setAuthTag(Buffer.from(epk.authTag, 'hex'));
      privateKey = dec.update(epk.data, 'hex', 'utf8') + dec.final('utf8');
    } catch (e) {
      console.error('Private key decrypt failed:', e.message);
    }
  }

  // ─── Crypto helpers ──────────────────────────────────────────────────────────

  const OAEP = { padding: crypto.constants.RSA_PKCS1_OAEP_PADDING };

  function rsaEncrypt(pubKey, buf) {
    return crypto.publicEncrypt({ key: pubKey, ...OAEP }, buf).toString('base64');
  }

  function rsaDecrypt(b64) {
    if (!privateKey) return null;
    try {
      return crypto.privateDecrypt({ key: privateKey, ...OAEP }, Buffer.from(b64, 'base64'));
    } catch (e) { return null; }
  }

  function aesEncrypt(plaintext, key) {
    const iv     = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct     = cipher.update(plaintext, 'utf8', 'base64') + cipher.final('base64');
    return { iv: iv.toString('hex'), authTag: cipher.getAuthTag().toString('hex'), ciphertext: ct };
  }

  function aesDecrypt(enc, key) {
    const dec = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(enc.iv, 'hex'));
    dec.setAuthTag(Buffer.from(enc.authTag, 'hex'));
    return dec.update(enc.ciphertext, 'base64', 'utf8') + dec.final('utf8');
  }

  // DM: returns {iv, authTag, ciphertext, keys} or null
  function dmEncrypt(plaintext, recipientName) {
    const recipientPub = publicKeys[recipientName];
    const senderPub    = publicKeys[username];
    if (!recipientPub || !senderPub || !privateKey) return null;

    const aesKey = crypto.randomBytes(32);
    const enc    = aesEncrypt(plaintext, aesKey);
    return {
      ...enc,
      keys: {
        [recipientName]: rsaEncrypt(recipientPub, aesKey),
        [username]:      rsaEncrypt(senderPub,    aesKey)
      }
    };
  }

  // Private channel: returns {iv, authTag, ciphertext}
  // to have everything needed to decrypt
  function channelEncrypt(plaintext, roomId) {
    const key = roomKeys[roomId];
    if (!key) return null;
    return aesEncrypt(plaintext, key);
  }

  // Decrypt a message
  function decrypt(msg, roomId) {
    if (msg.iv && msg.ciphertext) {
      try {
        if (msg.keys) {
          const encKey = msg.keys[username];
          if (!encKey) return '[encrypted message]';
          const aesKey = rsaDecrypt(encKey);
          if (!aesKey) return '[decryption failed]';
          return aesDecrypt(msg, aesKey);
        } else {
          const key = roomKeys[roomId];
          if (!key) return '[encrypted message]';
          return aesDecrypt(msg, key);
        }
      } catch (e) {
        return '[decryption failed]';
      }
    }
    return msg.content || '';
  }

  function decryptRoomKeyBlob(b64) {
    const buf = rsaDecrypt(b64);
    return buf;
  }

  // ─── UI helpers ──────────────────────────────────────────────────────────────

  $usernameLabel.text(username);

  let connected    = false;
  let socket       = io(`ws://${SERVER}:${PORT}`, { transports: ['websocket'] });
  let modalShowing = false;

  $('#addChannelModal').on('hide.bs.modal', () => { modalShowing = false; })
                       .on('show.bs.modal', () => { modalShowing = true;  });

  // ─── User list ───────────────────────────────────────────────────────────────

  let users = {};

  function updateUsers(p_users) {
    p_users.forEach(u => {
      users[u.username] = u;
      if (u.publicKey) publicKeys[u.username] = u.publicKey;
    });
    updateUserList();
  }

  function updateUser(uname, active) {
    if (!users[uname]) users[uname] = { username: uname };
    users[uname].active = active;
    updateUserList();
  }

  function updateUserList() {
    const $uta = $('#usersToAdd');
    $uta.empty();
    $userList.empty();

    for (const [, user] of Object.entries(users)) {
      if (user.username === username) continue;

      const li = document.createElement('li');
      li.textContent  = user.username;
      li.className    = user.active ? 'online' : 'offline';
      li.dataset.direct = user.username;
      li.addEventListener('click', () => window.setDirectRoom(li));
      $userList.append(li);

      const btn = document.createElement('button');
      btn.type      = 'button';
      btn.className = 'list-group-item list-group-item-action';
      btn.setAttribute('data-bs-dismiss', 'modal');
      btn.textContent = user.username;
      btn.addEventListener('click', () => addToChannel(user.username));
      $uta.append(btn);
    }
  }

  // ─── Room list ───────────────────────────────────────────────────────────────

  let rooms = [];

  function updateRooms(p_rooms) {
    rooms = [];
    p_rooms.forEach(r => { rooms[r.id] = r; });
    updateRoomList();
  }

  function updateRoom(room) {
    rooms[room.id] = room;
    updateRoomList();
  }

  function removeRoom(id) {
    delete rooms[id];
    delete roomKeys[id];
    updateRoomList();
  }

  function updateRoomList() {
    $roomList.empty();
    rooms.forEach(r => {
      if (r.direct) return;
      const li = document.createElement('li');
      li.textContent  = r.name;
      li.className    = r.private ? 'private' : 'public';
      li.dataset.room = r.id;
      li.addEventListener('click', () => setRoom(r.id));
      $roomList.append(li);
    });
  }

  function updateChannels(channels) {
    const $c = $('#channelJoins');
    $c.empty();
    channels.forEach(r => {
      if (rooms[r.id]) return;
      const btn = document.createElement('button');
      btn.type      = 'button';
      btn.className = 'list-group-item list-group-item-action';
      btn.setAttribute('data-bs-dismiss', 'modal');
      btn.textContent = r.name;
      btn.addEventListener('click', () => joinChannel(r.id));
      $c.append(btn);
    });
  }

  // ─── Chat ────────────────────────────────────────────────────────────────────

  let currentRoom = false;

  function setRoom(id) {
    const room = rooms[id];
    currentRoom = room;

    $messages.empty();
    room.history.forEach(m => addChatMessage(m));

    $userList.find('li').removeClass('active');
    $roomList.find('li').removeClass('active');

    if (room.direct) {
      const idx  = room.members.indexOf(username) === 0 ? 1 : 0;
      const user = room.members[idx];
      setDirectRoomHeader(user);
      $userList.find('li').filter(function() { return this.dataset.direct === user; })
        .addClass('active').removeClass('unread').attr('data-room', room.id);
    } else {
      $('#channel-name').text('#' + room.name);
      $('#channel-description').text(`👤 ${room.members.length} | ${room.description}`);
      $roomList.find('li').filter(function() { return parseInt(this.dataset.room) === room.id; })
        .addClass('active').removeClass('unread');
    }

    $('.roomAction').css('visibility', (room.direct || room.forceMembership) ? 'hidden' : 'visible');
  }
  window.setRoom = setRoom;

  function setDirectRoomHeader(user) {
    $('#channel-name').text(user);
    $('#channel-description').text('Direct message with ' + user);
  }

  function setToDirectRoom(user) {
    setDirectRoomHeader(user);
    socket.emit('request_direct_room', { to: user });
  }

  window.setDirectRoom = (el) => {
    const user = el.dataset.direct;
    const room = el.dataset.room;
    if (room) setRoom(parseInt(room));
    else      setToDirectRoom(user);
  };

  function sendMessage() {
    const text = $inputMessage.val();
    if (!text || !connected || currentRoom === false) return;
    if (currentRoom.private && rekeyingRooms.has(currentRoom.id)) return;
    $inputMessage.val('');

    let msgData;
    if (currentRoom.direct) {
      const other = currentRoom.members.find(m => m !== username);
      const enc   = other ? dmEncrypt(text, other) : null;
      msgData = enc || { content: text };
    } else if (currentRoom.private) {
      const enc = channelEncrypt(text, currentRoom.id);
      msgData = enc || { content: text };
    } else {
      msgData = { content: text };
    }

    socket.emit('new message', { username, room: currentRoom.id, ...msgData });
  }

  function addChatMessage(msg) {
    if (typeof msg === 'string') msg = { message: msg };

    const time = msg.time
      ? new Date(msg.time).toLocaleTimeString('en-US', { hour12: false, hour: 'numeric', minute: 'numeric' })
      : '';

    const wrap    = document.createElement('div');  wrap.className    = 'message';
    const avatar  = document.createElement('div');  avatar.className  = 'message-avatar';
    const textual = document.createElement('div');  textual.className = 'message-textual';
    const user    = document.createElement('span'); user.className    = 'message-user';
    const ts      = document.createElement('span'); ts.className      = 'message-time';
    const content = document.createElement('span'); content.className = 'message-content';

    user.textContent    = msg.username || '';
    ts.textContent      = time;
    content.textContent = decrypt(msg, msg.room !== undefined ? msg.room : (currentRoom ? currentRoom.id : undefined));

    textual.append(user, ts, content);
    wrap.append(avatar, textual);
    $messages.append(wrap);
    $messages[0].scrollTop = $messages[0].scrollHeight;
  }

  function messageNotify(msg) {
    if (msg.direct)
      $userList.find('li').filter(function() { return this.dataset.direct === msg.username; }).addClass('unread');
    else
      $roomList.find('li').filter(function() { return parseInt(this.dataset.room) === msg.room; }).addClass('unread');
  }

  function addChannel() {
    const name        = $('#inp-channel-name').val();
    const description = $('#inp-channel-description').val();
    const private_    = $('#inp-private').is(':checked');

    let encryptedRoomKey = null;
    if (private_ && publicKeys[username]) {
      const key = crypto.randomBytes(32);
      pendingChannelKeys[name] = key;
      encryptedRoomKey = rsaEncrypt(publicKeys[username], key);
    }

    socket.emit('add_channel', { name, description, private: private_, encryptedRoomKey });
  }
  window.addChannel = addChannel;

  function joinChannel(id) {
    socket.emit('join_channel', { id });
  }
  window.joinChannel = joinChannel;

  function addToChannel(user) {
    const encryptedRoomKey = (currentRoom && currentRoom.private && roomKeys[currentRoom.id] && publicKeys[user])
      ? rsaEncrypt(publicKeys[user], roomKeys[currentRoom.id])
      : null;
    socket.emit('add_user_to_channel', { channel: currentRoom.id, user, encryptedRoomKey });
  }
  window.addToChannel = addToChannel;

  function leaveChannel() {
    let rotatedKeys = null;
    if (currentRoom && currentRoom.private && roomKeys[currentRoom.id]) {
      const newKey          = crypto.randomBytes(32);
      const remainingMembers = currentRoom.members.filter(m => m !== username);
      rotatedKeys = {};
      for (const member of remainingMembers) {
        if (publicKeys[member]) rotatedKeys[member] = rsaEncrypt(publicKeys[member], newKey);
      }
    }
    socket.emit('leave_channel', { id: currentRoom.id, rotatedKeys });
  }
  window.leaveChannel = leaveChannel;

  // ─── Keyboard ────────────────────────────────────────────────────────────────

  $window.on('keydown', event => {
    if (modalShowing) return;
    if (!(event.ctrlKey || event.metaKey || event.altKey)) $inputMessage.trigger('focus');
    if (event.which === 13) sendMessage();
    if (event.which === 13 || event.which === 10) event.preventDefault();
  });

  // ─── Server events ───────────────────────────────────────────────────────────

  socket.on('login_ok', (data) => {
    connected = true;
    updateUsers(data.users);
    updateRooms(data.rooms);
    updateChannels(data.publicChannels);

    if (data.roomKeys && privateKey) {
      for (const [roomId, encKey] of Object.entries(data.roomKeys)) {
        const key = decryptRoomKeyBlob(encKey);
        if (key) roomKeys[parseInt(roomId)] = key;
      }
    }

    if (data.rooms.length > 0) setRoom(data.rooms[0].id);
  });

  socket.on('update_public_channels', (data) => {
    updateChannels(data.publicChannels);
  });

  socket.on('new message', (msg) => {
    const roomId = msg.room;
    const room   = rooms[roomId];
    if (room) room.history.push(msg);

    if (currentRoom && roomId === currentRoom.id) addChatMessage(msg);
    else messageNotify(msg);
  });

  socket.on('update_user', data => {
    const room = rooms[data.room];
    if (room) {
      room.members = data.members;
      if (room === currentRoom) setRoom(data.room);
    }
  });

  socket.on('user_state_change', (data) => {
    if (data.publicKey) publicKeys[data.username] = data.publicKey;
    updateUser(data.username, data.active);
  });

  socket.on('update_room', data => {
    updateRoom(data.room);
    // If this is a private channel we just created, store its key
    if (data.room.private && pendingChannelKeys[data.room.name]) {
      roomKeys[data.room.id] = pendingChannelKeys[data.room.name];
      delete pendingChannelKeys[data.room.name];
    }
    if (data.moveto) setRoom(data.room.id);
  });

  socket.on('channel_rekeying', ({ roomId }) => {
    rekeyingRooms.add(roomId);
  });

  socket.on('room_key_update', (data) => {
    const key = decryptRoomKeyBlob(data.encryptedKey);
    if (key) roomKeys[data.roomId] = key;
    rekeyingRooms.delete(data.roomId);
  });

  socket.on('remove_room', data => {
    removeRoom(data.room);
    if (currentRoom && currentRoom.id === data.room) setRoom(0);
  });

  socket.on('connect', () => {
    socket.emit('login', { name: userdata.name, password: userdata.password });
  });

  socket.on('disconnect', () => { console.log('disconnect'); });

  socket.on('reconnect', () => {
    socket.emit('login', { name: userdata.name, password: userdata.password });
  });
}
