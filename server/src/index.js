require('dotenv').config();
const { drizzle } = require('drizzle-orm/better-sqlite3');
const Database = require('better-sqlite3');
const { usersTable } = require('./db/schema.js');

const sqlite = new Database(process.env.DB_FILE_NAME);
sqlite.pragma('foreign_keys = ON');


const db = drizzle(sqlite);





// test select
const users =  db.select().from(usersTable).run();
console.log(users);


// Setup basic express server
const express = require('express');
const app     = express();
const path    = require('path');
const server  = require('http').createServer(app);
const io      = require('socket.io')(server);
const port    = process.env.PORT || 3000;

const Rooms = require('./rooms.js')(db);
Rooms.init(); // load from the database
const Users   = require('./users.js')(db);

// Load application config/state
require('./basicstate.js').setup(Users, Rooms);

server.listen(port, () => {
  console.log('Server listening on port %d', port);
});


///////////////////////////////
// Chatroom helper functions //
///////////////////////////////

function sendToRoom(room, event, data) {
  io.to('room' + room.getId()).emit(event, data);
}

function newUser(name, password) {
  const user = Users.addUser(name, password);
  const rooms = Rooms.getForcedRooms();

  rooms.forEach(room => {
    addUserToRoom(user, room);
  });

  return user;
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
    username: user,
    action: 'added',
    members: room.getMembers()
  });
}

function removeUserFromRoom(user, room) {
  user.removeSubscription(room);
  room.removeMember(user);

  sendToRoom(room, 'update_user', {
    room: room.getId(),
    username: user,
    action: 'removed',
    members: room.getMembers()
  });
}

function addMessageToRoom(roomId, username, msg) {
  const room = Rooms.getRoom(roomId);
  msg.time = new Date().getTime();

  if (room) {
    const msgData = msg.iv
      ? { iv: msg.iv, authTag: msg.authTag, ciphertext: msg.ciphertext, keys: msg.keys || null }
      : { content: msg.content || msg.message || '' };

    sendToRoom(room, 'new message', {
      username,
      room: msg.room,
      time: msg.time,
      direct: room.direct,
      ...msgData
    });

    Rooms.addMessageToRoom(msgData, room, username, msg.time);
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

const socketmap = {};

io.on('connection', (socket) => {
  let userLoggedIn = false;
  let username = false;
  
  console.log("New Connection");

  ///////////////////////
  // incomming message //
  ///////////////////////

  socket.on('new message', (msg) => {
    if (userLoggedIn) {
      console.log(msg);
      addMessageToRoom(msg.room, username, msg);
    }
  });

  /////////////////////////////
  // request for direct room //
  /////////////////////////////


  socket.on('request_direct_room', req => {
    if (userLoggedIn) {
      const user_a = Users.getUser(req.to);
      const user_b = Users.getUser(username);

      if(user_a && user_b) {
        const room = getDirectRoom(user_a, user_b);
        const roomCID = 'room' + room.getId();
        socket.join(roomCID);
        if (socketmap[user_a.name])
         socketmap[user_a.name].join(roomCID);

        socket.emit('update_room', {
          room: room,
          moveto: true
        });
      }
    }
  });

  socket.on('add_channel', req => {
    if (userLoggedIn) {
      const user = Users.getUser(username);
      const room = newChannel(req.name, req.description, req.private, user);
      const roomCID = 'room' + room.getId();
      socket.join(roomCID);

      if (req.private && req.encryptedRoomKey) {
        Rooms.storeRoomKey(room.getId(), username, req.encryptedRoomKey);
      }

      socket.emit('update_room', { room, moveto: true });

      if (!room.private) {
        const publicChannels = Rooms.getRooms().filter(r => !r.direct && !r.private);
        socket.broadcast.emit('update_public_channels', { publicChannels });
      }
    }
  });

  socket.on('join_channel', req => {
    if (userLoggedIn) {
      const user = Users.getUser(username);
      const room = Rooms.getRoom(req.id)

      if(!room.direct && !room.private) {
        addUserToRoom(user, room);
        
        const roomCID = 'room' + room.getId();
        socket.join(roomCID);

        socket.emit('update_room', {
          room: room,
          moveto: true
        });
      }
    }
  });

  
  socket.on('add_user_to_channel', req => {
    if (userLoggedIn) {
      const user = Users.getUser(req.user);
      const room = Rooms.getRoom(req.channel);

      if (!room.direct) {
        addUserToRoom(user, room);

        if (room.private && req.encryptedRoomKey) {
          Rooms.storeRoomKey(room.getId(), req.user, req.encryptedRoomKey);
        }

        if (socketmap[user.name]) {
          const roomCID = 'room' + room.getId();
          socketmap[user.name].join(roomCID);
          socketmap[user.name].emit('update_room', { room, moveto: false });

          if (room.private && req.encryptedRoomKey) {
            socketmap[user.name].emit('room_key_update', {
              roomId:       room.getId(),
              encryptedKey: req.encryptedRoomKey
            });
          }
        }
      }
    }
  });

  socket.on('leave_channel', req => {
    if (userLoggedIn) {
      const user = Users.getUser(username);
      const room = Rooms.getRoom(req.id);

      if (!room.direct && !room.forceMembership) {
        removeUserFromRoom(user, room);
        Rooms.deleteRoomKey(room.getId(), username);

        if (room.private && req.rotatedKeys) {
          io.to('room' + room.getId()).emit('channel_rekeying', { roomId: room.getId() });
          for (const [memberName, encKey] of Object.entries(req.rotatedKeys)) {
            Rooms.storeRoomKey(room.getId(), memberName, encKey);
            if (socketmap[memberName]) {
              socketmap[memberName].emit('room_key_update', {
                roomId:       room.getId(),
                encryptedKey: encKey
              });
            }
          }
        }

        socket.leave('room' + room.getId());
        socket.emit('remove_room', { room: room.getId() });
      }
    }
  });

  ///////////////
  // user join //
  ///////////////

  socket.on('login', req => {
    if (userLoggedIn)
      return;

    const user = Users.login(req.name, req.password);

    if (!user) {
      socket.emit('login_error', { message: 'invalid credentials' });
      return;
    }

    username = req.name;
    userLoggedIn = true;
    socketmap[username] = socket;

    let memUser = Users.getUser(username);
    if (!memUser) {
      memUser = Users.loadUser(username);
      Rooms.getForcedRooms().forEach(room => addUserToRoom(memUser, room));
    }

    const rooms = memUser.getSubscriptions().map(s => {
      socket.join('room' + s);
      return Rooms.getRoom(s);
    });

    const publicChannels = Rooms.getRooms().filter(r => !r.direct && !r.private);

    // User get his key to decrypt the history of messages
    const roomKeysList = Rooms.getRoomKeysForUser(username);
    const roomKeysMap  = {};
    roomKeysList.forEach(rk => { roomKeysMap[rk.roomId] = rk.encryptedKey; });

    socket.emit('login_ok', {
      users:               Users.getUsers().map(u => ({ username: u.name, active: u.active, publicKey: u.publicKey })),
      rooms,
      publicChannels,
      encryptedPrivateKey: user.encrypted_private_key ? JSON.parse(user.encrypted_private_key) : null,
      roomKeys:            roomKeysMap
    });

    setUserActiveState(socket, username, true);
  })


  socket.on('register', req => {
    console.log(`[register] attempt: ${req.name}`);

    if (userLoggedIn) {
      socket.emit('register_error', { message: 'already logged in' });
      return;
    }

    // Double check of the username and password
    if (!req.name || /\s/.test(req.name))
      return socket.emit('register_error', { message: 'invalid username' });
    if (!req.password || req.password.length < 8 ||
        !/[A-Z]/.test(req.password) ||
        !/[0-9]/.test(req.password) ||
        !/[^A-Za-z0-9]/.test(req.password))
      return socket.emit('register_error', { message: 'password does not meet requirements' });

    // Usernames are unique
    try {
      Users.addUser(req.name, req.password, req.publicKey, req.encryptedPrivateKey);
    } catch (e) {
      socket.emit('register_error', { message: 'username already taken' });
      return;
    }

    username = req.name;
    userLoggedIn = true;
    socketmap[username] = socket;

    const memUser = Users.getUser(username);
    Rooms.getForcedRooms().forEach(room => addUserToRoom(memUser, room));

    const rooms = memUser.getSubscriptions().map(s => {
      socket.join('room' + s);
      return Rooms.getRoom(s);
    });

    const publicChannels = Rooms.getRooms().filter(r => !r.direct && !r.private);

    socket.emit('register_ok', {
      users:        Users.getUsers().map(u => ({ username: u.name, active: u.active, publicKey: u.publicKey })),
      rooms,
      publicChannels
    });

    console.log(`[register] success: ${username}, rooms: ${rooms.length}`);
    setUserActiveState(socket, username, true);
  });

  ////////////////
  // reconnects //
  ////////////////

  socket.on('reconnect', () => {
    if (userLoggedIn)
      setUserActiveState(socket, username, true);
  });

  /////////////////
  // disconnects //
  /////////////////

  socket.on('disconnect', () => {
    if (userLoggedIn)
      setUserActiveState(socket, username, false);
  });

});
