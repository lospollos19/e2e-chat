const { roomsTable, roomMemberTable, messagesTable, roomKeysTable } = require('./db/schema.js');
const { eq, and } = require('drizzle-orm');
const {text, integer} = require("drizzle-orm/sqlite-core");

const rooms = [];
let roomIdCounter = 0;

class Room {
    constructor(id, name, options) {
        this.id   =  id;
        this.name =  name;

        this.description = options.description || "";
      
        this.forceMembership = !!options.forceMembership;
        this.private         = !!options.private;
        this.direct          = !!options.direct;
  
        this.members = [];
        this.history = [];
    }

    getId() {
        return this.id;
    }

    getMembers() {
        return this.members;
    }

    getMemberCount(){
        return this.members.length;
    }

    addMember(user) {
        const name = typeof user === 'string' ? user : user.name;
        if (this.members.indexOf(name) === -1)
            this.members.push(name);
    }

    removeMember(user) {
        const name = typeof user === 'string' ? user : user.name;
        const idx = this.members.indexOf(name);
        if (idx >= 0)
            this.members.splice(idx, 1);
    }

    getHistory() {
        return this.history;
    }

    addMessage(msg) {
        this.history.push(msg);
    }
}

//return newRoom(name, user, {
//    description: description,
//    private: private
//});

module.exports = (db) => {
    const init = () => {
        const dbRooms = db.select().from(roomsTable).all();
        dbRooms.forEach(r => {
            const room = new Room(r.id, r.name, {
                description: r.description,
                forceMembership: !!r.force_membership,
                private: !!r.is_private,
                direct: !!r.is_direct
            });

            const members = db.select().from(roomMemberTable)
                .where(eq(roomMemberTable.roomId, r.id)).all();
            members.forEach(m => room.members.push(m.userName));

            const messages = db.select().from(messagesTable)
                .where(eq(messagesTable.roomId, r.id)).all();
            messages.forEach(m => room.history.push({
                username:   m.userName,
                content:    m.content    || null,
                iv:         m.iv         || null,
                authTag:    m.authTag    || null,
                ciphertext: m.ciphertext || null,
                keys:       m.keys ? JSON.parse(m.keys) : null,
                time:       m.timestamp,
                room:       r.id
            }));

            rooms[r.id] = room;
            roomIdCounter = Math.max(roomIdCounter, r.id + 1);
        });
    };

    return {
        init,

        addMemberToRoom: (username, room) => {
            if (room.members.indexOf(username) !== -1) return;
            db.insert(roomMemberTable).values({
                roomId: room.id,
                userName: username
            }).run();
            room.addMember(username);
        },

        addRoom: (name, options) => {
            const result = db.insert(roomsTable).values({
                name,
                description: options.description || "",
                force_membership: options.forceMembership ? 1 : 0,
                is_private: options.private ? 1 : 0,
                is_direct: 0
            }).run();

            const id = result.lastInsertRowid;
            const room = new Room(id, name, options);
            rooms[id] = room;
            return room;
        },

        addDmRoom: (userA, userB) => {
            const name = `Direct-${userA.name}-${userB.name}`;
            const result = db.insert(roomsTable).values({
                name,
                description: "",
                force_membership: 0,
                is_private: 1,
                is_direct: 1
            }).run();

            const id = result.lastInsertRowid;
            const room = new Room(id, name, { direct: true, private: true });
            rooms[id] = room;
            return room;
        },

        getRooms: () => rooms,

        getForcedRooms: () => rooms.filter(r => r.forceMembership),

        getRoom: id => rooms[id],

        getRoomByName: name => rooms.find(r => r && r.name === name),

        storeRoomKey: (roomId, userName, encryptedKey) => {
            db.insert(roomKeysTable)
                .values({ roomId, userName, encryptedKey })
                .onConflictDoUpdate({ target: [roomKeysTable.roomId, roomKeysTable.userName], set: { encryptedKey } })
                .run();
        },

        deleteRoomKey: (roomId, userName) => {
            db.delete(roomKeysTable)
                .where(and(eq(roomKeysTable.roomId, roomId), eq(roomKeysTable.userName, userName)))
                .run();
        },

        getRoomKeysForUser: (userName) => {
            return db.select().from(roomKeysTable).where(eq(roomKeysTable.userName, userName)).all();
        },

        addMessageToRoom: (msgData, room, username, msgTime) => {
            db.insert(messagesTable).values({
                roomId:     room.id,
                userName:   username,
                content:    msgData.content    || null,
                iv:         msgData.iv         || null,
                authTag:    msgData.authTag     || null,
                ciphertext: msgData.ciphertext  || null,
                keys:       msgData.keys ? JSON.stringify(msgData.keys) : null,
                timestamp:  msgTime
            }).run();
            room.addMessage({ username, ...msgData, time: msgTime, room: room.id });
        }
    };
};