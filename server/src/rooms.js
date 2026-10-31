const { roomsTable, roomMemberTable, messagesTable, roomKeysTable } = require('./db/schema.js');
const { eq, and } = require('drizzle-orm');

const rooms = [];

class Room {
    constructor(id, name, options) {
        this.id   =  id;
        this.name =  name;

        this.description = options.description || "";

        this.forceMembership = !!options.forceMembership;
        this.private         = !!options.private;
        this.direct          = !!options.direct;

        this.keyVersion = options.keyVersion || 1;
        this.needsRekey = !!options.needsRekey;

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

    hasMember(user) {
        const name = typeof user === 'string' ? user : user.name;
        return this.members.indexOf(name) !== -1;
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

module.exports = (db) => {
    const init = () => {
        const dbRooms = db.select().from(roomsTable).all();
        dbRooms.forEach(r => {
            const room = new Room(r.id, r.name, {
                description: r.description,
                forceMembership: !!r.force_membership,
                private: !!r.is_private,
                direct: !!r.is_direct,
                keyVersion: r.key_version,
                needsRekey: !!r.needs_rekey
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
                keyVersion: m.keyVersion || null,
                time:       m.timestamp,
                room:       r.id
            }));

            rooms[r.id] = room;
        });
    };

    return {
        init,

        addMemberToRoom: (username, room) => {
            if (room.hasMember(username)) return;
            db.insert(roomMemberTable).values({
                roomId: room.id,
                userName: username
            }).onConflictDoNothing().run();
            room.addMember(username);
        },

        removeMemberFromRoom: (username, room) => {
            db.delete(roomMemberTable)
                .where(and(eq(roomMemberTable.roomId, room.id), eq(roomMemberTable.userName, username)))
                .run();
            room.removeMember(username);
        },

        addRoom: (name, options) => {
            const result = db.insert(roomsTable).values({
                name,
                description: options.description || "",
                force_membership: options.forceMembership ? 1 : 0,
                is_private: options.private ? 1 : 0,
                is_direct: 0
            }).run();

            const id = Number(result.lastInsertRowid);
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

            const id = Number(result.lastInsertRowid);
            const room = new Room(id, name, { direct: true, private: true });
            rooms[id] = room;
            return room;
        },

        getRooms: () => rooms,

        getForcedRooms: () => rooms.filter(r => r.forceMembership),

        getRoomsOfUser: name => rooms.filter(r => r.hasMember(name)),

        // ids come from the client: anything else than an integer is unknown
        getRoom: id => Number.isInteger(id) ? rooms[id] : undefined,

        getRoomByName: name => rooms.find(r => r && r.name === name),

        storeRoomKey: (roomId, userName, version, encryptedKey) => {
            db.insert(roomKeysTable)
                .values({ roomId, userName, version, encryptedKey })
                .onConflictDoUpdate({
                    target: [roomKeysTable.roomId, roomKeysTable.userName, roomKeysTable.version],
                    set: { encryptedKey }
                })
                .run();
        },

        // removes every key version of a member
        deleteRoomKeys: (roomId, userName) => {
            db.delete(roomKeysTable)
                .where(and(eq(roomKeysTable.roomId, roomId), eq(roomKeysTable.userName, userName)))
                .run();
        },

        getRoomKeysForUser: (userName) => {
            return db.select().from(roomKeysTable).where(eq(roomKeysTable.userName, userName)).all();
        },

        setKeyVersion: (room, version) => {
            db.update(roomsTable)
                .set({ key_version: version, needs_rekey: 0 })
                .where(eq(roomsTable.id, room.id))
                .run();
            room.keyVersion = version;
            room.needsRekey = false;
        },

        setNeedsRekey: (room) => {
            db.update(roomsTable).set({ needs_rekey: 1 }).where(eq(roomsTable.id, room.id)).run();
            room.needsRekey = true;
        },

        addMessageToRoom: (msgData, room, username, msgTime) => {
            db.insert(messagesTable).values({
                roomId:     room.id,
                userName:   username,
                content:    msgData.content    || null,
                iv:         msgData.iv         || null,
                authTag:    msgData.authTag    || null,
                ciphertext: msgData.ciphertext || null,
                keys:       msgData.keys ? JSON.stringify(msgData.keys) : null,
                keyVersion: msgData.keyVersion || null,
                timestamp:  msgTime
            }).run();
            room.addMessage({ username, ...msgData, time: msgTime, room: room.id });
        }
    };
};
