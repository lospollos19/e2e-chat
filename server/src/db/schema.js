const { int, sqliteTable, text, integer, primaryKey } = require("drizzle-orm/sqlite-core");

const usersTable = sqliteTable("users", {
    id: int().primaryKey({ autoIncrement: true }),
    name: text().notNull().unique(),
    password: text().notNull(),
    public_key: text(),
    encrypted_private_key: text()
});

const roomsTable = sqliteTable("rooms",{
    id: int().primaryKey({ autoIncrement: true }),
    name: text().notNull().unique(),
    description: text().notNull().default(""),
    force_membership: integer('force_membership', { mode: "boolean" }).notNull().default(0),
    is_private: integer('is_private', { mode: "boolean" }).notNull().default(0),
    is_direct: integer('is_direct', { mode: "boolean" }).notNull().default(0)
})

const roomMemberTable = sqliteTable("room_member", {
    roomId:   integer('room_id').notNull().references(() => roomsTable.id),
    userName: text('user_name').notNull().references(() => usersTable.name),
});

const messagesTable = sqliteTable("messages", {
    id:         int().primaryKey({ autoIncrement: true }),
    roomId:     integer('room_id').notNull().references(() => roomsTable.id),
    userName:   text('user_name').notNull().references(() => usersTable.name),
    content:    text(),
    iv:         text(),
    authTag:    text('auth_tag'),
    ciphertext: text(),
    keys:       text(),
    timestamp:  integer('timestamp').notNull().$defaultFn(() => Date.now())
})

const roomKeysTable = sqliteTable("room_keys", {
    roomId:       integer('room_id').notNull().references(() => roomsTable.id),
    userName:     text('user_name').notNull().references(() => usersTable.name),
    encryptedKey: text('encrypted_key').notNull(),
}, (t) => ({ pk: primaryKey({ columns: [t.roomId, t.userName] }) }));

module.exports = { usersTable, roomsTable, roomMemberTable, messagesTable, roomKeysTable };
