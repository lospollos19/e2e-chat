const { usersTable } = require('./db/schema.js');
const { eq } = require('drizzle-orm');

let users = {};
const bcrypt = require('bcrypt')
const jwt_token = require('jsonwebtoken')
let initialized  = false

class User {
    constructor(_name, _publicKey = null) {
        this.name      = _name;
        this.publicKey = _publicKey;
        this.active    = false;
        this.subscriptions = [];
    }

    getSubscriptions() {
        return this.subscriptions;
    }

    addSubscription(room) {
        const id = room.getId();

        if (this.subscriptions.indexOf(id) === -1)
            this.subscriptions.push(id);
    }

    removeSubscription(room) {
        const id = room.getId();

        const idx = this.subscriptions.indexOf(id);
        if (idx >= 0)
            this.subscriptions.splice(idx, 1);
    }

    setActiveState(b) {
        this.active = b;
    }

}

module.exports = (db) => ({
    addUser: (name, password, publicKey, encryptedPrivateKey) => {
        const hash = bcrypt.hashSync(password, 10);
        const encPrivKeyStr = encryptedPrivateKey ? JSON.stringify(encryptedPrivateKey) : null;
        db.insert(usersTable).values({
            name,
            password:              hash,
            public_key:            publicKey            || null,
            encrypted_private_key: encPrivKeyStr
        }).run();
        const user = new User(name, publicKey || null);
        users[name] = user;
        return user;
    },

    loadUser: (name) => {
        const dbUser = db.select().from(usersTable).where(eq(usersTable.name, name)).get();
        const user   = new User(name, dbUser?.public_key || null);
        users[name]  = user;
        return user;
    },

    getUser: name => {
        return users[name];
    },

    login: (name, password) => {
        const user = db.select().from(usersTable).where(eq(usersTable.name, name)).get();
        if (!user) return null

        const match = bcrypt.compareSync(password, user.password)
        if (!match) return null

        return user
    },

    getUsers: () => {
        if (!initialized) {
            const dbUsers = db.select().from(usersTable).all();
            initialized = true;
            dbUsers.forEach(u => {
                if (!users[u.name]) {
                    users[u.name] = new User(u.name, u.public_key || null);
                }
            });
        }
        return Object.values(users);
    }
})