const { usersTable, roomMemberTable } = require('./db/schema.js');
const { eq } = require('drizzle-orm');
const bcrypt = require('bcrypt')

let users = Object.create(null);
let initialized  = false

// Brute-force protection: lock a username for a while after too many failed logins
const MAX_FAILED_LOGINS = 5;
const LOCK_MS           = 60 * 1000;
const failedLogins      = new Map();
const DUMMY_HASH        = bcrypt.hashSync('dummy password', 10);

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

module.exports = (db) => {
    // the rooms a user is in are stored in room_member, so they survive a restart
    const restoreUser = (name, publicKey) => {
        const user = new User(name, publicKey || null);
        user.subscriptions = db.select().from(roomMemberTable)
            .where(eq(roomMemberTable.userName, name)).all()
            .map(m => m.roomId);
        users[name] = user;
        return user;
    };

    return {
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
            return restoreUser(name, dbUser?.public_key);
        },

        getUser: name => {
            return typeof name === 'string' && Object.hasOwn(users, name) ? users[name] : undefined;
        },

        // returns the db user, null for wrong credentials, or 'locked'
        login: (name, password) => {
            const attempts = failedLogins.get(name);
            if (attempts && attempts.count >= MAX_FAILED_LOGINS && Date.now() - attempts.last < LOCK_MS)
                return 'locked';

            const user = db.select().from(usersTable).where(eq(usersTable.name, name)).get();
            // compare against a dummy hash for unknown users, so both cases take the same time
            const hash  = user ? user.password : DUMMY_HASH;
            const match = bcrypt.compareSync(password, hash)

            if (!user || !match) {
                const count = attempts && Date.now() - attempts.last < LOCK_MS ? attempts.count : 0;
                failedLogins.set(name, { count: count + 1, last: Date.now() });
                return null
            }

            failedLogins.delete(name);
            return user
        },

        getUsers: () => {
            if (!initialized) {
                const dbUsers = db.select().from(usersTable).all();
                initialized = true;
                dbUsers.forEach(u => {
                    if (!users[u.name])
                        restoreUser(u.name, u.public_key);
                });
            }
            return Object.values(users);
        }
    };
}
