var config = require("../config");
var dummy = require("../dummy");
var pgp = require('pg-promise')();
const bcrypt = require('bcrypt');

async function init_db() {
    var db = pgp(config.db.connectionString);
    console.log("--- Starting Security Hotfix ---");

    try {
        // 1. Manually ensure the password column can hold long hashes
        // This is faster than dropping the whole table
        await db.none('ALTER TABLE users ALTER COLUMN password TYPE VARCHAR(255);');
        console.log("Column widened.");

        // 2. Directly Update the passwords to hashes
        const adminHash = await bcrypt.hash('admin', 10);
        const robertoHash = await bcrypt.hash('asdfpiuw981', 10);

        await db.none("UPDATE users SET password = $1 WHERE name = 'admin'", [adminHash]);
        await db.none("UPDATE users SET password = $1 WHERE name = 'roberto'", [robertoHash]);

        console.log("--- PASSWORDS SUCCESSFULLY HASHED ---");
    } catch (err) {
        console.log("Update failed (table might not exist yet), trying creation...");
        // Fallback: If the table doesn't exist at all, create it
        try {
            await db.none('CREATE TABLE IF NOT EXISTS users(name VARCHAR(100) PRIMARY KEY, password VARCHAR(255));');
            const hash = await bcrypt.hash('admin', 10);
            await db.none("INSERT INTO users(name, password) VALUES('admin', $1) ON CONFLICT DO NOTHING", [hash]);
            console.log("Emergency Table Created.");
        } catch (innerErr) {
            console.error("Critical DB Error:", innerErr);
        }
    }
}

module.exports = init_db;