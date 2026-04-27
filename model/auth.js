var config = require("../config"),
    pgp = require('pg-promise')(),
    bcrypt = require('bcrypt'); // 1. Import bcrypt

async function do_auth(username, password) {
    var db = pgp(config.db.connectionString);

    // 2. USE PARAMETERS ($1) instead of string concatenation (+)
    // This stops SQL Injection dead in its tracks.
    var query = "SELECT * FROM users WHERE name = $1;";

    try {
        // Fetch the user by name only
        const user = await db.one(query, [username]);

        // 3. COMPARE HASHED PASSWORDS
        // bcrypt.compare checks if the plain text 'password' 
        // matches the 'user.password' hash in the database.
        const match = await bcrypt.compare(password, user.password);

        if (match) {
            return user; // Success
        } else {
            throw new Error("Invalid password");
        }
    } catch (err) {
        // If user not found or password doesn't match
        throw new Error("Authentication failed");
    }
}

module.exports = do_auth;