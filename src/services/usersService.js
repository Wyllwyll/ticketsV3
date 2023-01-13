const client = require('../client');

class UsersService {
    async getUserByName(name) {
        const data = await client.query('SELECT * FROM users WHERE user_name=$1', [name]);
        if (data.rowCount) {
            return data.rows[0];
        }
        return undefined
    }

    async addUser(name, hash) {
        const data = await client.query('INSERT INTO users (user_name,password) VALUES ($1,$2) RETURNING *', [name, hash]);
        if (data.rowCount) {
            return data.rows[0];
        }
        return undefined
    }
}

module.exports = UsersService