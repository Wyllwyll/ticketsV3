const client = require('../client');

class TicketsService {
    async getAllTickets() {
        const data = await client.query('SELECT * FROM tickets');
        if (data.rowCount) {
            return data.rows;
        }
        return undefined
    }


    async getTicketsById(ticketId) {
        const data = await client.query('SELECT * FROM tickets WHERE id=$1', [ticketId]);
        if (data.rowCount) {
            return data.rows[0];
        }
        return undefined
    }

    async postTickets(mess, user_id) {
        const data = await client.query('INSERT INTO tickets (message,user_id) VALUES ($1,$2) returning *', [mess, user_id]);
        console.log(data.rows);
        if (data.rowCount) {
            return data.rows[0];
        }

        return undefined
    }

    async selectTickets(ticketId) {
        const data = await client.query('SELECT id,user_id FROM tickets WHERE id=$1', [ticketId]);
        if (data.rowCount > 0) {
            return data.rows[0];
        }

        return undefined
    }

    async delTickets(ticketId) {
        const data = await client.query('DELETE from tickets WHERE id= $1 RETURNING *', [ticketId])
        if (data.rowCount > 0) {
            return data.rows[0];
        }

        return undefined
    }

    async uptTickets(updateMess, ticketId, updateDone) {
        const data = await client.query('UPDATE tickets SET  done = $3, message = $1 WHERE id = $2 RETURNING *', [updateMess, ticketId, updateDone])
        if (data.rowCount > 0) {
            return data.rows[0];
        }
        return undefined
    }
}

module.exports = TicketsService






