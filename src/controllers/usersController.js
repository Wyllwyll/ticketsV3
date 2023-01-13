const bcrypt = require('bcrypt');
const client = require('../client');
const jwt = require('jsonwebtoken');
const UsersService = require('../services/usersService');

const accessTokenSecret = process.env.ACCESTOKENSECRET;

const usersService = new UsersService();

class UsersController {
    async login(req, res) {
        const name = req.body.user_name;
        const pass = req.body.password
        try {
            const user = await usersService.getUserByName(name);  // client.query('SELECT * FROM users WHERE name=$1', [name]);
            if (user) {
                bcrypt.compare(pass, user.password, async function (err, result) {
                    if (result == true) {
                        const accessToken = jwt.sign({ userId: user.id }, accessTokenSecret);
                        res.status(200).json({
                            status: 'OK',
                            data: accessToken,
                            message: 'logged in'
                        });
                    }
                    else {
                        res.status(403).json(
                            {
                                status: "fail",
                                message: "mot de passe incorrect",
                                data: null
                            }
                        )
                    }
                }
                )
            }
            else {
                res.status(404).json(
                    {
                        status: "fail",
                        message: "identifiant incorrect",
                        data: null
                    }
                )
            }
        }
        catch (err) {
            res.status(500).json(
                {
                    status: "fail",
                    message: "erreur serveur"
                }
            )
            console.log(err.stack);
        }
    }

    register(req, res) {
        const name = req.body.user_name;
        const pass = req.body.password
        bcrypt.hash(pass, 10, async function (err, hash) {
            try {
                const data = await usersService.addUser(name, hash);
                res.status(201).json(
                    {
                        status: "success",
                        message: "register success",
                        data: data
                    }
                )
            }
            catch (err) {
                res.status(500).json(
                    {
                        status: "fail",
                        message: "erreur serveur"
                    }
                )
                console.log(err.stack);
            }
        });
    }
}

module.exports = UsersController