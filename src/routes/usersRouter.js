
const express = require('express');
const bcrypt = require('bcrypt');
const client = require('../client');
const usersRouter = express.Router();
const jwt = require('jsonwebtoken');
const UsersController = require('../controllers/usersController');
require('dotenv').config()
const accessTokenSecret= process.env.ACCESTOKENSECRET
const usersController = new UsersController();


usersRouter.post('/register', (req, res) => usersController.register(req, res))
usersRouter.post('/login', (req, res) => usersController.login(req, res))




module.exports = usersRouter;