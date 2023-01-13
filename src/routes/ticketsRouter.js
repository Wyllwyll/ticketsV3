
const express = require('express');
const client = require('../client');
const TicketsController = require('../controllers/ticketsController');
const ticketsRouter = express.Router();
const authenticateJWT = require('../middlewares/auth.js')
const ticketsController= new TicketsController()






ticketsRouter.get('/', authenticateJWT, (req, res) => ticketsController.getAllTickets(req, res));


ticketsRouter.get('/:id', authenticateJWT, async (req, res) => ticketsController.getTicketsById(req,res))


ticketsRouter.post('/', authenticateJWT, async (req, res) => ticketsController.postTicket(req,res))


ticketsRouter.delete('/:id', authenticateJWT, async (req, res) => ticketsController.delTickets(req,res))


ticketsRouter.put('/:id', authenticateJWT, async (req, res) => ticketsController.uptTickets(req,res))





module.exports = ticketsRouter;