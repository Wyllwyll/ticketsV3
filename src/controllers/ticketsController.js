const bcrypt = require('bcrypt');
const client = require('../client');
const jwt = require('jsonwebtoken');
const TicketsService = require('../services/ticketsService');
const accessTokenSecret = process.env.ACCESTOKENSECRET;
const ticketsService = new TicketsService()



class TicketsController {

    async getAllTickets(req, res) {
        try {
            const data = await ticketsService.getAllTickets();
            res.status(200).json(
                {
                    status: "success",
                    message: "liste des Tickets :",
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

            console.log(err.stack)
        }
    }

    async getTicketsById(req, res) {
        const ticketId = req.params.id
        if (!Number.isNaN(Number(ticketId))) {
            try {
                const data = await ticketsService.getTicketsById(ticketId)
                if (data) {
                    res.status(200).json(
                        {
                            status: "success",
                            data: data
                        }
                    )
                }
                else {
                    res.status(404).json(
                        {
                            status: "fail",
                            message: "id ne correspond à aucun ticket"
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
                console.log(err.stack)
            }
        }
        else {
            res.status(404).json(
                {
                    status: "fail",
                    message: "numéro d'ID nécessaire"
                }
            )
        }
    }

    async postTicket(req, res) {
        const mess = req.body.message
        const user_id = req.userId

        if (mess && user_id != null) {
            try {
                const data = await ticketsService.postTickets(mess, user_id)
                res.status(201).json(
                    {
                        status: "success",
                        message: "message posté avec succés",
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
        }
        else {
            res.status(400).json(
                {
                    status: "fail",
                    message: "message ou id utilisateur obligatoire"
                }
            )
        }
    }

    async delTickets(req, res) {
        const ticketId = req.params.id
        const test = req.userId
        if (!Number.isNaN(Number(ticketId))) {
            try {
                const ticketData = await ticketsService.selectTickets(ticketId)
                if (!ticketData) {
                    res.status(404).json(
                        {
                            status: "fail",
                            message: "id ne correspond à aucun ticket"
                        }
                    )
                }
                else if
                    (test !== ticketData['user_id']) {
                    res.status(404).json(
                        {
                            status: "FAIL",
                            message: "suppression non autorisée"
                        }
                    )

                }
                else {
                    const data = await ticketsService.delTickets(ticketId)
                    if (data) {
                        res.status(200).json(
                            {
                                status: "success",
                                message: "ticket supprimé"
                            }
                        )
                    }
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
        else {
            res.status(404).json(
                {
                    status: "fail",
                    message: "numéro d'ID nécessaire"
                }
            )
        }


    }

    async uptTickets(req, res) {

        const ticketId = req.params.id
        const updateMess = req.body.message
        const updateDone = req.body.done
        const test = req.userId
        if (!Number.isNaN(Number(ticketId))) {
            if (updateMess && updateDone !== undefined) {
                if (updateDone === true || updateDone === false) {
                    try {
                        const ticketData = await ticketsService.selectTickets(ticketId)
                        if (!ticketData) {
                            res.status(404).json(
                                {
                                    status: "FAIL",
                                    message: "Nécessite un nombre valable en tant qu'Id"
                                });
                        }
                        else if (test !== ticketData['user_id']) {
                            res.status(404).json(
                                {
                                    status: "FAIL",
                                    message: "update non autorisée"
                                }
                            )
                        }
                        else {
                            const data = await ticketsService.uptTickets(updateMess, ticketId, updateDone)


                            if (data) {
                                res.status(201).json({
                                    status: "success",
                                    message: "données modifiées",
                                    data: data
                                })
                            }

                        }
                    }
                    catch (err) {
                        res.status(500).json(
                            {
                                status: "FAIL",
                                message: "erreur serveur"
                            })
                    }
                } else {
                    res.status(400).json(
                        {
                            status: "FAIL",
                            message: "Booléen attendu"
                        }
                    )
                }
            } else {
                res.status(400).json(
                    {
                        status: "FAIL",
                        message: "valeur manquante"
                    }
                )
            };
        }
    }
}


module.exports = TicketsController