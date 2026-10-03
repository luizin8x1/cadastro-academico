// src/routes/rotinaRoutes.js
const express = require('express');
const router = express.Router();
const rotinaController = require('../controllers/rotinaController');

// Rotina da semana inteira
router.get('/:usuarioId', rotinaController.obterRotina);
router.post('/:usuarioId', rotinaController.salvarRotinaCompleta);

// CRUD granular de um compromisso individual
router.post('/:usuarioId/compromissos', rotinaController.criarCompromisso);
router.put('/:usuarioId/compromissos/:compromissoId', rotinaController.editarCompromisso);
router.delete('/:usuarioId/compromissos/:compromissoId', rotinaController.excluirCompromisso);

module.exports = router;
