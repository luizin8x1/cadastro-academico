// src/routes/objetivosRoutes.js
const express = require('express');
const router = express.Router();
const objetivosController = require('../controllers/objetivosController');

router.get('/:usuarioId', objetivosController.obterObjetivos);
router.post('/:usuarioId', objetivosController.salvarObjetivos);   // cria
router.put('/:usuarioId', objetivosController.salvarObjetivos);    // edita (mesmo upsert)
router.delete('/:usuarioId', objetivosController.excluirObjetivos);

module.exports = router;
