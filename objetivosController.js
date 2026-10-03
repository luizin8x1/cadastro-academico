// src/controllers/objetivosController.js
const pool = require('../db/pool');
const { usuarioIdValido, validarObjetivos } = require('../utils/validacao');

function linhaParaFrontend(linha) {
    return {
        objetivos: linha.objetivos,
        disciplinasDificuldade: linha.disciplinas_dificuldade,
        disciplinaDificuldadeOutra: linha.disciplina_dificuldade_outra,
        prioridades: linha.prioridades,
        temProvaMarcada: linha.tem_prova_marcada,
        dataProva: linha.data_prova,
        detalhesProva: linha.detalhes_prova,
        tipoVestibular: linha.tipo_vestibular,
        vestibularOutro: linha.vestibular_outro,
        observacoes: linha.observacoes,
    };
}

// -----------------------------------------------------------------------
// GET /api/objetivos/:usuarioId
// -----------------------------------------------------------------------
async function obterObjetivos(req, res) {
    const usuarioId = usuarioIdValido(req.params.usuarioId);
    if (!usuarioId) return res.status(400).json({ erro: 'usuarioId inválido.' });

    try {
        const resultado = await pool.query(
            'SELECT * FROM objetivos_estudo WHERE usuario_id = $1',
            [usuarioId]
        );

        if (resultado.rowCount === 0) {
            return res.status(404).json({ erro: 'Objetivos de estudo ainda não cadastrados para este usuário.' });
        }

        return res.json(linhaParaFrontend(resultado.rows[0]));
    } catch (err) {
        console.error('Erro ao obter objetivos de estudo:', err);
        return res.status(500).json({ erro: 'Erro ao consultar os objetivos de estudo.' });
    }
}

// -----------------------------------------------------------------------
// POST /api/objetivos/:usuarioId
// Cria (ou substitui, se já existir) o registro de objetivos do aluno.
// -----------------------------------------------------------------------
async function salvarObjetivos(req, res) {
    const usuarioId = usuarioIdValido(req.params.usuarioId);
    if (!usuarioId) return res.status(400).json({ erro: 'usuarioId inválido.' });

    const erros = validarObjetivos(req.body);
    if (erros.length) return res.status(400).json({ erro: erros[0] });

    const {
        objetivos = [],
        disciplinasDificuldade = [],
        disciplinaDificuldadeOutra = null,
        prioridades = [],
        temProvaMarcada = false,
        dataProva = null,
        detalhesProva = null,
        tipoVestibular = null,
        vestibularOutro = null,
        observacoes = null,
    } = req.body;

    try {
        const resultado = await pool.query(
            `INSERT INTO objetivos_estudo (
                usuario_id, objetivos, disciplinas_dificuldade, disciplina_dificuldade_outra,
                prioridades, tem_prova_marcada, data_prova, detalhes_prova,
                tipo_vestibular, vestibular_outro, observacoes
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
             ON CONFLICT (usuario_id) DO UPDATE SET
                objetivos = EXCLUDED.objetivos,
                disciplinas_dificuldade = EXCLUDED.disciplinas_dificuldade,
                disciplina_dificuldade_outra = EXCLUDED.disciplina_dificuldade_outra,
                prioridades = EXCLUDED.prioridades,
                tem_prova_marcada = EXCLUDED.tem_prova_marcada,
                data_prova = EXCLUDED.data_prova,
                detalhes_prova = EXCLUDED.detalhes_prova,
                tipo_vestibular = EXCLUDED.tipo_vestibular,
                vestibular_outro = EXCLUDED.vestibular_outro,
                observacoes = EXCLUDED.observacoes,
                atualizado_em = now()
             RETURNING *`,
            [
                usuarioId, objetivos, disciplinasDificuldade, disciplinaDificuldadeOutra,
                prioridades, temProvaMarcada, dataProva, detalhesProva,
                tipoVestibular, vestibularOutro, observacoes,
            ]
        );

        return res.status(200).json(linhaParaFrontend(resultado.rows[0]));
    } catch (err) {
        console.error('Erro ao salvar objetivos de estudo:', err);
        return res.status(500).json({ erro: 'Erro ao salvar os objetivos de estudo.' });
    }
}

// -----------------------------------------------------------------------
// DELETE /api/objetivos/:usuarioId
// -----------------------------------------------------------------------
async function excluirObjetivos(req, res) {
    const usuarioId = usuarioIdValido(req.params.usuarioId);
    if (!usuarioId) return res.status(400).json({ erro: 'usuarioId inválido.' });

    try {
        const resultado = await pool.query(
            'DELETE FROM objetivos_estudo WHERE usuario_id = $1',
            [usuarioId]
        );

        if (resultado.rowCount === 0) {
            return res.status(404).json({ erro: 'Objetivos de estudo não encontrados.' });
        }

        return res.status(204).send();
    } catch (err) {
        console.error('Erro ao excluir objetivos de estudo:', err);
        return res.status(500).json({ erro: 'Erro ao excluir os objetivos de estudo.' });
    }
}

module.exports = {
    obterObjetivos,
    salvarObjetivos,
    excluirObjetivos,
};
