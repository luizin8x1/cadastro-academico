// src/controllers/rotinaController.js
const pool = require('../db/pool');
const { DIAS_VALIDOS, usuarioIdValido, validarCompromisso } = require('../utils/validacao');

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

function linhaParaFrontend(linha) {
    return {
        id: linha.id,
        inicio: linha.hora_inicio.slice(0, 5),   // "08:00:00" -> "08:00"
        fim: linha.hora_fim.slice(0, 5),
        descricao: linha.descricao,
        tipo: linha.tipo,
    };
}

// -----------------------------------------------------------------------
// GET /api/rotina/:usuarioId
// Consulta a rotina inteira (preferências + compromissos agrupados por dia)
// -----------------------------------------------------------------------
async function obterRotina(req, res) {
    const usuarioId = usuarioIdValido(req.params.usuarioId);
    if (!usuarioId) return res.status(400).json({ erro: 'usuarioId inválido.' });

    try {
        const preferenciasResult = await pool.query(
            'SELECT * FROM rotina_preferencias WHERE usuario_id = $1',
            [usuarioId]
        );

        if (preferenciasResult.rowCount === 0) {
            return res.status(404).json({ erro: 'Rotina ainda não cadastrada para este usuário.' });
        }

        const compromissosResult = await pool.query(
            `SELECT id, dia_semana, hora_inicio, hora_fim, descricao, tipo
             FROM rotina_compromissos
             WHERE usuario_id = $1
             ORDER BY dia_semana, hora_inicio`,
            [usuarioId]
        );

        const rotina = {};
        DIAS_VALIDOS.forEach((dia) => { rotina[dia] = []; });
        compromissosResult.rows.forEach((linha) => {
            rotina[linha.dia_semana].push(linhaParaFrontend(linha));
        });

        const prefs = preferenciasResult.rows[0];
        return res.json({
            horasPorDia: Number(prefs.horas_por_dia),
            diasSemana: prefs.dias_semana,
            periodoPreferido: prefs.periodo_preferido,
            duracaoFoco: prefs.duracao_foco,
            rotina,
        });
    } catch (err) {
        console.error('Erro ao obter rotina:', err);
        return res.status(500).json({ erro: 'Erro ao consultar a rotina.' });
    }
}

// -----------------------------------------------------------------------
// POST /api/rotina/:usuarioId
// Cria/substitui a rotina da semana inteira de uma vez (mantém compatibilidade
// com o formulário único de cronograma.html).
// -----------------------------------------------------------------------
async function salvarRotinaCompleta(req, res) {
    const usuarioId = usuarioIdValido(req.params.usuarioId);
    if (!usuarioId) return res.status(400).json({ erro: 'usuarioId inválido.' });

    const { horasPorDia, diasSemana, periodoPreferido, duracaoFoco, rotina } = req.body;

    if (horasPorDia === undefined || horasPorDia === null || isNaN(Number(horasPorDia))) {
        return res.status(400).json({ erro: 'Informe as horas disponíveis por dia.' });
    }
    if (!Array.isArray(diasSemana) || diasSemana.length === 0) {
        return res.status(400).json({ erro: 'Selecione pelo menos um dia da semana.' });
    }
    if (diasSemana.some((d) => !DIAS_VALIDOS.includes(d))) {
        return res.status(400).json({ erro: 'Foi enviado um dia da semana inválido.' });
    }

    // Valida todas as linhas de todos os dias antes de tocar no banco.
    const rotinaSegura = {};
    for (const dia of diasSemana) {
        const linhas = Array.isArray(rotina?.[dia]) ? rotina[dia] : [];
        for (const linha of linhas) {
            const erros = validarCompromisso({ diaSemana: dia, ...linha });
            if (erros.length) {
                return res.status(400).json({ erro: `${dia}: ${erros[0]}` });
            }
        }
        rotinaSegura[dia] = linhas;
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        await client.query(
            `INSERT INTO rotina_preferencias (usuario_id, horas_por_dia, dias_semana, periodo_preferido, duracao_foco)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (usuario_id) DO UPDATE SET
                horas_por_dia = EXCLUDED.horas_por_dia,
                dias_semana = EXCLUDED.dias_semana,
                periodo_preferido = EXCLUDED.periodo_preferido,
                duracao_foco = EXCLUDED.duracao_foco,
                atualizado_em = now()`,
            [usuarioId, horasPorDia, diasSemana, periodoPreferido || null, duracaoFoco || null]
        );

        // Substitui do zero os compromissos dos dias enviados (dias não
        // enviados na requisição não são tocados).
        await client.query(
            'DELETE FROM rotina_compromissos WHERE usuario_id = $1 AND dia_semana = ANY($2::varchar[])',
            [usuarioId, diasSemana]
        );

        for (const dia of diasSemana) {
            for (const linha of rotinaSegura[dia]) {
                await client.query(
                    `INSERT INTO rotina_compromissos (usuario_id, dia_semana, hora_inicio, hora_fim, descricao, tipo)
                     VALUES ($1, $2, $3, $4, $5, $6)`,
                    [usuarioId, dia, linha.inicio, linha.fim, linha.descricao.trim(), linha.tipo || null]
                );
            }
        }

        await client.query('COMMIT');
        return res.status(200).json({ mensagem: 'Rotina salva com sucesso.' });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Erro ao salvar rotina:', err);
        return res.status(500).json({ erro: 'Erro ao salvar a rotina.' });
    } finally {
        client.release();
    }
}

// -----------------------------------------------------------------------
// POST /api/rotina/:usuarioId/compromissos
// Cria UM compromisso novo em um dia específico.
// -----------------------------------------------------------------------
async function criarCompromisso(req, res) {
    const usuarioId = usuarioIdValido(req.params.usuarioId);
    if (!usuarioId) return res.status(400).json({ erro: 'usuarioId inválido.' });

    const { diaSemana, inicio, fim, descricao, tipo } = req.body;
    const erros = validarCompromisso({ diaSemana, inicio, fim, descricao, tipo });
    if (erros.length) return res.status(400).json({ erro: erros[0] });

    try {
        const resultado = await pool.query(
            `INSERT INTO rotina_compromissos (usuario_id, dia_semana, hora_inicio, hora_fim, descricao, tipo)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id, dia_semana, hora_inicio, hora_fim, descricao, tipo`,
            [usuarioId, diaSemana, inicio, fim, descricao.trim(), tipo || null]
        );

        return res.status(201).json(linhaParaFrontend(resultado.rows[0]));
    } catch (err) {
        console.error('Erro ao criar compromisso:', err);
        return res.status(500).json({ erro: 'Erro ao criar o compromisso.' });
    }
}

// -----------------------------------------------------------------------
// PUT /api/rotina/:usuarioId/compromissos/:compromissoId
// Edita um compromisso existente.
// -----------------------------------------------------------------------
async function editarCompromisso(req, res) {
    const usuarioId = usuarioIdValido(req.params.usuarioId);
    const compromissoId = usuarioIdValido(req.params.compromissoId);
    if (!usuarioId || !compromissoId) {
        return res.status(400).json({ erro: 'Identificador inválido.' });
    }

    const { diaSemana, inicio, fim, descricao, tipo } = req.body;
    const erros = validarCompromisso({ diaSemana, inicio, fim, descricao, tipo });
    if (erros.length) return res.status(400).json({ erro: erros[0] });

    try {
        const resultado = await pool.query(
            `UPDATE rotina_compromissos
             SET dia_semana = $1, hora_inicio = $2, hora_fim = $3, descricao = $4, tipo = $5, atualizado_em = now()
             WHERE id = $6 AND usuario_id = $7
             RETURNING id, dia_semana, hora_inicio, hora_fim, descricao, tipo`,
            [diaSemana, inicio, fim, descricao.trim(), tipo || null, compromissoId, usuarioId]
        );

        if (resultado.rowCount === 0) {
            return res.status(404).json({ erro: 'Compromisso não encontrado.' });
        }

        return res.json(linhaParaFrontend(resultado.rows[0]));
    } catch (err) {
        console.error('Erro ao editar compromisso:', err);
        return res.status(500).json({ erro: 'Erro ao editar o compromisso.' });
    }
}

// -----------------------------------------------------------------------
// DELETE /api/rotina/:usuarioId/compromissos/:compromissoId
// -----------------------------------------------------------------------
async function excluirCompromisso(req, res) {
    const usuarioId = usuarioIdValido(req.params.usuarioId);
    const compromissoId = usuarioIdValido(req.params.compromissoId);
    if (!usuarioId || !compromissoId) {
        return res.status(400).json({ erro: 'Identificador inválido.' });
    }

    try {
        const resultado = await pool.query(
            'DELETE FROM rotina_compromissos WHERE id = $1 AND usuario_id = $2',
            [compromissoId, usuarioId]
        );

        if (resultado.rowCount === 0) {
            return res.status(404).json({ erro: 'Compromisso não encontrado.' });
        }

        return res.status(204).send();
    } catch (err) {
        console.error('Erro ao excluir compromisso:', err);
        return res.status(500).json({ erro: 'Erro ao excluir o compromisso.' });
    }
}

module.exports = {
    obterRotina,
    salvarRotinaCompleta,
    criarCompromisso,
    editarCompromisso,
    excluirCompromisso,
};
