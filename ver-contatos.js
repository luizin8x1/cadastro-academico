require('dotenv').config();

const pool = require('./pool');

async function verContatos() {

    try {

        const resultado = await pool.query(`
            SELECT
                id,
                nome,
                email,
                telefone,
                assunto,
                mensagem,
                status,
                criado_em,
                respondido_em
            FROM mensagens_contato
            ORDER BY criado_em DESC;
        `);

        console.table(resultado.rows);

    } catch (erro) {

        console.error("Erro ao consultar mensagens:", erro);

    } finally {

        await pool.end();

    }

}

verContatos();