require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: { rejectUnauthorized: false }
});

async function verificarHoras() {
    try {

        const resultado = await pool.query(`
            SELECT
                COUNT(*) AS total_itens,
                COALESCE(SUM(duracao_min), 0) AS total_minutos,
                ROUND(
                    COALESCE(SUM(duracao_min), 0)::numeric / 60,
                    1
                ) AS total_horas
            FROM plano_estudo_item;
        `);

        console.table(resultado.rows);

    } catch (erro) {

        console.error("Erro ao consultar horas planejadas:");
        console.error(erro);

    } finally {

        await pool.end();

    }
}

verificarHoras();