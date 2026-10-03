require("dotenv").config();
const { Pool } = require("pg");

const pool = new Pool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: {
        rejectUnauthorized: false
    }
});

async function consultar() {
    try {
        const resultado = await pool.query(
            "SELECT id, nome, email, data_cadastro, status FROM usuario WHERE email = $1",
            ["teste.cancelamento@gmail.com"]
        );

        console.log("\nUSUÁRIO ENCONTRADO:\n");
        console.table(resultado.rows);

        console.log(`Quantidade encontrada: ${resultado.rowCount}`);

    } catch (erro) {
        console.error("Erro ao consultar:", erro);
    } finally {
        await pool.end();
    }
}

consultar();