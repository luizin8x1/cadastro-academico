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

async function listarUsuarios() {
  try {
    const resultado = await pool.query(`
      SELECT id, nome, email, data_cadastro, status
      FROM usuario
      ORDER BY id
    `);

    console.table(resultado.rows);
  } catch (erro) {
    console.error("Erro:", erro);
  } finally {
    await pool.end();
  }
}

listarUsuarios();