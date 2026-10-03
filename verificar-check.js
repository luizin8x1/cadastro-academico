require("dotenv").config();
const { Pool } = require("pg");

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: false }
});

async function verificar() {
  try {
    const resultado = await pool.query(`
      SELECT
        conname AS restricao,
        pg_get_constraintdef(oid) AS regra
      FROM pg_constraint
      WHERE conrelid = 'perfil_academico'::regclass
      ORDER BY conname;
    `);

    console.table(resultado.rows);
  } catch (erro) {
    console.error(erro);
  } finally {
    await pool.end();
  }
}

verificar();