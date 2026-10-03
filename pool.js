// src/db/pool.js
// Pool de conexão único, reaproveitado por toda a aplicação.
// Configure as variáveis de ambiente no seu .env (ou no serviço de deploy).

const { Pool } = require('pg');

const pool = new Pool({
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT) || 5432,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
   ssl: (process.env.DB_HOST && process.env.DB_HOST !== 'localhost')
    ? { rejectUnauthorized: false }
    : false
});

pool.on('error', (err) => {
    console.error('Erro inesperado no pool do PostgreSQL:', err);
});

module.exports = pool;
