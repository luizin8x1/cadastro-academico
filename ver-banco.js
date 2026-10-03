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

async function analisarBanco() {
  try {
    const tabelas = await pool.query(`
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = 'public'
        AND table_type = 'BASE TABLE'
      ORDER BY table_name
    `);

    console.log("\n======================================");
    console.log(" MAPA COMPLETO DO BANCO ROTA DO SUCESSO");
    console.log("======================================\n");

    for (const tabela of tabelas.rows) {
      const nomeTabela = tabela.table_name;

      console.log("\n--------------------------------------");
      console.log(`TABELA: ${nomeTabela}`);
      console.log("--------------------------------------");

      const colunas = await pool.query(`
        SELECT
          ordinal_position,
          column_name,
          data_type,
          is_nullable,
          column_default
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = $1
        ORDER BY ordinal_position
      `, [nomeTabela]);

      console.table(colunas.rows);

      const restricoes = await pool.query(`
        SELECT
          tc.constraint_type,
          kcu.column_name,
          ccu.table_name AS tabela_referenciada,
          ccu.column_name AS coluna_referenciada
        FROM information_schema.table_constraints tc
        LEFT JOIN information_schema.key_column_usage kcu
          ON tc.constraint_name = kcu.constraint_name
          AND tc.table_schema = kcu.table_schema
        LEFT JOIN information_schema.constraint_column_usage ccu
          ON tc.constraint_name = ccu.constraint_name
          AND tc.table_schema = ccu.table_schema
        WHERE tc.table_schema = 'public'
          AND tc.table_name = $1
        ORDER BY tc.constraint_type, kcu.column_name
      `, [nomeTabela]);

      if (restricoes.rows.length > 0) {
        console.log("CHAVES / RESTRIÇÕES:");
        console.table(restricoes.rows);
      }
    }

    console.log("\n======================================");
    console.log(" FIM DA ANÁLISE");
    console.log("======================================\n");

  } catch (erro) {
    console.error("ERRO AO ANALISAR O BANCO:");
    console.error(erro.message);
  } finally {
    await pool.end();
  }
}

analisarBanco();