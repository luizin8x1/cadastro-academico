require("dotenv").config();

const pool = require("./pool");

async function verificarEstrutura() {
  try {

    const resultado = await pool.query(`
      SELECT
        table_name,
        column_name,
        data_type,
        is_nullable,
        column_default
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name IN ('rotina', 'rotina_item')
      ORDER BY
        table_name,
        ordinal_position;
    `);

    console.table(resultado.rows);

  } catch (erro) {
    console.error("❌ Erro ao consultar estrutura:", erro);
  } finally {
    await pool.end();
  }
}

verificarEstrutura();