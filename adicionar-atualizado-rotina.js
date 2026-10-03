require('dotenv').config();

const pool = require('./pool');

async function alterarTabelaRotina() {
    try {
        await pool.query(`
            ALTER TABLE rotina
            ADD COLUMN IF NOT EXISTS atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
        `);

        console.log('✅ Coluna atualizado_em adicionada à tabela rotina!');

    } catch (erro) {
        console.error('❌ Erro ao alterar tabela rotina:', erro);
    } finally {
        await pool.end();
    }
}

alterarTabelaRotina();