require('dotenv').config();

const pool = require('./pool');

async function criarTabelaContato() {
    try {

        await pool.query(`
            CREATE TABLE IF NOT EXISTS mensagens_contato (

                id SERIAL PRIMARY KEY,

                nome VARCHAR(150) NOT NULL,

                email VARCHAR(255) NOT NULL,

                telefone VARCHAR(20),

                assunto VARCHAR(50) NOT NULL,

                mensagem TEXT NOT NULL,

                status VARCHAR(20) NOT NULL DEFAULT 'nova',

                criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                respondido_em TIMESTAMP NULL

            );
        `);

        console.log("✅ Tabela mensagens_contato criada com sucesso!");

    } catch (erro) {

        console.error("❌ Erro ao criar tabela:", erro);

    } finally {

        await pool.end();

    }
}

criarTabelaContato();