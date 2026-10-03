require("dotenv").config();

const { Pool } = require("pg");

// =====================================================
// CONEXÃO COM O BANCO
// =====================================================

const pool = new Pool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 5432,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: {
        rejectUnauthorized: false
    }
});


// =====================================================
// CRIAR TABELA PERFIL_DIFICULDADE
// =====================================================

async function criarTabela() {

    try {

        console.log("🔄 Conectando ao banco...");

        // Testa a conexão
        await pool.query("SELECT NOW()");

        console.log("✅ Conexão realizada.");

        await pool.query(`
            CREATE TABLE IF NOT EXISTS perfil_dificuldade (

                id SERIAL PRIMARY KEY,

                usuario_id INTEGER NOT NULL
                    REFERENCES usuario(id)
                    ON DELETE CASCADE,

                disciplina_id INTEGER NOT NULL
                    REFERENCES disciplina(id),

                conteudo_1 VARCHAR(150),
                conteudo_2 VARCHAR(150),
                conteudo_3 VARCHAR(150),

                atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                UNIQUE (usuario_id, disciplina_id)
            );
        `);

        console.log("✅ Tabela perfil_dificuldade criada com sucesso!");

    } catch (erro) {

        console.error("❌ Erro ao criar tabela:");
        console.error(erro);

    } finally {

        await pool.end();
        console.log("🔌 Conexão encerrada.");

    }
}


// =====================================================
// EXECUTAR
// =====================================================

criarTabela();