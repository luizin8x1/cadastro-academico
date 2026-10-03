require("dotenv").config();

const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

const pool = new Pool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    ssl: { rejectUnauthorized: false },
});


async function converterCodigos() {

    const client = await pool.connect();

    try {

        console.log("🔐 Iniciando conversão dos códigos...");

        await client.query("BEGIN");


        // Busca os integrantes cadastrados
        const resultado = await client.query(`
            SELECT
                id,
                nome,
                codigo_hash
            FROM equipe_sistema
            WHERE ativo = TRUE
            ORDER BY id
        `);


        for (const integrante of resultado.rows) {

            const codigoAtual = String(integrante.codigo_hash).trim();


            // Se já estiver convertido, não converte novamente
            if (
                codigoAtual.startsWith("$2a$") ||
                codigoAtual.startsWith("$2b$")
            ) {

                console.log(
                    `⏭️ ${integrante.nome}: código já está protegido.`
                );

                continue;
            }


            // Segurança: somente códigos de exatamente 6 números
            if (!/^\d{6}$/.test(codigoAtual)) {

                throw new Error(
                    `Código inválido encontrado para ${integrante.nome}.`
                );

            }


            // Gera o hash mantendo o código original como senha
            const hash = await bcrypt.hash(codigoAtual, 10);


            await client.query(
                `
                UPDATE equipe_sistema
                SET codigo_hash = $1
                WHERE id = $2
                `,
                [
                    hash,
                    integrante.id
                ]
            );


            console.log(
                `✅ ${integrante.nome}: código protegido.`
            );

        }


        await client.query("COMMIT");

        console.log("");
        console.log("🎉 Todos os códigos foram convertidos com sucesso.");


    } catch (erro) {

        await client.query("ROLLBACK");

        console.error("");
        console.error(
            "❌ Erro ao converter códigos:",
            erro
        );


    } finally {

        client.release();

        await pool.end();

    }

}


converterCodigos();