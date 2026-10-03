

require("dotenv").config();

const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const path = require("path");
const Anthropic = require("@anthropic-ai/sdk");
const PDFDocument = require("pdfkit");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json({
    limit: "2mb"
}));

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
app.use(express.static(path.join(__dirname, "public")));

const pool = new Pool({
  ...(process.env.DATABASE_URL
    ? { connectionString: process.env.DATABASE_URL }
    : {
        host: process.env.DB_HOST,
        port: process.env.DB_PORT || 5432,
        database: process.env.DB_NAME,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
      }),
  ssl: { rejectUnauthorized: false },
});

const adminSessionSecret =
  process.env.ADMIN_SESSION_SECRET ||
  process.env.DATABASE_URL ||
  process.env.DB_PASSWORD ||
  crypto.randomBytes(32).toString("hex");
const ADMIN_SESSION_TTL_SECONDS = 12 * 60 * 60;

function criarSessaoAdministrador(usuarioId) {
  const payload = Buffer.from(JSON.stringify({
    sub: Number(usuarioId),
    exp: Math.floor(Date.now() / 1000) + ADMIN_SESSION_TTL_SECONDS,
  })).toString("base64url");
  const assinatura = crypto
    .createHmac("sha256", adminSessionSecret)
    .update(payload)
    .digest("base64url");

  return `${payload}.${assinatura}`;
}

function autenticarAdministrador(req, res, next) {
  const [tipo, token] = String(req.headers.authorization || "").split(" ");
  if (tipo !== "Bearer" || !token) {
    return res.status(401).json({ erro: "Sessão administrativa necessária." });
  }

  const [payload, assinaturaRecebida, extra] = token.split(".");
  if (!payload || !assinaturaRecebida || extra) {
    return res.status(401).json({ erro: "Sessão administrativa inválida." });
  }

  const assinaturaEsperada = crypto
    .createHmac("sha256", adminSessionSecret)
    .update(payload)
    .digest();
  let assinaturaFornecida;
  try {
    assinaturaFornecida = Buffer.from(assinaturaRecebida, "base64url");
  } catch {
    return res.status(401).json({ erro: "Sessão administrativa inválida." });
  }

  if (
    assinaturaFornecida.length !== assinaturaEsperada.length ||
    !crypto.timingSafeEqual(assinaturaFornecida, assinaturaEsperada)
  ) {
    return res.status(401).json({ erro: "Sessão administrativa inválida." });
  }

  let sessao;
  try {
    sessao = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    return res.status(401).json({ erro: "Sessão administrativa inválida." });
  }

  if (!Number.isInteger(sessao.sub) || sessao.exp <= Date.now() / 1000) {
    return res.status(401).json({ erro: "Sessão administrativa expirada." });
  }

  pool.query(
    "SELECT id FROM usuario WHERE id = $1 AND tipo_usuario = 'administrador'",
    [sessao.sub]
  ).then((resultado) => {
    if (resultado.rowCount === 0) {
      return res.status(403).json({ erro: "Acesso permitido apenas a administradores." });
    }
    req.administradorId = sessao.sub;
    next();
  }).catch((erro) => {
    console.error("Erro ao validar sessão administrativa:", erro.message);
    res.status(500).json({ erro: "Não foi possível validar a sessão." });
  });
}

pool
  .query("SELECT NOW()")
  .then(() => console.log("Conectado ao banco Neon com sucesso."))
  .catch((err) => console.error("Erro ao conectar no banco:", err.message));

// Guarda o texto do objetivo "Outro" do perfil acadêmico (idempotente: roda sem problema várias vezes).
pool
  .query("ALTER TABLE perfil_academico ADD COLUMN IF NOT EXISTS objetivo_outro VARCHAR(150)")
  .catch((err) => console.error("Não foi possível garantir perfil_academico.objetivo_outro:", err.message));

// ---------- CADASTRO (nome/email/senha + perfil acadêmico, tudo de uma vez) ----------
app.post("/api/cadastro", async (req, res) => {
  const {
    nome,
    email,
    senha,
    dataNascimento,
    serie,
    redeEnsino,
    curso,
    universidade,
    tipoInstituicao,
    objetivo,
    objetivoOutro,
  } = req.body;

  if (
    !nome ||
    !email ||
    !senha ||
    !dataNascimento ||
    !serie ||
    !redeEnsino ||
    !curso ||
    !universidade ||
    !tipoInstituicao ||
    !objetivo
  ) {
    return res
      .status(400)
      .json({ erro: "Preencha todos os campos obrigatórios." });
  }
  if (senha.length < 6) {
    return res
      .status(400)
      .json({ erro: "A senha deve ter pelo menos 6 caracteres." });
  }

  try {
    const existe = await pool.query(
      "SELECT id FROM usuario WHERE email = $1",
      [email]
    );

    if (existe.rows.length > 0) {
      return res
        .status(400)
        .json({ erro: "Este e-mail já está cadastrado." });
    }

    const hash = await bcrypt.hash(senha, 10);

const redeEnsinoBanco =
  String(redeEnsino) === "1" ? "publica" :
  String(redeEnsino) === "2" ? "particular" :
  redeEnsino;

const tipoInstituicaoBanco =
  String(tipoInstituicao) === "1" ? "publica" :
  String(tipoInstituicao) === "2" ? "particular" :
  tipoInstituicao;

 const client = await pool.connect();

try {
  await client.query("BEGIN");

  // 1º INSERT: dados de acesso do usuário
  const resultadoUsuario = await client.query(
    `INSERT INTO usuario
      (nome, email, senha_hash)
     VALUES ($1, $2, $3)
     RETURNING id`,
    [
      nome,
      email,
      hash
    ]
  );

  const usuarioId = resultadoUsuario.rows[0].id;

  // 2º INSERT: perfil acadêmico
  await client.query(
    `INSERT INTO perfil_academico
      (usuario_id, data_nascimento, serie, rede_ensino,
       curso_desejado, universidade_desejada,
       tipo_universidade, objetivo_geral)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
[
  usuarioId,
  dataNascimento,
  serie,
  redeEnsinoBanco,
  curso,
  universidade,
  tipoInstituicaoBanco,
  objetivo
]
  );

  await client.query("COMMIT");

  res.json({
    sucesso: true,
    usuarioId: usuarioId
  });

} catch (erro) {
  await client.query("ROLLBACK");
  throw erro;

} finally {
  client.release();
}

  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro ao cadastrar usuário." });
  }
});

// ---------- LOGIN ----------
app.post("/api/login", async (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha) {
    return res.status(400).json({
      erro: "Preencha e-mail e senha."
    });
  }

  try {

    const resultado = await pool.query(
  `SELECT id, nome, email, senha_hash, tipo_usuario, status
   FROM usuario
   WHERE LOWER(email) = LOWER($1)`,
  [email.trim()]
);

    if (resultado.rows.length === 0) {
      return res.status(401).json({
        erro: "E-mail ou senha inválidos."
      });
    }

    const usuario = resultado.rows[0];

    const senhaCorreta = await bcrypt.compare(
      senha,
      usuario.senha_hash
    );

    if (!senhaCorreta) {
      return res.status(401).json({
        erro: "E-mail ou senha inválidos."
      });
    }

    return res.json({
  sucesso: true,
  usuarioId: usuario.id,
  nome: usuario.nome,
  email: usuario.email,
  tipoUsuario: usuario.tipo_usuario,
  ...(usuario.tipo_usuario === "administrador"
    ? { sessaoAdmin: criarSessaoAdministrador(usuario.id) }
    : {})
});

  } catch (err) {

    console.error("Erro no login:", err);

    return res.status(500).json({
      erro: "Erro ao entrar."
    });
  }
});

// =====================================================
// ADMINISTRADOR - API DE DADOS (usuários, disciplinas, planos de curso)
// =====================================================

// ---------- DADOS ADMINISTRATIVOS ----------
function erroDadosAdmin(res, erro, mensagem) {
  if (erro.code === "23505") {
    return res.status(409).json({ erro: "Já existe um registro com esses dados." });
  }
  if (erro.code === "23503") {
    return res.status(409).json({ erro: "Este registro está relacionado a outros dados e não pode ser removido." });
  }
  if (["22P02", "22007", "23502", "23514"].includes(erro.code)) {
    return res.status(400).json({ erro: "Confira os campos informados." });
  }

  console.error(`${mensagem}:`, erro.message);
  return res.status(500).json({ erro: mensagem });
}

function campoObrigatorio(valor) {
  return typeof valor === "string" ? valor.trim() : "";
}

app.get("/api/admin/dados/usuarios", autenticarAdministrador, async (req, res) => {
  try {
    const tipo = req.query.tipo === "administrador" ? "administrador" : null;
    const resultado = await pool.query(
      `SELECT
          u.id, u.nome, u.email, u.data_cadastro, u.ultimo_acesso,
          u.status, u.tipo_usuario,
          TO_CHAR(p.data_nascimento, 'YYYY-MM-DD') AS data_nascimento,
          p.serie, p.etapa_atual, p.escola, p.rede_ensino,
          p.curso_desejado, p.universidade_desejada, p.tipo_universidade,
          p.objetivo_geral, p.trilha_sesi, p.etapa_sesi
       FROM usuario u
       LEFT JOIN perfil_academico p ON p.usuario_id = u.id
       WHERE ($1::text IS NULL OR u.tipo_usuario = $1)
       ORDER BY u.id`,
      [tipo]
    );
    return res.json({ quantidade: resultado.rowCount, usuarios: resultado.rows });
  } catch (erro) {
    return erroDadosAdmin(res, erro, "Não foi possível carregar os usuários.");
  }
});

app.put("/api/admin/dados/usuarios/:id", autenticarAdministrador, async (req, res) => {
  const id = Number(req.params.id);
  const nome = campoObrigatorio(req.body.nome);
  const email = campoObrigatorio(req.body.email);
  if (!Number.isInteger(id) || id < 1 || !nome || !email) {
    return res.status(400).json({ erro: "Informe nome e e-mail válidos." });
  }

  let client;
  try {
    client = await pool.connect();
    await client.query("BEGIN");
    const usuario = await client.query(
      "UPDATE usuario SET nome = $1, email = $2 WHERE id = $3 RETURNING id, tipo_usuario",
      [nome, email, id]
    );
    if (usuario.rowCount === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ erro: "Usuário não encontrado." });
    }

    if (usuario.rows[0].tipo_usuario === "administrador") {
      await client.query("COMMIT");
      return res.json({ sucesso: true });
    }

    const perfil = req.body;
    const etapaSesi = perfil.etapa_sesi === "" || perfil.etapa_sesi == null
      ? null
      : Number(perfil.etapa_sesi);
    if (etapaSesi !== null && (!Number.isInteger(etapaSesi) || etapaSesi < 0)) {
      await client.query("ROLLBACK");
      return res.status(400).json({ erro: "A etapa SESI deve ser um número válido." });
    }

    await client.query(
      `INSERT INTO perfil_academico (
          usuario_id, data_nascimento, serie, escola, rede_ensino,
          curso_desejado, universidade_desejada, tipo_universidade,
          objetivo_geral, trilha_sesi, etapa_sesi
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       ON CONFLICT (usuario_id) DO UPDATE SET
          data_nascimento = EXCLUDED.data_nascimento,
          serie = EXCLUDED.serie,
          escola = EXCLUDED.escola,
          rede_ensino = EXCLUDED.rede_ensino,
          curso_desejado = EXCLUDED.curso_desejado,
          universidade_desejada = EXCLUDED.universidade_desejada,
          tipo_universidade = EXCLUDED.tipo_universidade,
          objetivo_geral = EXCLUDED.objetivo_geral,
          trilha_sesi = EXCLUDED.trilha_sesi,
          etapa_sesi = EXCLUDED.etapa_sesi,
          atualizado_em = NOW()`,
      [
        id,
        perfil.data_nascimento || null,
        campoObrigatorio(perfil.serie) || null,
        campoObrigatorio(perfil.escola) || null,
        campoObrigatorio(perfil.rede_ensino) || null,
        campoObrigatorio(perfil.curso_desejado) || null,
        campoObrigatorio(perfil.universidade_desejada) || null,
        campoObrigatorio(perfil.tipo_universidade) || null,
        campoObrigatorio(perfil.objetivo_geral) || null,
        campoObrigatorio(perfil.trilha_sesi) || null,
        etapaSesi,
      ]
    );

    await client.query("COMMIT");
    return res.json({ sucesso: true });
  } catch (erro) {
    if (client) await client.query("ROLLBACK").catch(() => {});
    return erroDadosAdmin(res, erro, "Não foi possível atualizar o usuário.");
  } finally {
    if (client) client.release();
  }
});

app.delete("/api/admin/dados/usuarios/:id", autenticarAdministrador, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) {
    return res.status(400).json({ erro: "ID de usuário inválido." });
  }
  if (id === req.administradorId) {
    return res.status(409).json({ erro: "Não é possível excluir a conta administrativa usada nesta sessão." });
  }

  try {
    const resultado = await pool.query("DELETE FROM usuario WHERE id = $1 RETURNING id", [id]);
    if (resultado.rowCount === 0) {
      return res.status(404).json({ erro: "Usuário não encontrado." });
    }
    return res.json({ sucesso: true, id: resultado.rows[0].id });
  } catch (erro) {
    return erroDadosAdmin(res, erro, "Não foi possível excluir o usuário.");
  }
});

app.get("/api/admin/dados/disciplinas", autenticarAdministrador, async (_req, res) => {
  try {
    const resultado = await pool.query("SELECT id, nome, area_conhecimento FROM disciplina ORDER BY nome");
    return res.json({ quantidade: resultado.rowCount, disciplinas: resultado.rows });
  } catch (erro) {
    return erroDadosAdmin(res, erro, "Não foi possível carregar as disciplinas.");
  }
});

app.post("/api/admin/dados/disciplinas", autenticarAdministrador, async (req, res) => {
  const nome = campoObrigatorio(req.body.nome);
  const area = campoObrigatorio(req.body.area_conhecimento);
  if (!nome) return res.status(400).json({ erro: "Informe o nome da disciplina." });
  try {
    const resultado = await pool.query(
      "INSERT INTO disciplina (nome, area_conhecimento) VALUES ($1, $2) RETURNING id, nome, area_conhecimento",
      [nome, area || null]
    );
    return res.status(201).json({ disciplina: resultado.rows[0] });
  } catch (erro) {
    return erroDadosAdmin(res, erro, "Não foi possível cadastrar a disciplina.");
  }
});

app.put("/api/admin/dados/disciplinas/:id", autenticarAdministrador, async (req, res) => {
  const id = Number(req.params.id);
  const nome = campoObrigatorio(req.body.nome);
  const area = campoObrigatorio(req.body.area_conhecimento);
  if (!Number.isInteger(id) || id < 1 || !nome) {
    return res.status(400).json({ erro: "Informe o nome da disciplina." });
  }
  try {
    const resultado = await pool.query(
      "UPDATE disciplina SET nome = $1, area_conhecimento = $2 WHERE id = $3 RETURNING id, nome, area_conhecimento",
      [nome, area || null, id]
    );
    if (resultado.rowCount === 0) return res.status(404).json({ erro: "Disciplina não encontrada." });
    return res.json({ disciplina: resultado.rows[0] });
  } catch (erro) {
    return erroDadosAdmin(res, erro, "Não foi possível atualizar a disciplina.");
  }
});

app.delete("/api/admin/dados/disciplinas/:id", autenticarAdministrador, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return res.status(400).json({ erro: "ID de disciplina inválido." });
  try {
    const resultado = await pool.query("DELETE FROM disciplina WHERE id = $1 RETURNING id", [id]);
    if (resultado.rowCount === 0) return res.status(404).json({ erro: "Disciplina não encontrada." });
    return res.json({ sucesso: true, id: resultado.rows[0].id });
  } catch (erro) {
    return erroDadosAdmin(res, erro, "Não foi possível excluir a disciplina.");
  }
});

app.get("/api/admin/dados/planos-curso", autenticarAdministrador, async (_req, res) => {
  try {
    const resultado = await pool.query(
      `SELECT pc.id, pc.ano_letivo, pc.serie, pc.etapa, pc.disciplina_id,
              pc.versao, pc.ativo, pc.trilha, d.nome AS disciplina,
              COUNT(cc.id)::int AS total_conteudos
       FROM plano_curso pc
       LEFT JOIN disciplina d ON d.id = pc.disciplina_id
       LEFT JOIN conteudo_curricular cc ON cc.plano_curso_id = pc.id
       GROUP BY pc.id, d.nome
       ORDER BY pc.ano_letivo DESC, pc.serie, pc.etapa, d.nome`
    );
    return res.json({ quantidade: resultado.rowCount, planos: resultado.rows });
  } catch (erro) {
    return erroDadosAdmin(res, erro, "Não foi possível carregar os planos de curso.");
  }
});

function validarPlanoCurso(body) {
  const ano = Number(body.ano_letivo);
  const serie = Number(body.serie);
  const etapa = Number(body.etapa);
  const disciplinaId = Number(body.disciplina_id);
  if (
    !Number.isInteger(ano) || ano < 2000 || ano > 2100 ||
    !Number.isInteger(serie) || serie < 1 ||
    !Number.isInteger(etapa) || etapa < 1 ||
    !Number.isInteger(disciplinaId) || disciplinaId < 1
  ) return null;
  return [ano, serie, etapa, disciplinaId, campoObrigatorio(body.versao) || "1", body.ativo === true, campoObrigatorio(body.trilha) || null];
}

app.post("/api/admin/dados/planos-curso", autenticarAdministrador, async (req, res) => {
  const valores = validarPlanoCurso(req.body);
  if (!valores) return res.status(400).json({ erro: "Confira ano, série, etapa e disciplina do plano." });
  try {
    const resultado = await pool.query(
      `INSERT INTO plano_curso (ano_letivo, serie, etapa, disciplina_id, versao, ativo, trilha)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
      valores
    );
    return res.status(201).json({ id: resultado.rows[0].id });
  } catch (erro) {
    return erroDadosAdmin(res, erro, "Não foi possível cadastrar o plano de curso.");
  }
});

app.put("/api/admin/dados/planos-curso/:id", autenticarAdministrador, async (req, res) => {
  const id = Number(req.params.id);
  const valores = validarPlanoCurso(req.body);
  if (!Number.isInteger(id) || id < 1 || !valores) {
    return res.status(400).json({ erro: "Confira ano, série, etapa e disciplina do plano." });
  }
  try {
    const resultado = await pool.query(
      `UPDATE plano_curso SET ano_letivo = $1, serie = $2, etapa = $3,
              disciplina_id = $4, versao = $5, ativo = $6, trilha = $7
       WHERE id = $8 RETURNING id`,
      [...valores, id]
    );
    if (resultado.rowCount === 0) return res.status(404).json({ erro: "Plano de curso não encontrado." });
    return res.json({ sucesso: true, id });
  } catch (erro) {
    return erroDadosAdmin(res, erro, "Não foi possível atualizar o plano de curso.");
  }
});

app.delete("/api/admin/dados/planos-curso/:id", autenticarAdministrador, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return res.status(400).json({ erro: "ID de plano inválido." });
  try {
    const resultado = await pool.query("DELETE FROM plano_curso WHERE id = $1 RETURNING id", [id]);
    if (resultado.rowCount === 0) return res.status(404).json({ erro: "Plano de curso não encontrado." });
    return res.json({ sucesso: true, id });
  } catch (erro) {
    return erroDadosAdmin(res, erro, "Não foi possível excluir o plano de curso.");
  }
});

app.get("/api/admin/dados/resumo", autenticarAdministrador, async (_req, res) => {
  try {
    const resultado = await pool.query(
      `SELECT
          (SELECT COUNT(*)::int FROM usuario WHERE tipo_usuario <> 'administrador') AS usuarios,
          (SELECT COUNT(*)::int FROM usuario WHERE tipo_usuario = 'administrador') AS administradores,
          (SELECT COUNT(*)::int FROM disciplina) AS disciplinas,
          (SELECT COUNT(*)::int FROM plano_curso) AS planos_curso,
          (SELECT COUNT(*)::int FROM cronograma_preferencias) AS cronogramas,
          (SELECT COUNT(*)::int FROM objetivo_estudo) AS objetivos`
    );
    return res.json(resultado.rows[0]);
  } catch (erro) {
    return erroDadosAdmin(res, erro, "Não foi possível carregar o resumo administrativo.");
  }
});



// =====================================================
// BUSCAR DADOS DO USUÁRIO + PERFIL ACADÊMICO
// =====================================================
async function consultarPerfil(db, usuarioId) {
  const resultado = await db.query(
    `SELECT
        u.nome,
        u.email,
        TO_CHAR(pa.data_nascimento, 'YYYY-MM-DD') AS data_nascimento,
        pa.serie,
        pa.etapa_atual,
        pa.escola,
        pa.rede_ensino,
        pa.curso_desejado,
        pa.universidade_desejada,
        pa.tipo_universidade,
        pa.objetivo_geral,
        pa.objetivo_outro,
        pa.trilha_sesi,
        pa.etapa_sesi
     FROM usuario u
     LEFT JOIN perfil_academico pa ON pa.usuario_id = u.id
     WHERE u.id = $1`,
    [usuarioId]
  );

  const linha = resultado.rows[0];
  if (!linha) return null;

  return {
    // Dados da conta
    nome: linha.nome,
    email: linha.email,

    // Perfil acadêmico
    dataNascimento: linha.data_nascimento,
    serie: linha.serie,
    etapaAtual: linha.etapa_atual,
    escola: linha.escola,
    redeEnsino: linha.rede_ensino,
    cursoDesejado: linha.curso_desejado,
    universidadeDesejada: linha.universidade_desejada,
    tipoUniversidade: linha.tipo_universidade,
    objetivoGeral: linha.objetivo_geral,
    objetivoOutro: linha.objetivo_outro,
    trilhaSesi: linha.trilha_sesi,
    etapaSesi: linha.etapa_sesi,
  };
}

app.get("/api/perfil/:usuarioId", async (req, res) => {
  const usuarioId = parseInt(req.params.usuarioId, 10);

  if (isNaN(usuarioId)) {
    return res.status(400).json({ erro: "ID de usuário inválido." });
  }

  try {
    const perfil = await consultarPerfil(pool, usuarioId);

    if (!perfil) {
      return res.status(404).json({ erro: "Usuário não encontrado." });
    }

    return res.json(perfil);
  } catch (erro) {
    console.error("❌ ERRO AO BUSCAR PERFIL:", erro);
    return res.status(500).json({
      sucesso: false,
      erro: "Erro ao buscar perfil do usuário.",
      detalhe: erro.message,
      codigo: erro.code,
    });
  }
});

// ---------- ATUALIZAR PERFIL ACADÊMICO ----------
// Aceita os códigos numéricos usados no cadastro (série 1-8, rede 1-2, objetivo 1-7)
// e também os textos equivalentes. Grava no mesmo formato que o cadastro usa.
const OBJETIVO_CHAVES = { enem: 1, vestibular: 2, notas: 3, estudos: 4, recuperacao: 5, concurso: 6, outro: 7 };

function normalizarSerie(valor) {
  if (valor === undefined || valor === null || valor === "") return null;
  const texto = String(valor).trim().toLowerCase();
  if (/^[1-8]$/.test(texto)) return Number(texto);
  const chave = texto.match(/^([1-9])_(ef|em)$/); // ex.: "6_ef", "1_em"
  const porExtenso = texto.match(/([1-9])\s*[ºo°]?\s*ano.*(fundamental|m[eé]dio)/);
  const achado = chave
    ? [Number(chave[1]), chave[2] === "ef" ? "ef" : "em"]
    : porExtenso
      ? [Number(porExtenso[1]), porExtenso[2].startsWith("f") ? "ef" : "em"]
      : null;
  if (!achado) return null;
  const [ano, nivel] = achado;
  if (nivel === "ef" && ano >= 5 && ano <= 9) return ano - 4;
  if (nivel === "em" && ano >= 1 && ano <= 3) return ano + 5;
  return null;
}

function normalizarRedeEnsino(valor) {
  const texto = String(valor ?? "").trim().toLowerCase();
  if (texto === "1" || texto === "publica" || texto === "pública") return "publica";
  if (texto === "2" || texto === "particular") return "particular";
  return null;
}

function normalizarObjetivo(valor) {
  const texto = String(valor ?? "").trim().toLowerCase();
  if (/^[1-7]$/.test(texto)) return Number(texto);
  return OBJETIVO_CHAVES[texto] || null;
}

function dataNascimentoValida(valor) {
  if (typeof valor !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(valor)) return false;
  const data = new Date(`${valor}T00:00:00Z`);
  if (Number.isNaN(data.getTime()) || data.toISOString().slice(0, 10) !== valor) return false;
  return data.getUTCFullYear() >= 1900 && data.getTime() <= Date.now();
}

app.put("/api/perfil/:usuarioId", async (req, res) => {
  const usuarioId = parseInt(req.params.usuarioId, 10);

  if (isNaN(usuarioId)) {
    return res.status(400).json({ erro: "ID de usuário inválido." });
  }

  const corpo = req.body || {};
  const texto = (v) => (v === undefined || v === null ? "" : String(v).trim());

  const nome = texto(corpo.nome);
  const dataNascimento = texto(corpo.dataNascimento);
  const serie = normalizarSerie(corpo.serie);
  const redeEnsino = normalizarRedeEnsino(corpo.redeEnsino);
  const escola = texto(corpo.escola);
  const curso = texto(corpo.curso);
  const universidade = texto(corpo.universidade);
  const tipoInstituicao = normalizarRedeEnsino(corpo.tipoInstituicao);
  const objetivo = normalizarObjetivo(corpo.objetivo);
  const objetivoOutro = texto(corpo.objetivoOutro);

  let etapaAtual = null;
  if (corpo.etapaAtual !== undefined && corpo.etapaAtual !== null && texto(corpo.etapaAtual) !== "") {
    etapaAtual = Number(corpo.etapaAtual);
    if (!Number.isInteger(etapaAtual) || etapaAtual < 1 || etapaAtual > 12) {
      return res.status(400).json({ erro: "A etapa atual deve ser um número entre 1 e 12." });
    }
  }

  // O nome só é alterado quando vem no corpo (a tela antiga perfil-visualizar.html não envia).
  const nomeInformado = corpo.nome !== undefined;
  if (nomeInformado && (nome.length < 2 || nome.length > 100)) {
    return res.status(400).json({ erro: "Informe seu nome completo (até 100 caracteres)." });
  }
  if (!dataNascimentoValida(dataNascimento)) {
    return res.status(400).json({ erro: "Informe uma data de nascimento válida." });
  }
  if (!serie) {
    return res.status(400).json({ erro: "Selecione a série/ano escolar." });
  }
  if (!redeEnsino) {
    return res.status(400).json({ erro: "Selecione a rede de ensino da escola." });
  }
  if (!curso || !universidade || !tipoInstituicao || !objetivo) {
    return res.status(400).json({ erro: "Preencha curso, universidade, tipo de instituição e objetivo." });
  }
  if (escola.length > 100 || curso.length > 100 || universidade.length > 100) {
    return res.status(400).json({ erro: "Escola, curso e universidade aceitam até 100 caracteres." });
  }
  if (objetivo === 7 && !objetivoOutro) {
    return res.status(400).json({ erro: "Descreva qual é o seu objetivo em \"Outro\"." });
  }
  if (objetivoOutro.length > 150) {
    return res.status(400).json({ erro: "O objetivo \"Outro\" aceita até 150 caracteres." });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const usuario = nomeInformado
      ? await client.query("UPDATE usuario SET nome = $1 WHERE id = $2 RETURNING id", [nome, usuarioId])
      : await client.query("SELECT id FROM usuario WHERE id = $1", [usuarioId]);

    if (usuario.rowCount === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ erro: "Usuário não encontrado." });
    }

    await client.query(
      `INSERT INTO perfil_academico (
          usuario_id, data_nascimento, serie, etapa_atual, escola, rede_ensino,
          curso_desejado, universidade_desejada, tipo_universidade,
          objetivo_geral, objetivo_outro, atualizado_em
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
       ON CONFLICT (usuario_id) DO UPDATE SET
          data_nascimento = EXCLUDED.data_nascimento,
          serie = EXCLUDED.serie,
          etapa_atual = EXCLUDED.etapa_atual,
          escola = EXCLUDED.escola,
          rede_ensino = EXCLUDED.rede_ensino,
          curso_desejado = EXCLUDED.curso_desejado,
          universidade_desejada = EXCLUDED.universidade_desejada,
          tipo_universidade = EXCLUDED.tipo_universidade,
          objetivo_geral = EXCLUDED.objetivo_geral,
          objetivo_outro = EXCLUDED.objetivo_outro,
          atualizado_em = NOW()`,
      [
        usuarioId,
        dataNascimento,
        String(serie),
        etapaAtual,
        escola || null,
        redeEnsino,
        curso,
        universidade,
        tipoInstituicao,
        String(objetivo),
        objetivo === 7 ? objetivoOutro : null,
      ]
    );

    await client.query("COMMIT");

    const perfil = await consultarPerfil(pool, usuarioId);
    if (!perfil) return res.status(404).json({ erro: "Usuário não encontrado." });
    return res.json({ sucesso: true, perfil });
  } catch (erro) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("❌ ERRO AO ATUALIZAR PERFIL:", erro);
    return res.status(500).json({ erro: "Erro ao atualizar perfil." });
  } finally {
    client.release();
  }
});


// =====================================================
// PERFIL ACADÊMICO - DIFICULDADES
// =====================================================

// =====================================================
// BUSCAR DIFICULDADES DO ALUNO
// =====================================================

app.get("/api/perfil-dificuldades/:usuarioId", async (req, res) => {

    const usuarioId =
        parseInt(req.params.usuarioId, 10);


    if (!Number.isInteger(usuarioId) || usuarioId <= 0) {

        return res.status(400).json({
            sucesso: false,
            erro: "ID de usuário inválido."
        });

    }


    try {

        // ==========================================
        // DISCIPLINAS E CONTEÚDOS DE DIFICULDADE
        // ==========================================

        const resultadoDificuldades =
            await pool.query(
                `
                SELECT
                    pd.id,
                    pd.disciplina_id,
                    d.nome AS disciplina,
                    pd.conteudo_1,
                    pd.conteudo_2,
                    pd.conteudo_3

                FROM perfil_dificuldade pd

                INNER JOIN disciplina d
                    ON d.id = pd.disciplina_id

                WHERE pd.usuario_id = $1

                ORDER BY d.nome
                `,
                [usuarioId]
            );


        // ==========================================
        // MATÉRIA QUE PRATICAMENTE NÃO ESTUDA
        // ==========================================

        const resultadoPerfil =
            await pool.query(
                `
                SELECT
                    disciplina_nao_estuda_id,
                    nao_estuda_nenhuma,
                    motivo_nao_estuda

                FROM perfil_academico

                WHERE usuario_id = $1
                `,
                [usuarioId]
            );


        const perfil =
            resultadoPerfil.rows[0] || null;


        let disciplinaNaoEstuda = "";


        if (perfil) {

            if (perfil.nao_estuda_nenhuma) {

                disciplinaNaoEstuda =
                    "nenhuma";

            } else if (
                perfil.disciplina_nao_estuda_id
            ) {

                disciplinaNaoEstuda =
                    String(
                        perfil.disciplina_nao_estuda_id
                    );

            }

        }


        return res.json({

            sucesso: true,

            dificuldades:
                resultadoDificuldades.rows,

            disciplinaNaoEstuda,

            motivoNaoEstuda:
                perfil?.motivo_nao_estuda || ""

        });


    } catch (erro) {

        console.error(
            "❌ Erro ao buscar dificuldades:",
            erro
        );


        return res.status(500).json({

            sucesso: false,

            erro:
                "Erro ao buscar dificuldades do aluno."

        });

    }

});

// =====================================================
// SALVAR / ATUALIZAR DIFICULDADES DO ALUNO
// =====================================================

app.put("/api/perfil-dificuldades/:usuarioId", async (req, res) => {

    const usuarioId =
        parseInt(req.params.usuarioId, 10);


    if (!Number.isInteger(usuarioId) || usuarioId <= 0) {

        return res.status(400).json({
            sucesso: false,
            erro: "ID de usuário inválido."
        });

    }


    const {
        dificuldades,
        disciplinaNaoEstuda,
        motivoNaoEstuda
    } = req.body;


    // ==========================================
    // VALIDAR DIFICULDADES
    // ==========================================

    if (!Array.isArray(dificuldades)) {

        return res.status(400).json({
            sucesso: false,
            erro: "Lista de dificuldades inválida."
        });

    }


    if (
        dificuldades.length === 0 ||
        dificuldades.length > 3
    ) {

        return res.status(400).json({
            sucesso: false,
            erro:
                "Selecione entre 1 e 3 disciplinas."
        });

    }


    // ==========================================
    // VALIDAR MATÉRIA QUE NÃO ESTUDA
    // ==========================================

    if (!disciplinaNaoEstuda) {

        return res.status(400).json({
            sucesso: false,
            erro:
                "Responda se existe alguma matéria que você praticamente não estuda."
        });

    }


    const marcouNenhuma =
        disciplinaNaoEstuda === "nenhuma";


    let disciplinaNaoEstudaId = null;


    if (!marcouNenhuma) {

        disciplinaNaoEstudaId =
            parseInt(
                disciplinaNaoEstuda,
                10
            );


        if (
            !Number.isInteger(
                disciplinaNaoEstudaId
            )
        ) {

            return res.status(400).json({
                sucesso: false,
                erro:
                    "Disciplina não estudada inválida."
            });

        }


        if (
            !String(
                motivoNaoEstuda || ""
            ).trim()
        ) {

            return res.status(400).json({
                sucesso: false,
                erro:
                    "Informe por que você praticamente não estuda essa matéria."
            });

        }

    }


    const motivoFinal =
        marcouNenhuma
            ? null
            : String(
                motivoNaoEstuda || ""
            ).trim();


    const client =
        await pool.connect();


    try {

        await client.query("BEGIN");


        // ==========================================
        // APAGAR DIFICULDADES ANTIGAS
        // ==========================================

        await client.query(
            `
            DELETE FROM perfil_dificuldade

            WHERE usuario_id = $1
            `,
            [usuarioId]
        );


        // ==========================================
        // SALVAR DIFICULDADES ATUAIS
        // ==========================================

        for (const item of dificuldades) {

            const disciplinaId =
                parseInt(
                    item.disciplinaId,
                    10
                );


            if (
                !Number.isInteger(
                    disciplinaId
                )
            ) {

                throw new Error(
                    "Disciplina inválida."
                );

            }


            await client.query(
                `
                INSERT INTO perfil_dificuldade
                (
                    usuario_id,
                    disciplina_id,
                    conteudo_1,
                    conteudo_2,
                    conteudo_3,
                    atualizado_em
                )

                VALUES (
                    $1,
                    $2,
                    $3,
                    $4,
                    $5,
                    CURRENT_TIMESTAMP
                )
                `,
                [
                    usuarioId,
                    disciplinaId,
                    item.conteudo1?.trim() || null,
                    item.conteudo2?.trim() || null,
                    item.conteudo3?.trim() || null
                ]
            );

        }


        // ==========================================
        // SALVAR MATÉRIA QUE NÃO ESTUDA
        // ==========================================

        const resultadoPerfil =
            await client.query(
                `
                UPDATE perfil_academico

                SET
                    disciplina_nao_estuda_id = $1,
                    nao_estuda_nenhuma = $2,
                    motivo_nao_estuda = $3

                WHERE usuario_id = $4

                RETURNING usuario_id
                `,
                [
                    disciplinaNaoEstudaId,
                    marcouNenhuma,
                    motivoFinal,
                    usuarioId
                ]
            );


        if (
            resultadoPerfil.rowCount === 0
        ) {

            throw new Error(
                "Perfil Acadêmico não encontrado."
            );

        }


        await client.query("COMMIT");


        return res.json({

            sucesso: true,

            mensagem:
                "Dificuldades salvas com sucesso."

        });


    } catch (erro) {

        await client.query(
            "ROLLBACK"
        );


        console.error(
            "❌ Erro ao salvar dificuldades:",
            erro
        );


        return res.status(500).json({

            sucesso: false,

            erro:
                "Erro ao salvar dificuldades."

        });


    } finally {

        client.release();

    }

});


// =====================================================
// BUSCAR TEMPO DISPONÍVEL PARA ESTUDOS
// =====================================================

app.get("/api/perfil-tempo-estudo/:usuarioId", async (req, res) => {

    const usuarioId = parseInt(req.params.usuarioId, 10);

    if (isNaN(usuarioId)) {
        return res.status(400).json({
            sucesso: false,
            erro: "ID de usuário inválido."
        });
    }

    try {

        const resultado = await pool.query(
            `
            SELECT
                usuario_id,
                tempo_atual_minutos,
                dias_disponiveis,
                periodo_preferido,
                tempo_disponivel_minutos,
                fim_semana,
                periodo_livre,
                atualizado_em
            FROM perfil_tempo_estudo
            WHERE usuario_id = $1
            `,
            [usuarioId]
        );

        if (resultado.rows.length === 0) {
            return res.json({
                sucesso: true,
                tempoEstudo: null
            });
        }

        return res.json({
            sucesso: true,
            tempoEstudo: resultado.rows[0]
        });

    } catch (erro) {

        console.error("❌ Erro ao buscar tempo de estudo:", erro);

        return res.status(500).json({
            sucesso: false,
            erro: "Erro ao buscar tempo disponível para estudos."
        });
    }
});


// =====================================================
// SALVAR / ATUALIZAR TEMPO DISPONÍVEL PARA ESTUDOS
// =====================================================

app.put("/api/perfil-tempo-estudo/:usuarioId", async (req, res) => {

    const usuarioId = parseInt(req.params.usuarioId, 10);

    if (isNaN(usuarioId)) {
        return res.status(400).json({
            sucesso: false,
            erro: "ID de usuário inválido."
        });
    }

    const {
        horasAtuais,
        diasDisponiveis,
        periodoPreferido,
        tempoDisponivel,
        fimSemana,
        periodoLivre
    } = req.body;

    // =====================================================
    // VALIDAÇÕES
    // =====================================================

    if (
        horasAtuais === undefined ||
        horasAtuais === null ||
        horasAtuais === ""
    ) {
        return res.status(400).json({
            sucesso: false,
            erro: "Informe quanto tempo o aluno estuda atualmente."
        });
    }

    if (!Array.isArray(diasDisponiveis) || diasDisponiveis.length === 0) {
        return res.status(400).json({
            sucesso: false,
            erro: "Informe pelo menos um dia disponível para estudos."
        });
    }

    if (!periodoPreferido) {
        return res.status(400).json({
            sucesso: false,
            erro: "Informe o período preferido para estudos."
        });
    }

    if (
        tempoDisponivel === undefined ||
        tempoDisponivel === null ||
        tempoDisponivel === ""
    ) {
        return res.status(400).json({
            sucesso: false,
            erro: "Informe o tempo disponível para estudos."
        });
    }

    if (!fimSemana) {
        return res.status(400).json({
            sucesso: false,
            erro: "Informe a disponibilidade no fim de semana."
        });
    }


    try {

        const resultado = await pool.query(
            `
            INSERT INTO perfil_tempo_estudo (
                usuario_id,
                tempo_atual_minutos,
                dias_disponiveis,
                periodo_preferido,
                tempo_disponivel_minutos,
                fim_semana,
                periodo_livre,
                atualizado_em
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP)

            ON CONFLICT (usuario_id)

            DO UPDATE SET
                tempo_atual_minutos = EXCLUDED.tempo_atual_minutos,
                dias_disponiveis = EXCLUDED.dias_disponiveis,
                periodo_preferido = EXCLUDED.periodo_preferido,
                tempo_disponivel_minutos = EXCLUDED.tempo_disponivel_minutos,
                fim_semana = EXCLUDED.fim_semana,
                periodo_livre = EXCLUDED.periodo_livre,
                atualizado_em = CURRENT_TIMESTAMP

            RETURNING *
            `,
            [
                usuarioId,
                parseInt(horasAtuais, 10),
                diasDisponiveis,
                periodoPreferido,
                parseInt(tempoDisponivel, 10),
                fimSemana,
                periodoLivre?.trim() || null
            ]
        );

        return res.json({
            sucesso: true,
            mensagem: "Tempo disponível para estudos salvo com sucesso.",
            tempoEstudo: resultado.rows[0]
        });

    } catch (erro) {

        console.error("❌ Erro ao salvar tempo de estudo:", erro);

        return res.status(500).json({
            sucesso: false,
            erro: "Erro ao salvar tempo disponível para estudos."
        });
    }
});



// =====================================================
// LISTAR DISCIPLINAS
// =====================================================

app.get("/api/disciplinas", async (req, res) => {

    try {

        const resultado = await pool.query(`
            SELECT
                id,
                nome
            FROM disciplina
            ORDER BY nome
        `);

        return res.json({
            sucesso: true,
            disciplinas: resultado.rows
        });

    } catch (erro) {

        console.error("❌ Erro ao buscar disciplinas:", erro);

        return res.status(500).json({
            sucesso: false,
            erro: "Erro ao buscar disciplinas."
        });
    }
});



// ---------- CRONOGRAMA PERSONALIZADO ----------
app.get("/api/cronograma/:usuarioId", async (req, res) => {
  const usuarioId = parseInt(req.params.usuarioId, 10);

  if (isNaN(usuarioId)) {
    return res.status(400).json({ erro: "ID de usuário inválido." });
  }

  try {
    const resultado = await pool.query(
      `SELECT horas_por_dia, dias_semana, materias_dificeis,
              materia_dificil_outra, periodo_preferido, duracao_foco
       FROM cronograma_preferencias
       WHERE usuario_id = $1`,
      [usuarioId]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({ erro: "Cronograma ainda não preenchido." });
    }

    const linha = resultado.rows[0];

    res.json({
      horasPorDia: linha.horas_por_dia,
      diasSemana: linha.dias_semana,
      materiasDificeis: linha.materias_dificeis,
      materiaDificilOutra: linha.materia_dificil_outra,
      periodoPreferido: linha.periodo_preferido,
      duracaoFoco: linha.duracao_foco,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro ao buscar cronograma." });
  }
});

app.post("/api/cronograma/:usuarioId", async (req, res) => {
  const usuarioId = parseInt(req.params.usuarioId, 10);

  if (isNaN(usuarioId)) {
    return res.status(400).json({ erro: "ID de usuário inválido." });
  }

  const {
    horasPorDia,
    diasSemana,
    materiasDificeis,
    materiaDificilOutra,
    periodoPreferido,
    duracaoFoco,
  } = req.body;

  if (
    horasPorDia === undefined ||
    horasPorDia === null ||
    horasPorDia === "" ||
    !Array.isArray(diasSemana) ||
    diasSemana.length === 0 ||
    !Array.isArray(materiasDificeis) ||
    materiasDificeis.length === 0 ||
    !periodoPreferido ||
    !duracaoFoco
  ) {
    return res
      .status(400)
      .json({ erro: "Preencha todas as perguntas obrigatórias." });
  }

  try {
    const usuarioExiste = await pool.query(
      "SELECT id FROM usuario WHERE id = $1",
      [usuarioId]
    );

    if (usuarioExiste.rows.length === 0) {
      return res.status(404).json({ erro: "Usuário não encontrado." });
    }

    await pool.query(
      `INSERT INTO cronograma_preferencias
        (usuario_id, horas_por_dia, dias_semana, materias_dificeis,
         materia_dificil_outra, periodo_preferido, duracao_foco)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (usuario_id) DO UPDATE SET
         horas_por_dia = EXCLUDED.horas_por_dia,
         dias_semana = EXCLUDED.dias_semana,
         materias_dificeis = EXCLUDED.materias_dificeis,
         materia_dificil_outra = EXCLUDED.materia_dificil_outra,
         periodo_preferido = EXCLUDED.periodo_preferido,
         duracao_foco = EXCLUDED.duracao_foco,
         atualizado_em = NOW()`,
      [
        usuarioId,
        horasPorDia,
        diasSemana,
        materiasDificeis,
        materiaDificilOutra || null,
        periodoPreferido,
        duracaoFoco,
      ]
    );

    res.json({ sucesso: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro ao salvar cronograma." });
  }
});

// ---------- ASSISTENTE IA (cronograma personalizado com Claude) ----------
// Fluxo: o backend monta um contexto compacto do aluno (perfil, currículo SESI,
// dificuldades, objetivos, rotina e eventos), calcula as janelas livres de estudo
// e só então pede ao Claude para distribuir os conteúdos dentro dessas janelas.

const DIAS_ORDEM = ["seg", "ter", "qua", "qui", "sex", "sab", "dom"];
const DIA_LABELS = {
  seg: "Segunda-feira",
  ter: "Terça-feira",
  qua: "Quarta-feira",
  qui: "Quinta-feira",
  sex: "Sexta-feira",
  sab: "Sábado",
  dom: "Domingo",
};
// rotina_item.dia_semana usa 1 = segunda ... 7 = domingo
const DIA_NUM = { seg: 1, ter: 2, qua: 3, qui: 4, sex: 5, sab: 6, dom: 7 };
// perfil_tempo_estudo.dias_disponiveis usa os rótulos do formulário
const DIA_TEMPO_PARA_CURTO = {
  Seg: "seg", Ter: "ter", Qua: "qua", Qui: "qui", Sex: "sex", "Sáb": "sab", Dom: "dom",
};
const SERIE_LABELS = {
  1: "5º Ano - Ensino Fundamental",
  2: "6º Ano - Ensino Fundamental",
  3: "7º Ano - Ensino Fundamental",
  4: "8º Ano - Ensino Fundamental",
  5: "9º Ano - Ensino Fundamental",
  6: "1º Ano - Ensino Médio",
  7: "2º Ano - Ensino Médio",
  8: "3º Ano - Ensino Médio",
};
// Série do plano_curso pode vir numerada dentro do nível (1-3 no Médio; 5-9 no Fundamental).
const SERIE_ALTERNATIVA = { 1: 5, 2: 6, 3: 7, 4: 8, 5: 9, 6: 1, 7: 2, 8: 3 };
const REDE_LABELS = { 1: "Pública", 2: "Particular", publica: "Pública", particular: "Particular" };
const OBJETIVO_LABELS = {
  1: "Passar no ENEM",
  2: "Passar no vestibular",
  3: "Melhorar as notas",
  4: "Organizar os estudos",
  5: "Recuperação escolar",
  6: "Concurso",
  7: "Outro",
  enem: "Passar no ENEM",
  vestibular: "Passar no vestibular",
  notas: "Melhorar as notas",
  estudos: "Organizar os estudos",
  recuperacao: "Recuperação escolar",
  concurso: "Concurso",
  outro: "Outro",
};
const PERIODO_CRON = { 1: "manha", 2: "tarde", 3: "noite", 4: "madrugada" };

// Remove campos vazios (null, "", []) para o prompt ficar curto e sem ruído.
function limpar(obj) {
  const saida = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v === null || v === undefined || v === "") continue;
    if (Array.isArray(v) && v.length === 0) continue;
    saida[k] = v;
  }
  return saida;
}
const PERIODO_FAIXA = {
  manha: [6 * 60, 12 * 60],
  tarde: [12 * 60, 18 * 60],
  noite: [18 * 60, 23 * 60],
  madrugada: [0, 6 * 60],
};
const INICIO_DIA_MIN = 6 * 60;
const FIM_DIA_MIN = 23 * 60;

function hhmmParaMin(valor) {
  const m = /^(\d{1,2}):(\d{2})/.exec(String(valor || ""));
  return m ? Number(m[1]) * 60 + Number(m[2]) : null;
}

function minParaHHMM(min) {
  const h = String(Math.floor(min / 60)).padStart(2, "0");
  const m = String(min % 60).padStart(2, "0");
  return `${h}:${m}`;
}

// Remove de [inicio, fim] os intervalos bloqueados e devolve as janelas livres.
function subtrairIntervalos(inicio, fim, bloqueados) {
  let livres = [[inicio, fim]];
  for (const [bi, bf] of bloqueados) {
    const proximas = [];
    for (const [li, lf] of livres) {
      if (bf <= li || bi >= lf) {
        proximas.push([li, lf]);
        continue;
      }
      if (bi > li) proximas.push([li, bi]);
      if (bf < lf) proximas.push([bf, lf]);
    }
    livres = proximas;
  }
  return livres;
}

function intersectar(janelas, faixa) {
  return janelas
    .map(([i, f]) => [Math.max(i, faixa[0]), Math.min(f, faixa[1])])
    .filter(([i, f]) => f > i);
}

// Consulta que não derruba a geração inteira se uma tabela opcional falhar.
async function consultaOpcional(sql, params, rotulo) {
  try {
    return (await pool.query(sql, params)).rows;
  } catch (err) {
    console.warn(`Assistente IA: falha ao ler ${rotulo}:`, err.message);
    return [];
  }
}

async function montarContextoAluno(usuarioId) {
  const perfilResultado = await pool.query(
    `SELECT u.nome, p.serie, p.etapa_atual, p.rede_ensino, p.curso_desejado,
            p.universidade_desejada, p.tipo_universidade, p.objetivo_geral,
            p.trilha_sesi, p.etapa_sesi, p.disciplina_nao_estuda_id,
            p.nao_estuda_nenhuma, p.motivo_nao_estuda,
            d.nome AS disciplina_nao_estuda
       FROM usuario u
       LEFT JOIN perfil_academico p ON p.usuario_id = u.id
       LEFT JOIN disciplina d ON d.id = p.disciplina_nao_estuda_id
      WHERE u.id = $1`,
    [usuarioId]
  );
  const perfil = perfilResultado.rows[0];
  if (!perfil) return null;

  const [objetivoPlano] = await consultaOpcional(
    `SELECT objetivo, objetivo_outro FROM plano_estudo_objetivo
      WHERE usuario_id = $1 ORDER BY atualizado_em DESC LIMIT 1`,
    [usuarioId],
    "plano_estudo_objetivo"
  );
  const [tempo] = await consultaOpcional(
    `SELECT tempo_atual_minutos, tempo_disponivel_minutos, dias_disponiveis,
            periodo_preferido, fim_semana, periodo_livre
       FROM perfil_tempo_estudo WHERE usuario_id = $1`,
    [usuarioId],
    "perfil_tempo_estudo"
  );

  const dificuldades = await consultaOpcional(
    `SELECT pd.disciplina_id, d.nome, pd.conteudo_1, pd.conteudo_2, pd.conteudo_3
       FROM perfil_dificuldade pd
       JOIN disciplina d ON d.id = pd.disciplina_id
      WHERE pd.usuario_id = $1`,
    [usuarioId],
    "perfil_dificuldade"
  );

  const [rotina] = await consultaOpcional(
    `SELECT id, duracao_bloco_min, intervalo_min, preferencia_periodo
       FROM rotina
      WHERE usuario_id = $1 AND ativa = true
      ORDER BY atualizado_em DESC NULLS LAST, id DESC
      LIMIT 1`,
    [usuarioId],
    "rotina"
  );
  const itensRotina = rotina
    ? await consultaOpcional(
        `SELECT dia_semana, hora_inicio, hora_fim, tipo_atividade, descricao,
                tempo_deslocamento_min, bloqueia_estudo
           FROM rotina_item WHERE rotina_id = $1`,
        [rotina.id],
        "rotina_item"
      )
    : [];

  const objetivos = await consultaOpcional(
    `SELECT id, tipo_objetivo, descricao, objetivo_principal,
            TO_CHAR(data_limite, 'YYYY-MM-DD') AS data_limite
       FROM objetivo_estudo
      WHERE usuario_id = $1 AND ativo = true
      ORDER BY objetivo_principal DESC NULLS LAST, id`,
    [usuarioId],
    "objetivo_estudo"
  );
  const objetivoIds = objetivos.map((o) => o.id);
  const objetivoDisciplinas = objetivoIds.length
    ? await consultaOpcional(
        `SELECT od.disciplina_id, d.nome, od.nivel_dificuldade, od.prioridade,
                od.tipo_dificuldade, od.observacao
           FROM objetivo_disciplina od
           JOIN disciplina d ON d.id = od.disciplina_id
          WHERE od.objetivo_id = ANY($1::int[])`,
        [objetivoIds],
        "objetivo_disciplina"
      )
    : [];

  // Currículo SESI da série/etapa/trilha do aluno.
  // Ensino Médio tem trilha (Alfa/Ômega); Fundamental não (trilha nula no plano).
  // O código da série do perfil (1-8) pode não ser o mesmo usado no plano_curso,
  // então tentamos o código do perfil e, se vier vazio, a numeração dentro do nível.
  const consultaCurriculo = (serie) =>
    consultaOpcional(
      `SELECT pc.disciplina_id, d.nome AS disciplina, pc.ano_letivo,
              cc.id AS conteudo_id, cc.titulo, cc.ordem, cc.carga_horaria
         FROM plano_curso pc
         JOIN disciplina d ON d.id = pc.disciplina_id
         LEFT JOIN conteudo_curricular cc ON cc.plano_curso_id = pc.id
        WHERE pc.ativo = true
          AND pc.serie::text = $1::text
          AND ($2::int IS NULL OR pc.etapa = $2::int)
          AND (pc.trilha IS NULL OR $3::text IS NULL OR LOWER(pc.trilha) = LOWER($3::text))
        ORDER BY pc.ano_letivo DESC, d.nome, cc.ordem`,
      [String(serie), perfil.etapa_sesi ?? null, perfil.trilha_sesi ?? null],
      "currículo SESI"
    );

  let curriculoLinhas = [];
  if (perfil.serie) {
    const candidatas = [String(perfil.serie)];
    const alt = SERIE_ALTERNATIVA[Number(perfil.serie)];
    if (alt) candidatas.push(String(alt));
    for (const serie of candidatas) {
      curriculoLinhas = await consultaCurriculo(serie);
      if (curriculoLinhas.some((l) => l.conteudo_id)) break;
    }
    if (!curriculoLinhas.some((l) => l.conteudo_id)) {
      console.warn(
        `Assistente IA: nenhum conteúdo curricular encontrado para o usuário ${usuarioId} ` +
          `(serie=${perfil.serie}, etapa=${perfil.etapa_sesi}, trilha=${perfil.trilha_sesi}).`
      );
    }
  }

  // Calendário do aluno (provas, tarefas, eventos, metas) ainda não concluídos.
  const eventos = await consultaOpcional(
    `SELECT ci.tipo, ci.subtipo, ci.titulo, ci.prioridade, d.nome AS disciplina,
            TO_CHAR(ci.data_inicio, 'YYYY-MM-DD') AS data,
            TO_CHAR(ci.hora_inicio, 'HH24:MI') AS hora_inicio,
            TO_CHAR(ci.hora_fim, 'HH24:MI') AS hora_fim,
            EXTRACT(ISODOW FROM ci.data_inicio)::int AS dia_iso
       FROM calendario_item ci
       LEFT JOIN disciplina d ON d.id = ci.disciplina_id
      WHERE ci.usuario_id = $1
        AND ci.concluido = false
        AND ci.data_inicio >= CURRENT_DATE
        AND ci.data_inicio < CURRENT_DATE + INTERVAL '30 days'
      ORDER BY ci.data_inicio, ci.hora_inicio NULLS LAST
      LIMIT 20`,
    [usuarioId],
    "calendario_item"
  );

  // ---------- disponibilidade ----------
  // Fonte: perfil_tempo_estudo (dias, tempo por dia, período) + rotina (bloco e intervalo).
  let dias = (tempo?.dias_disponiveis || []).map((d) => DIA_TEMPO_PARA_CURTO[d]).filter(Boolean);

  if (tempo?.fim_semana === "nao") dias = dias.filter((d) => d !== "sab" && d !== "dom");
  if (tempo?.fim_semana === "somenteSabado") dias = dias.filter((d) => d !== "dom");
  if (tempo?.fim_semana === "somenteDomingo") dias = dias.filter((d) => d !== "sab");
  dias = DIAS_ORDEM.filter((d) => dias.includes(d));

  const minutosPorDia = tempo?.tempo_disponivel_minutos || null;
  const periodo = tempo?.periodo_preferido || PERIODO_CRON[rotina?.preferencia_periodo] || null;
  const blocoFoco = rotina?.duracao_bloco_min || 45;
  const intervalo = rotina?.intervalo_min || 10;

  const janelas = {};
  for (const dia of dias) {
    const bloqueados = itensRotina
      .filter((i) => Number(i.dia_semana) === DIA_NUM[dia] && i.bloqueia_estudo)
      .map((i) => {
        const ini = hhmmParaMin(i.hora_inicio);
        const fim = hhmmParaMin(i.hora_fim);
        if (ini == null || fim == null) return null;
        const desloc = Number(i.tempo_deslocamento_min) || 0;
        return [ini - desloc, fim + desloc];
      })
      .filter(Boolean);

    const livres = subtrairIntervalos(INICIO_DIA_MIN, FIM_DIA_MIN, bloqueados).filter(
      ([i, f]) => f - i >= blocoFoco
    );
    const faixa = PERIODO_FAIXA[periodo];
    const preferidas = faixa ? intersectar(livres, faixa).filter(([i, f]) => f - i >= blocoFoco) : [];
    const fmt = (lista) => lista.map(([i, f]) => `${minParaHHMM(i)}-${minParaHHMM(f)}`);
    janelas[dia] = { preferidas: fmt(preferidas), livres: fmt(livres) };
  }

  // ---------- disciplinas prioritárias ----------
  const prioridades = new Map();
  const somar = (id, nome, extra) => {
    if (!id) return;
    const atual = prioridades.get(id) || { disciplina_id: id, nome, dificuldades: [], observacoes: [] };
    if (extra.dificuldades) atual.dificuldades.push(...extra.dificuldades);
    if (extra.observacao) atual.observacoes.push(extra.observacao);
    if (extra.nivel) atual.nivel = Math.max(atual.nivel || 0, Number(extra.nivel));
    if (extra.prioridade) atual.prioridade = Math.min(atual.prioridade || 99, Number(extra.prioridade));
    prioridades.set(id, atual);
  };
  dificuldades.forEach((d) =>
    somar(d.disciplina_id, d.nome, {
      dificuldades: [d.conteudo_1, d.conteudo_2, d.conteudo_3].filter(Boolean),
    })
  );
  objetivoDisciplinas.forEach((d) =>
    somar(d.disciplina_id, d.nome, {
      nivel: d.nivel_dificuldade,
      prioridade: d.prioridade,
      observacao: d.observacao,
      dificuldades: d.tipo_dificuldade ? [d.tipo_dificuldade] : [],
    })
  );

  // ---------- currículo (pega a versão mais recente por disciplina; limita o tamanho) ----------
  const anoPorDisciplina = new Map();
  curriculoLinhas.forEach((l) => {
    if (!anoPorDisciplina.has(l.disciplina_id)) anoPorDisciplina.set(l.disciplina_id, l.ano_letivo);
  });
  const prioritarias = new Set(prioridades.keys());
  const contagem = new Map();
  const conteudos = curriculoLinhas
    .filter((l) => l.conteudo_id && l.ano_letivo === anoPorDisciplina.get(l.disciplina_id))
    .sort((a, b) => Number(prioritarias.has(b.disciplina_id)) - Number(prioritarias.has(a.disciplina_id)))
    .filter((l) => {
      const n = (contagem.get(l.disciplina_id) || 0) + 1;
      contagem.set(l.disciplina_id, n);
      return n <= (prioritarias.has(l.disciplina_id) ? 10 : 5);
    })
    .slice(0, 60)
    .map((l) => ({
      conteudo_id: l.conteudo_id,
      disciplina_id: l.disciplina_id,
      disciplina: l.disciplina,
      titulo: l.titulo,
      carga_horaria: l.carga_horaria,
    }));

  const objetivoTexto =
    OBJETIVO_LABELS[perfil.objetivo_geral] ||
    OBJETIVO_LABELS[objetivoPlano?.objetivo] ||
    perfil.objetivo_geral ||
    null;

  const blocosPorDia =
    minutosPorDia && blocoFoco
      ? Math.max(1, Math.floor((minutosPorDia + intervalo) / (blocoFoco + intervalo)))
      : null;

  return {
    data_hoje: new Date().toISOString().slice(0, 10),
    aluno: limpar({
      nome: String(perfil.nome || "").split(" ")[0],
      serie: SERIE_LABELS[perfil.serie] || perfil.serie,
      etapa_sesi: perfil.etapa_sesi,
      trilha_sesi: perfil.trilha_sesi,
      rede_ensino: REDE_LABELS[perfil.rede_ensino] || perfil.rede_ensino,
      curso_desejado: perfil.curso_desejado,
      universidade_desejada: perfil.universidade_desejada,
      tipo_universidade: REDE_LABELS[perfil.tipo_universidade] || perfil.tipo_universidade,
      objetivo_geral: objetivoTexto,
      objetivo_detalhe: objetivoPlano?.objetivo_outro,
      disciplina_que_nao_estuda: perfil.nao_estuda_nenhuma ? null : perfil.disciplina_nao_estuda,
      nao_estuda_nenhuma_disciplina: perfil.nao_estuda_nenhuma ? true : null,
      motivo_nao_estuda: perfil.motivo_nao_estuda,
    }),
    objetivos: objetivos.map((o) =>
      limpar({
        tipo: o.tipo_objetivo,
        descricao: o.descricao,
        principal: o.objetivo_principal ? true : null,
        data_limite: o.data_limite,
      })
    ),
    disponibilidade: limpar({
      dias_disponiveis: dias.map((d) => DIA_LABELS[d]),
      minutos_por_dia_maximo: minutosPorDia,
      max_blocos_por_dia: blocosPorDia,
      periodo_preferido: periodo,
      bloco_foco_min: blocoFoco,
      intervalo_min: intervalo,
      tempo_estudo_atual_min_por_dia: tempo?.tempo_atual_minutos,
      periodo_livre_informado: tempo?.periodo_livre,
      janelas,
    }),
    disciplinas_prioritarias: [...prioridades.values()].map((p) =>
      limpar({
        disciplina_id: p.disciplina_id,
        nome: p.nome,
        dificuldades: [...new Set(p.dificuldades)],
        nivel_dificuldade: p.nivel,
        prioridade: p.prioridade,
        observacoes: p.observacoes,
      })
    ),
    conteudos_curriculares: conteudos,
    eventos_proximos: eventos.map((e) =>
      limpar({
        tipo: e.tipo,
        subtipo: e.subtipo,
        titulo: e.titulo,
        disciplina: e.disciplina,
        prioridade: e.prioridade,
        data: e.data,
        hora_inicio: e.hora_inicio,
        hora_fim: e.hora_fim,
        dia_da_semana: DIA_LABELS[DIAS_ORDEM[(e.dia_iso || 1) - 1]],
      })
    ),
    // Usado só no backend para validar a resposta:
    _dias: dias,
  };
}

const SYSTEM_ASSISTENTE = `Você é um orientador de estudos de uma plataforma para estudantes do SESI.
Monte um cronograma semanal de estudos PERSONALIZADO usando somente o contexto JSON recebido.

Regras:
- Use APENAS os dias de "dias_disponiveis". Nos demais dias, devolva "rotina": [] e um resumo curto de descanso.
- Cada atividade deve começar dentro de uma janela de "disponibilidade.janelas" do dia. Dê preferência às "preferidas"; use "livres" se precisar.
- Cada bloco tem "bloco_foco_min" minutos, com "intervalo_min" minutos de pausa entre blocos consecutivos.
- A soma dos blocos de um dia não pode passar de "minutos_por_dia_maximo" nem de "max_blocos_por_dia" blocos.
- Priorize "disciplinas_prioritarias" (as com "nivel_dificuldade" ou "prioridade" mais altos primeiro), trabalhando primeiro os assuntos listados em "dificuldades". Coloque-as nos melhores horários (janelas preferidas).
- Escolha os assuntos de estudo a partir de "conteudos_curriculares" e, quando usar um deles, informe "conteudo_id" e "disciplina_id" exatos.
- Se "disciplina_que_nao_estuda" estiver preenchida, inclua ao menos um bloco leve dessa disciplina na semana.
- Considere "objetivos" e "data_limite" para definir a intensidade. Evite estudar em cima de "eventos_proximos" (veja "dia_da_semana"); se houver prova próxima, reforce a matéria correspondente. "data_hoje" é a data de hoje.
- Não invente compromissos, matérias ou horários fora do contexto. Se faltar informação, faça algo simples e equilibrado.
- Varie os métodos de estudo (resumo, exercícios, revisão espaçada) no texto da atividade.

Responda SOMENTE com um JSON válido, sem markdown e sem texto extra, neste formato exato:
{
  "Segunda-feira": {
    "resumo": "uma frase curta com o foco do dia",
    "rotina": [
      { "horario": "19:00", "atividade": "Matemática - exercícios de função afim", "duracao_min": 45, "disciplina_id": 3, "conteudo_id": 41 }
    ]
  },
  "Terça-feira": { "resumo": "...", "rotina": [] },
  "Quarta-feira": { "resumo": "...", "rotina": [] },
  "Quinta-feira": { "resumo": "...", "rotina": [] },
  "Sexta-feira": { "resumo": "...", "rotina": [] },
  "Sábado": { "resumo": "...", "rotina": [] },
  "Domingo": { "resumo": "...", "rotina": [] }
}
"disciplina_id" e "conteudo_id" podem ser null quando a atividade não vier do currículo.`;

// Extrai o objeto JSON da resposta, mesmo que venha com crases ou texto em volta.
function extrairJson(texto) {
  const inicio = texto.indexOf("{");
  const fim = texto.lastIndexOf("}");
  if (inicio === -1 || fim <= inicio) throw new Error("JSON não encontrado");
  return JSON.parse(texto.slice(inicio, fim + 1));
}

// Garante os 7 dias e que dias indisponíveis fiquem vazios (a tela depende disso).
function normalizarPlano(bruto, diasDisponiveis) {
  const plano = {};
  for (const dia of DIAS_ORDEM) {
    const nome = DIA_LABELS[dia];
    const item = bruto?.[nome] || {};
    const disponivel = diasDisponiveis.includes(dia);
    const rotina = disponivel && Array.isArray(item.rotina)
      ? item.rotina
          .filter((r) => r && r.horario && r.atividade)
          .map((r) => ({
            horario: String(r.horario).slice(0, 5),
            atividade: String(r.atividade),
            duracao_min: Number.isFinite(Number(r.duracao_min)) ? Number(r.duracao_min) : null,
            disciplina_id: Number.isInteger(r.disciplina_id) ? r.disciplina_id : null,
            conteudo_id: Number.isInteger(r.conteudo_id) ? r.conteudo_id : null,
          }))
          .sort((a, b) => a.horario.localeCompare(b.horario))
      : [];
    plano[nome] = {
      resumo: typeof item.resumo === "string" && item.resumo
        ? item.resumo
        : disponivel ? "Dia de estudo." : "Dia de descanso.",
      rotina,
    };
  }
  return plano;
}

// Gera (ou regenera) o cronograma personalizado com o Claude e salva em sugestoes_ia.
app.post("/api/assistente-ia/:usuarioId", async (req, res) => {
  const usuarioId = parseInt(req.params.usuarioId, 10);

  if (isNaN(usuarioId)) {
    return res.status(400).json({ erro: "ID de usuário inválido." });
  }

  if (!process.env.ANTHROPIC_API_KEY) {
    return res
      .status(500)
      .json({ erro: "ANTHROPIC_API_KEY não configurada no servidor." });
  }

  try {
    const contexto = await montarContextoAluno(usuarioId);

    if (!contexto) {
      return res.status(404).json({ erro: "Usuário não encontrado." });
    }

    if (contexto._dias.length === 0) {
      return res.status(404).json({
        erro: "Informe os dias em que você pode estudar (Tempo de Estudo, no seu perfil) antes de gerar o Assistente IA.",
      });
    }

    const { _dias: diasDisponiveis, ...contextoParaIA } = contexto;

    const resposta = await anthropic.messages.create({
      model: process.env.ANTHROPIC_MODEL || "claude-haiku-4-5-20251001",
      max_tokens: 4096,
      system: SYSTEM_ASSISTENTE,
      messages: [
        {
          role: "user",
          content: `Contexto do aluno:\n${JSON.stringify(contextoParaIA)}`,
        },
      ],
    });

    if (resposta.stop_reason === "max_tokens") {
      return res.status(502).json({ erro: "A resposta da IA foi cortada. Tente gerar novamente." });
    }

    const textoResposta = (resposta.content || [])
      .filter((b) => b.type === "text")
      .map((b) => b.text)
      .join("")
      .trim();

    let plano;
    try {
      plano = normalizarPlano(extrairJson(textoResposta), diasDisponiveis);
    } catch (e) {
      console.error("Erro no JSON retornado pela IA:", textoResposta);
      return res
        .status(502)
        .json({ erro: "A IA não respondeu no formato JSON correto." });
    }

    await pool.query(
      `INSERT INTO sugestoes_ia (usuario_id, sugestao)
       VALUES ($1, $2)
       ON CONFLICT (usuario_id) DO UPDATE SET
         sugestao = EXCLUDED.sugestao,
         gerado_em = NOW()`,
      [usuarioId, JSON.stringify(plano)]
    );

    res.json({ sucesso: true, plano });
  } catch (err) {
    console.error("Erro ao gerar cronograma com IA:", err);
    const status = err?.status === 401 ? 500 : err?.status === 429 ? 429 : 502;
    const msg =
      err?.status === 401
        ? "Chave da API do Claude inválida."
        : err?.status === 429
        ? "Muitas requisições à IA. Tente novamente em instantes."
        : "Erro ao gerar cronograma com IA.";
    res.status(status).json({ erro: msg });
  }
});

// =====================================================
// CONTATO - SALVAR MENSAGEM
// =====================================================
app.post('/api/contato', async (req, res) => {
    try {
        const { nome, email, telefone, assunto, mensagem } = req.body;

        // Campos obrigatórios
        if (!nome || !email || !assunto || !mensagem) {
            return res.status(400).json({
                success: false,
                erro: 'Preencha todos os campos obrigatórios.'
            });
        }

        // Validação básica de e-mail
        const emailValido = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (!emailValido.test(email)) {
            return res.status(400).json({
                success: false,
                erro: 'Informe um e-mail válido.'
            });
        }

        // Validação do telefone, caso tenha sido preenchido
        if (telefone) {
            const somenteNumeros = telefone.replace(/\D/g, '');

            if (somenteNumeros.length !== 10 && somenteNumeros.length !== 11) {
                return res.status(400).json({
                    success: false,
                    erro: 'Informe um telefone válido com DDD.'
                });
            }
        }

        // Limite da mensagem
        if (mensagem.length > 1500) {
            return res.status(400).json({
                success: false,
                erro: 'A mensagem deve possuir no máximo 1500 caracteres.'
            });
        }

        // Salva no banco
        const resultado = await pool.query(
            `
            INSERT INTO mensagens_contato
                (nome, email, telefone, assunto, mensagem)
            VALUES
                ($1, $2, $3, $4, $5)
            RETURNING id, criado_em
            `,
            [
                nome.trim(),
                email.trim().toLowerCase(),
                telefone ? telefone.trim() : null,
                assunto,
                mensagem.trim()
            ]
        );

        return res.status(201).json({
            success: true,
            mensagem: 'Mensagem enviada com sucesso!',
            id: resultado.rows[0].id
        });

    } catch (erro) {
        console.error('Erro ao salvar mensagem de contato:', erro);

        return res.status(500).json({
            success: false,
            erro: 'Não foi possível enviar a mensagem.'
        });
    }
});



// Busca a última sugestão de IA já gerada e salva para este usuário.
app.get("/api/assistente-ia/:usuarioId", async (req, res) => {
  const usuarioId = parseInt(req.params.usuarioId, 10);

  if (isNaN(usuarioId)) {
    return res.status(400).json({ erro: "ID de usuário inválido." });
  }

  try {
    const resultado = await pool.query(
      `SELECT sugestao, gerado_em FROM sugestoes_ia WHERE usuario_id = $1`,
      [usuarioId]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({ erro: "Nenhuma sugestão gerada ainda." });
    }

    let plano;
    try {
      plano = JSON.parse(resultado.rows[0].sugestao);
    } catch (e) {
      return res.status(500).json({ erro: "Sugestão salva está corrompida." });
    }

    res.json({
      plano,
      geradoEm: resultado.rows[0].gerado_em,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro ao buscar sugestão salva." });
  }
});

const PORT = process.env.PORT || 3000;

// ======================================================
// ESTATÍSTICAS PÚBLICAS DO ROTA DO SUCESSO
// ======================================================

app.get("/api/estatisticas", async (req, res) => {
  try {

    // Total de usuários ativos
    const resultadoUsuarios = await pool.query(`
      SELECT COUNT(*)::int AS total_usuarios
      FROM usuario
      WHERE status = 'ativo'
    `);

    // Total de horas planejadas nos planos de estudo
    const resultadoHoras = await pool.query(`
      SELECT
        COALESCE(
          ROUND(SUM(duracao_min)::numeric / 60, 1),
          0
        ) AS total_horas
      FROM plano_estudo_item
    `);

    res.json({
      sucesso: true,
      totalUsuarios: resultadoUsuarios.rows[0].total_usuarios,
      horasPlanejadas: Number(resultadoHoras.rows[0].total_horas)
    });

  } catch (erro) {

    console.error("Erro ao buscar estatísticas:", erro);

    res.status(500).json({
      sucesso: false,
      erro: "Erro ao buscar estatísticas."
    });

  }
});

// ======================================================
// ROTINA DIÁRIA - CONSULTAR ROTINA DO USUÁRIO
// ======================================================

app.get("/api/rotina/:usuarioId", async (req, res) => {
  const { usuarioId } = req.params;

  try {

    // Busca a rotina ativa mais recente do usuário
    const resultadoRotina = await pool.query(
      `
      SELECT
        id,
        usuario_id,
        nome,
        preferencia_periodo,
        duracao_bloco_min,
        intervalo_min,
        rotina_variavel,
        ativa,
        criada_em,
        atualizada_em
      FROM rotina
      WHERE usuario_id = $1
        AND ativa = true
      ORDER BY atualizada_em DESC, criada_em DESC
      LIMIT 1
      `,
      [usuarioId]
    );

    // Usuário ainda não possui rotina
    if (resultadoRotina.rows.length === 0) {
      return res.json({
        sucesso: true,
        existe: false,
        rotina: null
      });
    }

    const rotina = resultadoRotina.rows[0];

    // Busca os compromissos da rotina
    const resultadoItens = await pool.query(
      `
      SELECT
        id,
        rotina_id,
        dia_semana,
        hora_inicio,
        hora_fim,
        tipo_atividade,
        descricao,
        tempo_deslocamento_min,
        fixo,
        bloqueia_estudo
      FROM rotina_item
      WHERE rotina_id = $1
      ORDER BY dia_semana ASC, hora_inicio ASC
      `,
      [rotina.id]
    );

    return res.json({
      sucesso: true,
      existe: true,
      rotina: {
        ...rotina,
        itens: resultadoItens.rows
      }
    });

  } catch (erro) {

    console.error("Erro ao consultar rotina:", erro);

    return res.status(500).json({
      sucesso: false,
      erro: "Erro ao consultar a rotina diária.",
      detalhe: erro.message
    });

  }
});

// =====================================================
// SALVAR ROTINA DIÁRIA
// =====================================================

app.post("/api/rotina", async (req, res) => {

    const { usuarioId, itens } = req.body;

    if (!usuarioId) {
        return res.status(400).json({
            sucesso: false,
            erro: "Usuário não informado."
        });
    }

    if (!Array.isArray(itens) || itens.length === 0) {
        return res.status(400).json({
            sucesso: false,
            erro: "Cadastre pelo menos um compromisso."
        });
    }

    const client = await pool.connect();

    try {

        await client.query("BEGIN");

        // Verifica se o usuário já possui rotina ativa
        const rotinaExistente = await client.query(
            `SELECT id
             FROM rotina
             WHERE usuario_id = $1
             AND ativa = true
             LIMIT 1`,
            [usuarioId]
        );

        let rotinaId;

        if (rotinaExistente.rows.length > 0) {

            rotinaId = rotinaExistente.rows[0].id;

            // Atualiza a data da rotina
            await client.query(
                `UPDATE rotina
                 SET atualizada_em = CURRENT_TIMESTAMP
                 WHERE id = $1`,
                [rotinaId]
            );

            // Remove os itens antigos para gravar a versão atual
            await client.query(
                `DELETE FROM rotina_item
                 WHERE rotina_id = $1`,
                [rotinaId]
            );

        } else {

            // Cria a rotina
            const novaRotina = await client.query(
                `INSERT INTO rotina
                    (usuario_id, nome, ativa, criada_em, atualizada_em)
                 VALUES
                    ($1, $2, true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                 RETURNING id`,
                [
                    usuarioId,
                    "Rotina diária"
                ]
            );

            rotinaId = novaRotina.rows[0].id;
        }

        // Insere todos os compromissos
        for (const item of itens) {

            await client.query(
                `INSERT INTO rotina_item
                    (
                        rotina_id,
                        dia_semana,
                        hora_inicio,
                        hora_fim,
                        tipo_atividade,
                        descricao,
                        fixo,
                        bloqueia_estudo
                    )
                 VALUES
                    ($1, $2, $3, $4, $5, $6, true, true)`,
                [
                    rotinaId,
                    item.diaSemana,
                    item.horaInicio || null,
                    item.horaFim || null,
                    item.tipoAtividade,
                    item.descricao
                ]
            );
        }

        await client.query("COMMIT");

        res.json({
            sucesso: true,
            mensagem: "Rotina salva com sucesso!",
            rotinaId
        });

    } catch (erro) {

        await client.query("ROLLBACK");

        console.error("Erro ao salvar rotina:", erro);

        res.status(500).json({
            sucesso: false,
            erro: "Erro ao salvar rotina."
        });

    } finally {

        client.release();
    }
});

// =====================================================
// EXCLUIR ROTINA DIÁRIA
// =====================================================

app.delete("/api/rotina/:usuarioId", async (req, res) => {

    const usuarioId = Number(req.params.usuarioId);

    if (!usuarioId) {
        return res.status(400).json({
            sucesso: false,
            erro: "Usuário não informado."
        });
    }

    const client = await pool.connect();

    try {

        await client.query("BEGIN");

        // Procura a rotina ativa do usuário
        const resultadoRotina = await client.query(
            `SELECT id
             FROM rotina
             WHERE usuario_id = $1
             AND ativa = true
             LIMIT 1`,
            [usuarioId]
        );

        if (resultadoRotina.rows.length === 0) {

            await client.query("ROLLBACK");

            return res.status(404).json({
                sucesso: false,
                erro: "Nenhuma rotina encontrada."
            });
        }

        const rotinaId = resultadoRotina.rows[0].id;

        // Primeiro remove os compromissos
        await client.query(
            `DELETE FROM rotina_item
             WHERE rotina_id = $1`,
            [rotinaId]
        );

        // Depois remove a rotina
        await client.query(
            `DELETE FROM rotina
             WHERE id = $1`,
            [rotinaId]
        );

        await client.query("COMMIT");

        return res.json({
            sucesso: true,
            mensagem: "Rotina excluída com sucesso!"
        });

    } catch (erro) {

        await client.query("ROLLBACK");

        console.error("Erro ao excluir rotina:", erro);

        return res.status(500).json({
            sucesso: false,
            erro: "Erro ao excluir rotina."
        });

    } finally {

        client.release();
    }
});

// =====================================================
// FRASES MOTIVACIONAIS - CADASTRAR NOVA FRASE
// =====================================================
app.post("/api/frases-motivacionais", async (req, res) => {

    const { frase, autor } = req.body;

    // Validação
    if (!frase || !frase.trim()) {
        return res.status(400).json({
            sucesso: false,
            erro: "A frase é obrigatória."
        });
    }

    try {

        const resultado = await pool.query(
            `
            INSERT INTO frase_motivacional
                (frase, autor)
            VALUES
                ($1, $2)
            RETURNING
                id,
                frase,
                autor,
                ativa,
                criado_em;
            `,
            [
                frase.trim(),
                autor?.trim() || null
            ]
        );

        return res.status(201).json({
            sucesso: true,
            mensagem: "Frase cadastrada com sucesso!",
            frase: resultado.rows[0]
        });

    } catch (erro) {

        console.error("❌ ERRO AO CADASTRAR FRASE:");
        console.error(erro);

        return res.status(500).json({
            sucesso: false,
            erro: "Erro ao cadastrar a frase.",
            detalhe: erro.message
        });
    }

});

// =====================================================
// FRASE MOTIVACIONAL ALEATÓRIA
// =====================================================

app.get("/api/frase-aleatoria", async (req, res) => {
  try {

    const resultado = await pool.query(`
      SELECT id, frase, autor
      FROM frase_motivacional
      WHERE ativa = true
      ORDER BY RANDOM()
      LIMIT 1
    `);

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        sucesso: false,
        erro: "Nenhuma frase motivacional disponível."
      });
    }

    return res.json({
      sucesso: true,
      frase: resultado.rows[0]
    });

  } catch (erro) {

    console.error("❌ ERRO AO BUSCAR FRASE MOTIVACIONAL:");
    console.error(erro);

    return res.status(500).json({
      sucesso: false,
      erro: "Erro ao buscar frase motivacional.",
      detalhe: erro.message
    });
  }
});

// =====================================================
// ADMIN - FRASES MOTIVACIONAIS
// =====================================================


// ---------- LISTAR TODAS AS FRASES ----------
app.get("/api/admin/frases", async (req, res) => {
  try {

    const resultado = await pool.query(`
      SELECT id, frase, autor, ativa
      FROM frase_motivacional
      ORDER BY id ASC
    `);

    res.json({
      sucesso: true,
      frases: resultado.rows
    });

  } catch (erro) {

    console.error("❌ ERRO AO LISTAR FRASES:");
    console.error(erro);

    res.status(500).json({
      sucesso: false,
      erro: "Erro ao buscar frases motivacionais.",
      detalhe: erro.message
    });
  }
});


// ---------- ADICIONAR NOVA FRASE ----------
app.post("/api/admin/frases", async (req, res) => {

  const { frase, autor } = req.body;

  if (!frase || !autor) {
    return res.status(400).json({
      sucesso: false,
      erro: "Informe a frase e o autor."
    });
  }

  try {

    const resultado = await pool.query(
      `
      INSERT INTO frase_motivacional
        (frase, autor, ativa)
      VALUES
        ($1, $2, true)
      RETURNING id, frase, autor, ativa
      `,
      [
        frase.trim(),
        autor.trim()
      ]
    );

    res.status(201).json({
      sucesso: true,
      mensagem: "Frase cadastrada com sucesso!",
      frase: resultado.rows[0]
    });

  } catch (erro) {

    console.error("❌ ERRO AO CADASTRAR FRASE:");
    console.error(erro);

    res.status(500).json({
      sucesso: false,
      erro: "Erro ao cadastrar frase motivacional.",
      detalhe: erro.message
    });
  }
});


// ---------- EDITAR FRASE ----------
app.put("/api/admin/frases/:id", async (req, res) => {

  const id = parseInt(req.params.id, 10);
  const { frase, autor } = req.body;

  if (isNaN(id)) {
    return res.status(400).json({
      sucesso: false,
      erro: "ID inválido."
    });
  }

  if (!frase || !autor) {
    return res.status(400).json({
      sucesso: false,
      erro: "Informe a frase e o autor."
    });
  }

  try {

    const resultado = await pool.query(
      `
      UPDATE frase_motivacional
      SET
        frase = $1,
        autor = $2
      WHERE id = $3
      RETURNING id, frase, autor, ativa
      `,
      [
        frase.trim(),
        autor.trim(),
        id
      ]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        sucesso: false,
        erro: "Frase não encontrada."
      });
    }

    res.json({
      sucesso: true,
      mensagem: "Frase atualizada com sucesso!",
      frase: resultado.rows[0]
    });

  } catch (erro) {

    console.error("❌ ERRO AO EDITAR FRASE:");
    console.error(erro);

    res.status(500).json({
      sucesso: false,
      erro: "Erro ao editar frase motivacional.",
      detalhe: erro.message
    });
  }
});


// ---------- EXCLUIR FRASE ----------
app.delete("/api/admin/frases/:id", async (req, res) => {

  const id = parseInt(req.params.id, 10);

  if (isNaN(id)) {
    return res.status(400).json({
      sucesso: false,
      erro: "ID inválido."
    });
  }

  try {

    const resultado = await pool.query(
      `
      DELETE FROM frase_motivacional
      WHERE id = $1
      RETURNING id
      `,
      [id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({
        sucesso: false,
        erro: "Frase não encontrada."
      });
    }

    res.json({
      sucesso: true,
      mensagem: "Frase excluída com sucesso!"
    });

  } catch (erro) {

    console.error("❌ ERRO AO EXCLUIR FRASE:");
    console.error(erro);

    res.status(500).json({
      sucesso: false,
      erro: "Erro ao excluir frase motivacional.",
      detalhe: erro.message
    });
  }
});

// ============================================================
// EQUIPE DO SISTEMA - VALIDAR CÓDIGO DE SEGURANÇA
// ============================================================

app.post("/api/equipe/validar-codigo", async (req, res) => {

    try {

        const codigo = String(req.body.codigo || '').trim();


        // ----------------------------------------------------
        // 1. VALIDAR FORMATO
        // ----------------------------------------------------

        if (!/^\d{6}$/.test(codigo)) {

            return res.status(400).json({
                sucesso: false,
                erro: "O código deve possuir exatamente 6 números."
            });

        }


        // ----------------------------------------------------
        // 2. BUSCAR SOMENTE INTEGRANTES ATIVOS
        // ----------------------------------------------------

        const resultado = await pool.query(`
            SELECT
                id,
                nome,
                equipe,
                codigo_hash
            FROM equipe_sistema
            WHERE ativo = TRUE
        `);


        // ----------------------------------------------------
        // 3. COMPARAR O CÓDIGO COM OS HASHES
        // ----------------------------------------------------

        let integranteEncontrado = null;


        for (const integrante of resultado.rows) {

            const codigoCorreto = await bcrypt.compare(
                codigo,
                integrante.codigo_hash
            );


            if (codigoCorreto) {

                integranteEncontrado = integrante;

                break;

            }

        }


        // ----------------------------------------------------
        // 4. CÓDIGO NÃO ENCONTRADO
        // ----------------------------------------------------

        if (!integranteEncontrado) {

            return res.status(401).json({
                sucesso: false,
                erro: "Código de segurança inválido."
            });

        }


        // ----------------------------------------------------
        // 5. CÓDIGO CORRETO
        // ----------------------------------------------------

        return res.json({

            sucesso: true,

            integrante: {
                id: integranteEncontrado.id,
                nome: integranteEncontrado.nome,
                equipe: integranteEncontrado.equipe
            }

        });


    } catch (erro) {

        console.error(
            "❌ Erro ao validar código da equipe:",
            erro
        );


        return res.status(500).json({
            sucesso: false,
            erro: "Erro interno ao validar o código de segurança."
        });

    }

});

// =====================================================
// CADASTRAR VALIDAÇÃO OU ERRO
// =====================================================

app.post("/api/validacoes-erros", async (req, res) => {

    try {

        const {
            tipo,
            descricao,
            importancia,
            inserido_por
        } = req.body;


        // Validação dos campos obrigatórios
        if (!tipo || !descricao || !importancia || !inserido_por) {
            return res.status(400).json({
                erro: "Todos os campos são obrigatórios."
            });
        }


        // Aceita somente os dois tipos previstos
        if (!["validacao", "erro"].includes(tipo)) {
            return res.status(400).json({
                erro: "Tipo de registro inválido."
            });
        }


        // Aceita somente os graus previstos
        if (!["baixa", "media", "alta", "critica"].includes(importancia)) {
            return res.status(400).json({
                erro: "Grau de importância inválido."
            });
        }


        const resultado = await pool.query(
            `
            INSERT INTO validacoes_erros
                (
                    tipo,
                    descricao,
                    importancia,
                    inserido_por
                )
            VALUES ($1, $2, $3, $4)

            RETURNING
                id,
                tipo,
                descricao,
                importancia,
                inserido_por,
                criado_em,
                resolvido
            `,
            [
                tipo,
                descricao.trim(),
                importancia,
                inserido_por
            ]
        );


        console.log(
            "✅ Validação/erro cadastrado:",
            resultado.rows[0]
        );


        return res.status(201).json({
            mensagem: "Registro cadastrado com sucesso.",
            registro: resultado.rows[0]
        });


    } catch (erro) {

        console.error(
            "❌ Erro ao cadastrar validação/erro:",
            erro
        );


        return res.status(500).json({
            erro: "Não foi possível cadastrar o registro."
        });

    }

});


// =====================================================
// MARCAR VALIDAÇÃO / ERRO COMO RESOLVIDO
// =====================================================

app.put("/api/validacoes-erros/:id/resolver", async (req, res) => {

    try {

        const id = Number(req.params.id);
        const { codigo } = req.body;


        // ID válido
        if (!Number.isInteger(id) || id <= 0) {

            return res.status(400).json({
                sucesso: false,
                erro: "Registro inválido."
            });

        }


        // Código com 6 dígitos
        if (!/^\d{6}$/.test(String(codigo || ""))) {

            return res.status(400).json({
                sucesso: false,
                erro: "Informe um código de segurança válido."
            });

        }


        // Busca integrantes ativos
        const resultadoEquipe = await pool.query(`
            SELECT
                id,
                nome,
                equipe,
                codigo_hash
            FROM equipe_sistema
            WHERE ativo = TRUE
            ORDER BY id
        `);


        let integranteIdentificado = null;


        // Compara o código informado com os hashes
        for (const integrante of resultadoEquipe.rows) {

            const codigoValido = await bcrypt.compare(
                String(codigo),
                integrante.codigo_hash
            );


            if (codigoValido) {

                integranteIdentificado = integrante;
                break;

            }

        }


        // Código não pertence a ninguém
        if (!integranteIdentificado) {

            return res.status(401).json({
                sucesso: false,
                erro: "Código de segurança inválido."
            });

        }


        // Marca como resolvido
        const resultado = await pool.query(
            `
            UPDATE validacoes_erros

            SET
                resolvido = TRUE,
                resolvido_em = CURRENT_TIMESTAMP,
                resolvido_por = $1,
                atualizado_em = CURRENT_TIMESTAMP

            WHERE id = $2
              AND resolvido = FALSE

            RETURNING
                id,
                tipo,
                descricao,
                importancia,
                resolvido,
                resolvido_em,
                resolvido_por
            `,
            [
                integranteIdentificado.id,
                id
            ]
        );


        if (resultado.rowCount === 0) {

            return res.status(404).json({
                sucesso: false,
                erro: "Registro não encontrado ou já marcado como resolvido."
            });

        }


        console.log(
            "🔧 Registro marcado como resolvido:",
            resultado.rows[0]
        );


        return res.json({

            sucesso: true,

            mensagem:
                "Registro marcado como resolvido com sucesso.",

            registro:
                resultado.rows[0],

            integrante: {
                id: integranteIdentificado.id,
                nome: integranteIdentificado.nome,
                equipe: integranteIdentificado.equipe
            }

        });


    } catch (erro) {

        console.error(
            "❌ Erro ao marcar registro como resolvido:",
            erro
        );


        return res.status(500).json({
            sucesso: false,
            erro: "Não foi possível concluir o registro."
        });

    }

});

// =====================================================
// LISTAR VALIDAÇÕES E ERROS
// =====================================================

app.get("/api/validacoes-erros", async (req, res) => {

    try {

        const resultado = await pool.query(`
            SELECT
                ve.id,
                ve.tipo,
                ve.descricao,
                ve.importancia,
                ve.criado_em,
                ve.resolvido,
                ve.resolvido_em,

                inseridor.nome AS inserido_por_nome,
                inseridor.equipe AS inserido_por_equipe,

                resolvedor.nome AS resolvido_por_nome,
                resolvedor.equipe AS resolvido_por_equipe

            FROM validacoes_erros ve

            INNER JOIN equipe_sistema inseridor
                ON inseridor.id = ve.inserido_por

            LEFT JOIN equipe_sistema resolvedor
                ON resolvedor.id = ve.resolvido_por

            ORDER BY
                ve.resolvido ASC,
                ve.criado_em DESC
        `);


        return res.json({
            sucesso: true,
            registros: resultado.rows
        });


    } catch (erro) {

        console.error(
            "❌ Erro ao carregar validações e erros:",
            erro
        );


        return res.status(500).json({
            sucesso: false,
            erro: "Não foi possível carregar as validações e erros."
        });

    }

});

// =====================================================
// EXCLUIR VALIDAÇÃO OU ERRO
// =====================================================

app.delete("/api/validacoes-erros/:id", async (req, res) => {

    try {

        const id = Number(req.params.id);

        // Verifica se o ID é válido
        if (!Number.isInteger(id) || id <= 0) {

            return res.status(400).json({
                sucesso: false,
                erro: "Registro inválido."
            });

        }


        const resultado = await pool.query(
            `
            DELETE FROM validacoes_erros
            WHERE id = $1
            RETURNING id, tipo, descricao
            `,
            [id]
        );


        // Nenhum registro encontrado
        if (resultado.rowCount === 0) {

            return res.status(404).json({
                sucesso: false,
                erro: "Registro não encontrado."
            });

        }


        console.log(
            "🗑️ Validação/erro excluído:",
            resultado.rows[0]
        );


        return res.json({
            sucesso: true,
            mensagem: "Registro excluído com sucesso.",
            registro: resultado.rows[0]
        });


    } catch (erro) {

        console.error(
            "❌ Erro ao excluir validação/erro:",
            erro
        );


        return res.status(500).json({
            sucesso: false,
            erro: "Não foi possível excluir o registro."
        });

    }

});

// =====================================================
// ALTERAR VALIDAÇÃO OU ERRO
// =====================================================

app.put("/api/validacoes-erros/:id", async (req, res) => {

    try {

        const id = Number(req.params.id);

        const {
            descricao,
            importancia
        } = req.body;


        // ID inválido
        if (!Number.isInteger(id) || id <= 0) {

            return res.status(400).json({
                sucesso: false,
                erro: "Registro inválido."
            });

        }


        // Campos obrigatórios
        if (!descricao || !descricao.trim() || !importancia) {

            return res.status(400).json({
                sucesso: false,
                erro: "Descrição e grau de importância são obrigatórios."
            });

        }


        // Importâncias permitidas
        if (!["baixa", "media", "alta", "critica"].includes(importancia)) {

            return res.status(400).json({
                sucesso: false,
                erro: "Grau de importância inválido."
            });

        }


        const resultado = await pool.query(
            `
            UPDATE validacoes_erros

            SET
                descricao = $1,
                importancia = $2,
                atualizado_em = CURRENT_TIMESTAMP

            WHERE id = $3

            RETURNING
                id,
                tipo,
                descricao,
                importancia,
                criado_em,
                atualizado_em
            `,
            [
                descricao.trim(),
                importancia,
                id
            ]
        );


        if (resultado.rowCount === 0) {

            return res.status(404).json({
                sucesso: false,
                erro: "Registro não encontrado."
            });

        }


        console.log(
            "✏️ Validação/erro alterado:",
            resultado.rows[0]
        );


        return res.json({
            sucesso: true,
            mensagem: "Registro alterado com sucesso.",
            registro: resultado.rows[0]
        });


    } catch (erro) {

        console.error(
            "❌ Erro ao alterar validação/erro:",
            erro
        );


        return res.status(500).json({
            sucesso: false,
            erro: "Não foi possível alterar o registro."
        });

    }

});

// =====================================================
// PLANO DE ESTUDO - OBJETIVOS PERMITIDOS
// =====================================================

const OBJETIVOS_PLANO_ESTUDO = new Set([
    "organizar_rotina",
    "melhorar_desempenho",
    "recuperar_dificuldades",
    "preparar_provas",
    "enem_vestibular",
    "criar_habito",
    "aprofundar_conhecimentos",
    "outro"
]);

// =====================================================
// PLANO DE ESTUDO - TIPOS DE PLANEJAMENTO
// =====================================================

const TIPOS_PLANEJAMENTO =
    new Set([
        "semanal",
        "mensal"
    ]);


// =====================================================
// PLANO DE ESTUDO - VERIFICAR PREPARAÇÃO
// =====================================================

app.get(
    "/api/plano-estudo/preparacao/:usuarioId",
    async (req, res) => {

        const usuarioId =
            parseInt(req.params.usuarioId, 10);


        if (
            !Number.isInteger(usuarioId) ||
            usuarioId <= 0
        ) {

            return res.status(400).json({
                sucesso: false,
                erro: "ID de usuário inválido."
            });

        }


        try {

            // ==========================================
            // CONFIRMA QUE O USUÁRIO EXISTE
            // ==========================================

            const usuario = await pool.query(
                `
                SELECT id
                FROM usuario
                WHERE id = $1
                `,
                [usuarioId]
            );


            if (usuario.rows.length === 0) {

                return res.status(404).json({
                    sucesso: false,
                    erro: "Usuário não encontrado."
                });

            }


            // ==========================================
            // VERIFICA ROTINA E PERFIL
            // ==========================================

            const status = await pool.query(
                `
                SELECT

                    EXISTS (
                        SELECT 1
                        FROM rotina r
                        WHERE r.usuario_id = $1
                          AND r.ativa = TRUE
                    )
                    AS rotina_preenchida,


                    EXISTS (
                        SELECT 1
                        FROM perfil_tempo_estudo pte
                        WHERE pte.usuario_id = $1
                    )
                    AS perfil_academico_preenchido

                `,
                [usuarioId]
            );


            // ==========================================
            // OBJETIVO JÁ SALVO
            // ==========================================

            const objetivoResultado =
                await pool.query(
                    `
                    SELECT
                        objetivo,
                        objetivo_outro,
                        tipo_planejamento

                    FROM plano_estudo_objetivo

                    WHERE usuario_id = $1
                    `,
                    [usuarioId]
                );


            const objetivoSalvo =
                objetivoResultado.rows[0] || null;


            const rotinaPreenchida =
                Boolean(
                    status.rows[0].rotina_preenchida
                );


            const perfilAcademicoPreenchido =
                Boolean(
                    status.rows[0]
                        .perfil_academico_preenchido
                );


            return res.json({

                sucesso: true,

                rotinaPreenchida,

                perfilAcademicoPreenchido,

                objetivo:
                    objetivoSalvo?.objetivo || "",

                objetivoOutro:
                objetivoSalvo?.objetivo_outro || "",
                    tipoPlanejamento:
                objetivoSalvo?.tipo_planejamento || "",
                    objetivoPreenchido:
                        Boolean(
                            objetivoSalvo?.objetivo
                        ),
                    tipoPlanejamentoPreenchido:
                TIPOS_PLANEJAMENTO.has(
                objetivoSalvo?.tipo_planejamento
                ),

podeGerar:
    rotinaPreenchida &&
    perfilAcademicoPreenchido &&
    Boolean(
        objetivoSalvo?.objetivo
    ) &&
    TIPOS_PLANEJAMENTO.has(
        objetivoSalvo?.tipo_planejamento
    )

            });


        } catch (erro) {

            console.error(
                "❌ Erro ao verificar preparação do plano:",
                erro
            );


            return res.status(500).json({
                sucesso: false,
                erro:
                    "Não foi possível verificar os dados do Plano de Estudo."
            });

        }

    }
);


// =====================================================
// PLANO DE ESTUDO - MONTAR PAYLOAD PARA IA
// =====================================================

async function montarPayloadPlanoEstudo(usuarioId) {

    // ==========================================
    // 1. PERFIL ACADÊMICO
    // ==========================================

    const perfilResultado =
        await pool.query(
            `
            SELECT

                pa.serie,
                pa.etapa_atual,
                pa.rede_ensino,

                pa.curso_desejado,
                pa.universidade_desejada,
                pa.tipo_universidade,

                pa.objetivo_geral,

                pa.trilha_sesi,
                pa.etapa_sesi,

                pa.nao_estuda_nenhuma,
                pa.motivo_nao_estuda,

                disciplina_nao_estuda.nome
                    AS disciplina_nao_estuda

            FROM perfil_academico pa

            LEFT JOIN disciplina
                AS disciplina_nao_estuda

                ON disciplina_nao_estuda.id =
                    pa.disciplina_nao_estuda_id

            WHERE pa.usuario_id = $1
            `,
            [usuarioId]
        );


    if (perfilResultado.rows.length === 0) {

        const erro =
            new Error(
                "Perfil Acadêmico não encontrado."
            );

        erro.status = 404;

        throw erro;

    }


    // ==========================================
    // 2. DIFICULDADES
    // ==========================================

    const dificuldadesResultado =
        await pool.query(
            `
            SELECT

                d.nome AS disciplina,

                pd.conteudo_1,
                pd.conteudo_2,
                pd.conteudo_3

            FROM perfil_dificuldade pd

            INNER JOIN disciplina d
                ON d.id = pd.disciplina_id

            WHERE pd.usuario_id = $1

            ORDER BY d.nome
            `,
            [usuarioId]
        );


    // ==========================================
    // 3. TEMPO DISPONÍVEL
    // ==========================================

    const tempoResultado =
        await pool.query(
            `
            SELECT

                tempo_atual_minutos,
                dias_disponiveis,
                periodo_preferido,
                tempo_disponivel_minutos,
                fim_semana,
                periodo_livre

            FROM perfil_tempo_estudo

            WHERE usuario_id = $1
            `,
            [usuarioId]
        );


    if (tempoResultado.rows.length === 0) {

        const erro =
            new Error(
                "Tempo disponível para estudos não encontrado."
            );

        erro.status = 400;

        throw erro;

    }


    // ==========================================
    // 4. OBJETIVO DO PLANO
    // ==========================================

    const objetivoResultado =
        await pool.query(
            `
            SELECT

                objetivo,
                objetivo_outro,
                tipo_planejamento

            FROM plano_estudo_objetivo

            WHERE usuario_id = $1
            `,
            [usuarioId]
        );


    if (objetivoResultado.rows.length === 0) {

        const erro =
            new Error(
                "Objetivo do Plano de Estudo não encontrado."
            );

        erro.status = 400;

        throw erro;

    }


    // ==========================================
    // 5. ROTINA ATIVA
    // ==========================================

    const rotinaResultado =
        await pool.query(
            `
            SELECT

                id,
                preferencia_periodo,
                duracao_bloco_min,
                intervalo_min,
                rotina_variavel

            FROM rotina

            WHERE usuario_id = $1
              AND ativa = TRUE

            ORDER BY
                atualizada_em DESC,
                criada_em DESC

            LIMIT 1
            `,
            [usuarioId]
        );


    if (rotinaResultado.rows.length === 0) {

        const erro =
            new Error(
                "Rotina Diária não encontrada."
            );

        erro.status = 400;

        throw erro;

    }


    const rotinaBase =
        rotinaResultado.rows[0];


    const itensResultado =
        await pool.query(
            `
            SELECT

                dia_semana,
                hora_inicio,
                hora_fim,
                tipo_atividade,
                descricao,
                tempo_deslocamento_min,
                fixo,
                bloqueia_estudo

            FROM rotina_item

            WHERE rotina_id = $1

            ORDER BY
                dia_semana ASC,
                hora_inicio ASC
            `,
            [rotinaBase.id]
        );


    // ==========================================
    // 6. PAYLOAD FINAL
    // ==========================================

    return {

        perfil:
            perfilResultado.rows[0],

        dificuldades:
            dificuldadesResultado.rows,

        tempoEstudo:
            tempoResultado.rows[0],

        tipoPlanejamento:
            objetivoResultado.rows[0].tipo_planejamento,

        objetivoPlano:
            objetivoResultado.rows[0],

        rotina: {

            preferenciaPeriodo:
                rotinaBase.preferencia_periodo,

            duracaoBlocoMin:
                rotinaBase.duracao_bloco_min,

            intervaloMin:
                rotinaBase.intervalo_min,

            rotinaVariavel:
                rotinaBase.rotina_variavel,

            compromissos:
                itensResultado.rows

        }

    };

}


// =====================================================
// PLANO DE ESTUDO - VISUALIZAR PAYLOAD
// DIAGNÓSTICO - NÃO CHAMA IA
// =====================================================

app.get(
    "/api/plano-estudo/payload/:usuarioId",
    async (req, res) => {

        const usuarioId =
            parseInt(req.params.usuarioId, 10);


        if (
            !Number.isInteger(usuarioId) ||
            usuarioId <= 0
        ) {

            return res.status(400).json({
                sucesso: false,
                erro: "ID de usuário inválido."
            });

        }


        try {

            const payload =
                await montarPayloadPlanoEstudo(
                    usuarioId
                );


            return res.json({

                sucesso: true,

                payload

            });


        } catch (erro) {

            console.error(
                "❌ Erro ao montar payload:",
                erro
            );


            return res
                .status(erro.status || 500)
                .json({

                    sucesso: false,

                    erro:
                        erro.message ||
                        "Não foi possível montar o payload."

                });

        }

    }
);


// =====================================================
// PLANO DE ESTUDO - CONFIGURAÇÃO DO JSON DA IA
// =====================================================

const NOMES_DIAS_PLANO = {

    1: "Segunda-feira",
    2: "Terça-feira",
    3: "Quarta-feira",
    4: "Quinta-feira",
    5: "Sexta-feira",
    6: "Sábado",
    7: "Domingo"

};


const DIAS_DISPONIVEIS_PLANO = {

    "Seg": 1,
    "Ter": 2,
    "Qua": 3,
    "Qui": 4,
    "Sex": 5,
    "Sáb": 6,
    "Sab": 6,
    "Dom": 7

};

// =====================================================
// PLANO DE ESTUDO - MONTAR PROMPT PARA O CLAUDE
// =====================================================

function montarPromptPlanoEstudo(payload) {

    const formatoResposta = {

        versao: 1,

        resumo:
            "Breve explicação do plano criado.",

        sessoes: [

            {
                diaSemana: 1,
                dia: "Segunda-feira",
                horaInicio: "19:00",
                horaFim: "19:45",
                disciplina: "Matemática",
                conteudo: "Equações do 1º grau",
                atividade:
                    "Revisar conceitos e resolver exercícios.",
                duracaoMin: 45,
                prioridade: "alta"
            }

        ],

        observacoes: [
            "Orientação curta para o estudante."
        ]

    };


    return `
Você é um orientador pedagógico especializado em planejamento de estudos.

Sua tarefa é criar um plano semanal REALISTA para um estudante.

IMPORTANTE:
- Utilize somente as informações fornecidas.
- Não invente compromissos, dificuldades ou dados acadêmicos.
- Nunca coloque sessão de estudo em horário ocupado pela rotina.
- Compromissos com bloqueia_estudo=true impedem totalmente o uso daquele horário.
- Utilize somente os dias que o estudante informou como disponíveis.
- Respeite o tempo_disponivel_minutos por dia.
- Priorize disciplinas e conteúdos indicados como dificuldade.
- Considere a disciplina que o estudante praticamente não estuda, quando houver.
- Considere o período do dia em que o estudante afirma render melhor.
- O plano precisa ser sustentável, não excessivo.
- Prefira sessões entre 25 e 90 minutos.
- Evite horários incompatíveis com os compromissos cadastrados.
- diaSemana usa obrigatoriamente:
  1 = Segunda-feira
  2 = Terça-feira
  3 = Quarta-feira
  4 = Quinta-feira
  5 = Sexta-feira
  6 = Sábado
  7 = Domingo
- horaInicio e horaFim devem usar HH:MM no formato 24 horas.
- duracaoMin deve corresponder exatamente à diferença entre horaInicio e horaFim.
- prioridade deve ser apenas "alta", "media" ou "normal".

DADOS DO ESTUDANTE:

${JSON.stringify(payload, null, 2)}

FORMATO OBRIGATÓRIO DA RESPOSTA:

${JSON.stringify(formatoResposta, null, 2)}

Responda SOMENTE com JSON válido.

Não use markdown.
Não use blocos de código.
Não escreva nenhuma explicação antes ou depois do JSON.
`;

}


// =====================================================
// PLANO DE ESTUDO - UTILITÁRIOS DE HORÁRIO
// =====================================================

function converterHoraParaMinutos(hora) {

    if (
        typeof hora !== "string" ||
        !/^\d{2}:\d{2}/.test(hora)
    ) {
        return null;
    }


    const partes =
        hora.substring(0, 5)
            .split(":")
            .map(Number);


    const horas = partes[0];
    const minutos = partes[1];


    if (
        horas < 0 ||
        horas > 23 ||
        minutos < 0 ||
        minutos > 59
    ) {
        return null;
    }


    return horas * 60 + minutos;

}


// =====================================================
// PLANO DE ESTUDO - VALIDAR JSON GERADO
// =====================================================

function validarPlanoGerado(
    plano,
    payload
) {

    if (
        !plano ||
        typeof plano !== "object" ||
        Array.isArray(plano)
    ) {

        throw new Error(
            "A IA não retornou um objeto JSON válido."
        );

    }


    if (
        plano.versao !== 1
    ) {

        throw new Error(
            "Versão do plano inválida."
        );

    }


    if (
        typeof plano.resumo !== "string" ||
        !plano.resumo.trim()
    ) {

        throw new Error(
            "O plano não possui resumo válido."
        );

    }


    if (
        !Array.isArray(plano.sessoes) ||
        plano.sessoes.length === 0
    ) {

        throw new Error(
            "O plano não possui sessões de estudo."
        );

    }


    if (
        plano.sessoes.length > 50
    ) {

        throw new Error(
            "O plano possui sessões demais."
        );

    }


    const diasDisponiveis =
        new Set(
            (
                payload.tempoEstudo
                    .dias_disponiveis || []
            )
                .map(
                    dia =>
                        DIAS_DISPONIVEIS_PLANO[
                            dia
                        ]
                )
                .filter(Boolean)
        );


    const limiteDiario =
        Number(
            payload.tempoEstudo
                .tempo_disponivel_minutos
        );


    const minutosPorDia = {};


    plano.sessoes.forEach(
        (sessao, indice) => {

            const numero =
                indice + 1;


            if (
                !Number.isInteger(
                    sessao.diaSemana
                ) ||
                sessao.diaSemana < 1 ||
                sessao.diaSemana > 7
            ) {

                throw new Error(
                    `Sessão ${numero}: diaSemana inválido.`
                );

            }


            if (
                sessao.dia !==
                NOMES_DIAS_PLANO[
                    sessao.diaSemana
                ]
            ) {

                throw new Error(
                    `Sessão ${numero}: nome do dia incompatível.`
                );

            }


            if (
                diasDisponiveis.size > 0 &&
                !diasDisponiveis.has(
                    sessao.diaSemana
                )
            ) {

                throw new Error(
                    `Sessão ${numero}: dia não informado como disponível pelo estudante.`
                );

            }


            const inicio =
                converterHoraParaMinutos(
                    sessao.horaInicio
                );


            const fim =
                converterHoraParaMinutos(
                    sessao.horaFim
                );


            if (
                inicio === null ||
                fim === null ||
                fim <= inicio
            ) {

                throw new Error(
                    `Sessão ${numero}: horário inválido.`
                );

            }


            const duracaoCalculada =
                fim - inicio;


            if (
                !Number.isInteger(
                    sessao.duracaoMin
                ) ||
                sessao.duracaoMin !==
                    duracaoCalculada
            ) {

                throw new Error(
                    `Sessão ${numero}: duração incompatível com o horário.`
                );

            }


            if (
                sessao.duracaoMin < 15 ||
                sessao.duracaoMin > 180
            ) {

                throw new Error(
                    `Sessão ${numero}: duração fora do limite permitido.`
                );

            }


            [
                "disciplina",
                "conteudo",
                "atividade"
            ].forEach(campo => {

                if (
                    typeof sessao[campo] !==
                        "string" ||
                    !sessao[campo].trim()
                ) {

                    throw new Error(
                        `Sessão ${numero}: campo ${campo} inválido.`
                    );

                }

            });


            if (
                ![
                    "alta",
                    "media",
                    "normal"
                ].includes(
                    sessao.prioridade
                )
            ) {

                throw new Error(
                    `Sessão ${numero}: prioridade inválida.`
                );

            }


            // ==========================================
            // VERIFICAR CONFLITO COM A ROTINA
            // ==========================================

            const compromissos =
                payload.rotina
                    ?.compromissos || [];


            compromissos
                .filter(
                    compromisso =>
                        Number(
                            compromisso.dia_semana
                        ) ===
                            sessao.diaSemana &&
                        compromisso
                            .bloqueia_estudo
                )
                .forEach(
                    compromisso => {

                        const inicioCompromisso =
                            converterHoraParaMinutos(
                                compromisso
                                    .hora_inicio
                            );


                        const fimCompromisso =
                            converterHoraParaMinutos(
                                compromisso
                                    .hora_fim
                            );


                        if (
                            inicioCompromisso ===
                                null ||
                            fimCompromisso ===
                                null
                        ) {
                            return;
                        }


                        const existeConflito =
                            inicio <
                                fimCompromisso &&
                            fim >
                                inicioCompromisso;


                        if (existeConflito) {

                            throw new Error(
                                `Sessão ${numero}: conflito com compromisso da Rotina Diária.`
                            );

                        }

                    }
                );


            minutosPorDia[
                sessao.diaSemana
            ] =
                (
                    minutosPorDia[
                        sessao.diaSemana
                    ] || 0
                ) +
                sessao.duracaoMin;

        }
    );


    if (
        Number.isFinite(limiteDiario) &&
        limiteDiario > 0
    ) {

        Object.entries(
            minutosPorDia
        ).forEach(
            ([dia, minutos]) => {

                if (
                    minutos >
                    limiteDiario
                ) {

                    throw new Error(
                        `O plano ultrapassa o tempo diário disponível em ${NOMES_DIAS_PLANO[dia]}.`
                    );

                }

            }
        );

    }


    if (
        !Array.isArray(
            plano.observacoes
        )
    ) {

        plano.observacoes = [];

    }


    return plano;

}

// =====================================================
// PLANO DE ESTUDO - GERAR COM CLAUDE
// TESTE REAL - AINDA NÃO SALVA NO BANCO
// =====================================================

app.post(
    "/api/plano-estudo/claude/:usuarioId",
    async (req, res) => {

        const usuarioId =
            parseInt(
                req.params.usuarioId,
                10
            );


        if (
            !Number.isInteger(usuarioId) ||
            usuarioId <= 0
        ) {

            return res.status(400).json({

                sucesso: false,

                erro:
                    "ID de usuário inválido."

            });

        }


        if (
            !process.env
                .ANTHROPIC_API_KEY
        ) {

            return res.status(500).json({

                sucesso: false,

                erro:
                    "ANTHROPIC_API_KEY não configurada."

            });

        }


        try {

            // ==========================================
            // 1. BUSCAR DADOS REAIS DO ALUNO
            // ==========================================

            const payload =
                await montarPayloadPlanoEstudo(
                    usuarioId
                );


            // ==========================================
            // 2. MONTAR PROMPT
            // ==========================================

            const prompt =
                montarPromptPlanoEstudo(
                    payload
                );


            // ==========================================
            // 3. CHAMAR CLAUDE
            // ==========================================

            const respostaClaude =
                await anthropic.messages.create({

                    model:
                        "claude-sonnet-4-6",

                    max_tokens:
                        3000,

                    temperature:
                        0.2,

                    messages: [

                        {
                            role: "user",
                            content: prompt
                        }

                    ]

                });


            // ==========================================
            // 4. EXTRAIR TEXTO
            // ==========================================

            const textoResposta =
                respostaClaude.content

                    .filter(
                        bloco =>
                            bloco.type ===
                            "text"
                    )

                    .map(
                        bloco =>
                            bloco.text
                    )

                    .join("\n")

                    .trim();


            if (!textoResposta) {

                throw new Error(
                    "Claude não retornou conteúdo."
                );

            }


            // ==========================================
            // 5. LIMPAR EVENTUAL MARKDOWN
            // ==========================================

            const textoLimpo =
                textoResposta

                    .replace(
                        /^```json\s*/i,
                        ""
                    )

                    .replace(
                        /^```\s*/i,
                        ""
                    )

                    .replace(
                        /\s*```$/,
                        ""
                    )

                    .trim();


            // ==========================================
            // 6. CONVERTER PARA JSON
            // ==========================================

            let plano;


            try {

                plano =
                    JSON.parse(
                        textoLimpo
                    );

            } catch (erroJson) {

                console.error(
                    "❌ JSON inválido retornado pelo Claude:",
                    textoLimpo
                );


                return res
                    .status(502)
                    .json({

                        sucesso: false,

                        erro:
                            "Claude respondeu, mas o JSON retornado é inválido."

                    });

            }


            // ==========================================
            // 7. VALIDAR PLANO
            // ==========================================

            const planoValidado =
                validarPlanoGerado(
                    plano,
                    payload
                );


            // ==========================================
            // 8. RETORNAR
            // NÃO SALVA NADA AINDA
            // ==========================================

            return res.json({

                sucesso: true,

                modelo:
                    respostaClaude.model,

                uso: {

                    tokensEntrada:
                        respostaClaude
                            .usage
                            ?.input_tokens ||
                        null,

                    tokensSaida:
                        respostaClaude
                            .usage
                            ?.output_tokens ||
                        null

                },

                plano:
                    planoValidado

            });


        } catch (erro) {

            console.error(
                "❌ Erro ao gerar Plano de Estudo com Claude:",
                {
                    status:
                        erro.status,

                    mensagem:
                        erro.message
                }
            );


            return res
                .status(
                    erro.status &&
                    Number.isInteger(
                        erro.status
                    )
                        ? erro.status
                        : 500
                )
                .json({

                    sucesso: false,

                    erro:
                        erro.message ||
                        "Não foi possível gerar o Plano de Estudo."

                });

        }

    }
);


// =====================================================
// PLANO DE ESTUDO - GERAR
// POR ENQUANTO FUNCIONA EM MODO DE TESTE
// =====================================================

app.post(
    "/api/plano-estudo/gerar/:usuarioId",
    async (req, res) => {

        const usuarioId =
            parseInt(req.params.usuarioId, 10);


        const {
            objetivo,
            objetivoOutro,
            tipoPlanejamento
        } = req.body;


        // ==========================================
        // VALIDAR USUÁRIO
        // ==========================================

        if (
            !Number.isInteger(usuarioId) ||
            usuarioId <= 0
        ) {

            return res.status(400).json({
                sucesso: false,
                erro: "ID de usuário inválido."
            });

        }


        // ==========================================
        // VALIDAR OBJETIVO
        // ==========================================

        if (
            !objetivo ||
            !OBJETIVOS_PLANO_ESTUDO.has(objetivo)
        ) {

            return res.status(400).json({
                sucesso: false,
                erro:
                    "Selecione um objetivo válido para o Plano de Estudo."
            });

        }


        if (
            objetivo === "outro" &&
            !String(objetivoOutro || "").trim()
        ) {

            return res.status(400).json({
                sucesso: false,
                erro:
                    "Informe qual é o seu objetivo."
            });

        }

        // ==========================================
// VALIDAR TIPO DE PLANEJAMENTO
// ==========================================

if (
    !TIPOS_PLANEJAMENTO.has(
        tipoPlanejamento
    )
) {

    return res.status(400).json({

        sucesso: false,

        erro:
            "Escolha se deseja um planejamento semanal ou mensal."

    });

}

        try {

            // ==========================================
            // CONFIRMA USUÁRIO
            // ==========================================

            const usuario =
                await pool.query(
                    `
                    SELECT id
                    FROM usuario
                    WHERE id = $1
                    `,
                    [usuarioId]
                );


            if (usuario.rows.length === 0) {

                return res.status(404).json({
                    sucesso: false,
                    erro: "Usuário não encontrado."
                });

            }


            // ==========================================
            // VERIFICA PRÉ-REQUISITOS
            // ==========================================

            const status =
                await pool.query(
                    `
                    SELECT

                        EXISTS (
                            SELECT 1
                            FROM rotina r
                            WHERE r.usuario_id = $1
                              AND r.ativa = TRUE
                        )
                        AS rotina_preenchida,


                        EXISTS (
                            SELECT 1
                            FROM perfil_tempo_estudo pte
                            WHERE pte.usuario_id = $1
                        )
                        AS perfil_academico_preenchido

                    `,
                    [usuarioId]
                );


            const rotinaPreenchida =
                Boolean(
                    status.rows[0].rotina_preenchida
                );


            const perfilAcademicoPreenchido =
                Boolean(
                    status.rows[0]
                        .perfil_academico_preenchido
                );


            const faltando = [];


            if (!rotinaPreenchida) {
                faltando.push("Rotina Diária");
            }


            if (!perfilAcademicoPreenchido) {
                faltando.push("Perfil Acadêmico");
            }


            if (faltando.length > 0) {

                return res.status(400).json({

                    sucesso: false,

                    erro:
                        "Existem informações obrigatórias que ainda não foram preenchidas.",

                    faltando

                });

            }


            // ==========================================
            // SALVAR / ATUALIZAR OBJETIVO
            // ==========================================

            const objetivoOutroFinal =
                objetivo === "outro"
                    ? String(objetivoOutro).trim()
                    : null;


            const resultadoObjetivo =
                await pool.query(
                    `
                    INSERT INTO plano_estudo_objetivo
                    (
                        usuario_id,
                        objetivo,
                        objetivo_outro,
                        tipo_planejamento
                    )

                    VALUES ($1, $2, $3, $4)

                    ON CONFLICT (usuario_id)

                    DO UPDATE SET

                        objetivo =
                            EXCLUDED.objetivo,

                        objetivo_outro =
                            EXCLUDED.objetivo_outro,

                        tipo_planejamento =
                            EXCLUDED.tipo_planejamento,

                        atualizado_em =
                            CURRENT_TIMESTAMP

                    RETURNING
                        id,
                        usuario_id,
                        objetivo,
                        objetivo_outro,
                        tipo_planejamento,
                        criado_em,
                        atualizado_em
                    `,
                    [
                        usuarioId,
                        objetivo,
                        objetivoOutroFinal,
                        tipoPlanejamento
                    ]
                );


            console.log(
                "🤖 Dados preparados para geração do plano:",
                {
                    usuarioId,
                    objetivo,
                    tipoPlanejamento
                }
            );


            // ==========================================
            // FUTURAMENTE A API DA IA ENTRARÁ AQUI
            // ==========================================


            return res.json({

                sucesso: true,

                modo: "teste",

                prontoParaIA: true,

                mensagem:
                    "Todos os dados necessários estão prontos para geração do Plano de Estudo.",

                objetivo:
                    resultadoObjetivo.rows[0]

            });


        } catch (erro) {

            console.error(
                "❌ Erro ao preparar Plano de Estudo:",
                erro
            );


            return res.status(500).json({

                sucesso: false,

                erro:
                    "Não foi possível preparar o Plano de Estudo."

            });

        }

    }
);

// =====================================================
// PDF - PLANO DE ESTUDOS
// =====================================================

function formatarDataPdf(data) {

    if (!data) {
        return "-";
    }

    const texto =
        String(data).substring(0, 10);

    const partes =
        texto.split("-");

    if (partes.length !== 3) {
        return texto;
    }

    return `${partes[2]}/${partes[1]}/${partes[0]}`;
}


function nomeArquivoSeguro(texto) {

    return String(texto || "estudante")

        .normalize("NFD")

        .replace(
            /[\u0300-\u036f]/g,
            ""
        )

        .replace(
            /[^a-zA-Z0-9]+/g,
            "-"
        )

        .replace(
            /^-+|-+$/g,
            ""
        )

        .toLowerCase();
}


function gerarBufferPdfPlano(
    plano,
    itens
) {

    return new Promise(
        (resolve, reject) => {

            const doc =
                new PDFDocument({

                    size: "A4",

                    margins: {
                        top: 45,
                        bottom: 50,
                        left: 45,
                        right: 45
                    },

                    bufferPages: true

                });


            const partes = [];


            doc.on(
                "data",
                parte =>
                    partes.push(parte)
            );


            doc.on(
                "error",
                reject
            );


            doc.on(
                "end",
                () => {

                    resolve(
                        Buffer.concat(partes)
                    );

                }
            );


            // ==========================================
            // CABEÇALHO
            // ==========================================

            doc
                .rect(
                    0,
                    0,
                    doc.page.width,
                    115
                )
                .fill("#1e3a8a");


            doc
                .fillColor("#ffffff")
                .font("Helvetica-Bold")
                .fontSize(23)
                .text(
                    "ROTA DO SUCESSO",
                    45,
                    32
                );


            doc
                .font("Helvetica")
                .fontSize(12)
                .text(
                    "Cronograma Personalizado de Estudos",
                    45,
                    68
                );


            doc.y = 140;


            // ==========================================
            // ALUNO
            // ==========================================

            doc
                .fillColor("#0f172a")
                .font("Helvetica-Bold")
                .fontSize(16)
                .text(
                    plano.aluno_nome ||
                    "Estudante"
                );


            doc.moveDown(0.4);


            doc
                .font("Helvetica")
                .fontSize(10)
                .fillColor("#475569");


            if (plano.serie) {

                doc.text(
                    `Série: ${plano.serie}`
                );

            }


            if (plano.escola) {

                doc.text(
                    `Escola: ${plano.escola}`
                );

            }


            if (
                plano.data_inicio ||
                plano.data_fim
            ) {

                doc.text(
                    `Período do plano: ${formatarDataPdf(plano.data_inicio)} a ${formatarDataPdf(plano.data_fim)}`
                );

            }


            doc.moveDown(1);


            doc
                .fillColor("#1e40af")
                .font("Helvetica-Bold")
                .fontSize(14)
                .text(
                    "Cronograma semanal"
                );


            doc.moveDown(0.7);


            // ==========================================
            // SESSÕES
            // ==========================================

            itens.forEach(
                (item, indice) => {

                    if (
                        doc.y >
                        doc.page.height - 180
                    ) {

                        doc.addPage();

                    }


                    const y =
                        doc.y;


                    doc
                        .roundedRect(
                            45,
                            y,
                            doc.page.width - 90,
                            112,
                            8
                        )
                        .fillAndStroke(
                            "#f8fafc",
                            "#dbeafe"
                        );


                    doc
                        .fillColor("#1d4ed8")
                        .font("Helvetica-Bold")
                        .fontSize(11)
                        .text(
                            `${formatarDataPdf(item.data_prevista)}  |  ${item.hora_inicio || "--:--"} - ${item.hora_fim || "--:--"}`,
                            60,
                            y + 14
                        );


                    doc
                        .fillColor("#0f172a")
                        .font("Helvetica-Bold")
                        .fontSize(12)
                        .text(
                            item.disciplina ||
                            "Sessão de estudo",
                            60,
                            y + 38
                        );


                    if (item.conteudo) {

                        doc
                            .font("Helvetica")
                            .fontSize(9)
                            .fillColor("#334155")
                            .text(
                                `Conteúdo: ${item.conteudo}`,
                                60,
                                y + 58,
                                {
                                    width:
                                        doc.page.width -
                                        120
                                }
                            );

                    }


                    doc
                        .font("Helvetica")
                        .fontSize(9)
                        .fillColor("#334155")
                        .text(
                            `Atividade: ${item.atividade || "Estudo programado"}`,
                            60,
                            y + 76,
                            {
                                width:
                                    doc.page.width -
                                    120
                            }
                        );


                    doc
                        .font("Helvetica")
                        .fontSize(8)
                        .fillColor("#64748b")
                        .text(
                            `Duração: ${item.duracao_min || "-"} minutos`,
                            60,
                            y + 96
                        );


                    doc.y =
                        y + 128;

                }
            );


            // ==========================================
            // RODAPÉ
            // ==========================================

            const paginas =
                doc.bufferedPageRange();


            for (
                let i = paginas.start;
                i <
                    paginas.start +
                    paginas.count;
                i++
            ) {

                doc.switchToPage(i);


                doc
                    .font("Helvetica")
                    .fontSize(8)
                    .fillColor("#94a3b8")
                    .text(
                        `Rota do Sucesso | Página ${i + 1} de ${paginas.count}`,
                        45,
                        doc.page.height - 30,
                        {
                            width:
                                doc.page.width -
                                90,
                            align: "center"
                        }
                    );

            }


            doc.end();

        }
    );

}


// =====================================================
// GERAR E SALVAR PDF
// =====================================================

async function gerarESalvarPdfPlano(
    usuarioId,
    planoId
) {

    // ==========================================
    // DADOS PRINCIPAIS DO PLANO
    // ==========================================

    const resultadoPlano =
        await pool.query(
            `
            SELECT

                pe.id,

                pe.usuario_id,

                TO_CHAR(
                    pe.data_inicio,
                    'YYYY-MM-DD'
                ) AS data_inicio,

                TO_CHAR(
                    pe.data_fim,
                    'YYYY-MM-DD'
                ) AS data_fim,

                pe.versao,

                u.nome
                    AS aluno_nome,

                pa.serie,

                pa.escola,

                pa.rede_ensino

            FROM plano_estudo pe

            INNER JOIN usuario u
                ON u.id =
                    pe.usuario_id

            LEFT JOIN perfil_academico pa
                ON pa.usuario_id =
                    pe.usuario_id

            WHERE pe.id = $1
              AND pe.usuario_id = $2
            `,
            [
                planoId,
                usuarioId
            ]
        );


    if (
        resultadoPlano.rows.length === 0
    ) {

        const erro =
            new Error(
                "Plano de Estudo não encontrado."
            );

        erro.status = 404;

        throw erro;

    }


    const plano =
        resultadoPlano.rows[0];


    // ==========================================
    // SESSÕES DO PLANO
    // ==========================================

    const resultadoItens =
        await pool.query(
            `
            SELECT

                pei.id,

                TO_CHAR(
                    pei.data_prevista,
                    'YYYY-MM-DD'
                ) AS data_prevista,

                CASE
                    WHEN pei.hora_inicio IS NULL
                    THEN NULL
                    ELSE TO_CHAR(
                        pei.hora_inicio,
                        'HH24:MI'
                    )
                END AS hora_inicio,

                CASE
                    WHEN pei.hora_fim IS NULL
                    THEN NULL
                    ELSE TO_CHAR(
                        pei.hora_fim,
                        'HH24:MI'
                    )
                END AS hora_fim,

                pei.atividade,

                pei.metodo_estudo,

                pei.duracao_min,

                d.nome
                    AS disciplina,

                cc.titulo
                    AS conteudo

            FROM plano_estudo_item pei

            LEFT JOIN disciplina d
                ON d.id =
                    pei.disciplina_id

            LEFT JOIN conteudo_curricular cc
                ON cc.id =
                    pei.conteudo_curricular_id

            WHERE pei.plano_id = $1

            ORDER BY

                pei.data_prevista ASC
                    NULLS LAST,

                pei.hora_inicio ASC
                    NULLS LAST,

                pei.id ASC
            `,
            [
                planoId
            ]
        );


    if (
        resultadoItens.rows.length === 0
    ) {

        const erro =
            new Error(
                "O plano ainda não possui sessões de estudo."
            );

        erro.status = 400;

        throw erro;

    }


    // ==========================================
    // CRIAR PDF
    // ==========================================

    const pdfBuffer =
        await gerarBufferPdfPlano(
            plano,
            resultadoItens.rows
        );


    // ==========================================
    // HASH DO ARQUIVO
    // ==========================================

    const hash =
        crypto
            .createHash("sha256")
            .update(pdfBuffer)
            .digest("hex");


    const nomeAluno =
        nomeArquivoSeguro(
            plano.aluno_nome
        );


    const nomeArquivo =
        `cronograma-rota-do-sucesso-${nomeAluno}-plano-${planoId}.pdf`;


    // ==========================================
    // SALVAR NO POSTGRESQL
    // ==========================================

    const resultadoPdf =
        await pool.query(
            `
            INSERT INTO plano_estudo_pdf
            (
                plano_id,
                usuario_id,
                nome_arquivo,
                mime_type,
                arquivo_pdf,
                tamanho_bytes,
                hash_sha256,
                versao
            )

            VALUES
            (
                $1,
                $2,
                $3,
                'application/pdf',
                $4,
                $5,
                $6,
                1
            )

            ON CONFLICT (plano_id)

            DO UPDATE SET

                arquivo_pdf =
                    EXCLUDED.arquivo_pdf,

                nome_arquivo =
                    EXCLUDED.nome_arquivo,

                tamanho_bytes =
                    EXCLUDED.tamanho_bytes,

                hash_sha256 =
                    EXCLUDED.hash_sha256,

                versao =
                    plano_estudo_pdf.versao + 1,

                atualizado_em =
                    CURRENT_TIMESTAMP

            RETURNING

                id,
                plano_id,
                nome_arquivo,
                tamanho_bytes,
                versao
            `,
            [
                planoId,
                usuarioId,
                nomeArquivo,
                pdfBuffer,
                pdfBuffer.length,
                hash
            ]
        );


    return resultadoPdf.rows[0];

}

// =====================================================
// GERAR PDF DO PLANO
// =====================================================

app.post(
    "/api/plano-estudo/:usuarioId/:planoId/pdf/gerar",
    async (req, res) => {

        const usuarioId =
            parseInt(
                req.params.usuarioId,
                10
            );

        const planoId =
            parseInt(
                req.params.planoId,
                10
            );


        try {

            const pdf =
                await gerarESalvarPdfPlano(
                    usuarioId,
                    planoId
                );


            return res.json({

                sucesso: true,

                mensagem:
                    "PDF gerado e salvo com sucesso.",

                pdf: {

                    ...pdf,

                    urlDownload:
                        `/api/plano-estudo/${usuarioId}/${planoId}/pdf/download`

                }

            });


        } catch (erro) {

            console.error(
                "Erro ao gerar PDF:",
                erro
            );


            return res
                .status(
                    erro.status || 500
                )
                .json({

                    sucesso: false,

                    erro:
                        erro.message ||
                        "Erro ao gerar PDF."

                });

        }

    }
);

// =====================================================
// LISTAR PLANOS DE ESTUDO DO USUÁRIO
// =====================================================

app.get(
    "/api/plano-estudo/:usuarioId/planos",
    async (req, res) => {

        const usuarioId =
            parseInt(
                req.params.usuarioId,
                10
            );


        if (
            !Number.isInteger(usuarioId) ||
            usuarioId <= 0
        ) {

            return res.status(400).json({

                sucesso: false,

                erro:
                    "ID de usuário inválido."

            });

        }


        try {

            const resultado =
                await pool.query(
                    `
                    SELECT

                        pe.id,

                        pe.tipo_planejamento,

                        TO_CHAR(
                            pe.data_inicio,
                            'DD/MM/YYYY'
                        ) AS data_inicio,

                        TO_CHAR(
                            pe.data_fim,
                            'DD/MM/YYYY'
                        ) AS data_fim,

                        pe.versao,

                        pe.gerado_por_ia,

                        TO_CHAR(
                            pe.criado_em,
                            'DD/MM/YYYY HH24:MI'
                        ) AS criado_em,

                        pdf.id
                            AS pdf_id,

                        pdf.nome_arquivo,

                        pdf.tamanho_bytes,

                        pdf.versao
                            AS pdf_versao

                    FROM plano_estudo pe

                    LEFT JOIN plano_estudo_pdf pdf
                        ON pdf.plano_id =
                            pe.id

                    WHERE pe.usuario_id = $1

                    ORDER BY
                        pe.criado_em DESC,
                        pe.id DESC
                    `,
                    [
                        usuarioId
                    ]
                );


            const planos =
                resultado.rows.map(
                    plano => ({

                        id:
                            plano.id,

                        tipoPlanejamento:
                            plano.tipo_planejamento,

                        dataInicio:
                            plano.data_inicio,

                        dataFim:
                            plano.data_fim,

                        versao:
                            plano.versao,

                        geradoPorIA:
                            plano.gerado_por_ia,

                        criadoEm:
                            plano.criado_em,

                        pdfDisponivel:
                            Boolean(
                                plano.pdf_id
                            ),

                        pdf:
                            plano.pdf_id
                                ? {

                                    id:
                                        plano.pdf_id,

                                    nomeArquivo:
                                        plano.nome_arquivo,

                                    tamanhoBytes:
                                        plano.tamanho_bytes,

                                    versao:
                                        plano.pdf_versao,

                                    urlDownload:
                                        `/api/plano-estudo/${usuarioId}/${plano.id}/pdf/download`

                                }
                                : null

                    })
                );


            return res.json({

                sucesso: true,

                planos

            });


        } catch (erro) {

            console.error(
                "Erro ao listar Planos de Estudo:",
                erro
            );


            return res
                .status(500)
                .json({

                    sucesso: false,

                    erro:
                        "Não foi possível carregar seus Planos de Estudo."

                });

        }

    }
);

// =====================================================
// CONSULTAR PDF MAIS RECENTE
// =====================================================

app.get(
    "/api/plano-estudo/:usuarioId/pdf-atual",
    async (req, res) => {

        const usuarioId =
            parseInt(
                req.params.usuarioId,
                10
            );


        try {

            const resultado =
                await pool.query(
                    `
                    SELECT

                        pe.id
                            AS plano_id,

                        pdf.id
                            AS pdf_id,

                        pdf.nome_arquivo,

                        pdf.tamanho_bytes,

                        pdf.versao

                    FROM plano_estudo pe

                    LEFT JOIN plano_estudo_pdf pdf
                        ON pdf.plano_id =
                            pe.id

                    WHERE pe.usuario_id = $1

                    ORDER BY
                        pe.criado_em DESC,
                        pe.id DESC

                    LIMIT 1
                    `,
                    [
                        usuarioId
                    ]
                );


            if (
                resultado.rows.length === 0
            ) {

                return res.json({

                    sucesso: true,

                    planoExiste: false,

                    pdfDisponivel: false

                });

            }


            const linha =
                resultado.rows[0];


            return res.json({

                sucesso: true,

                planoExiste: true,

                planoId:
                    linha.plano_id,

                pdfDisponivel:
                    Boolean(
                        linha.pdf_id
                    ),

                pdf:
                    linha.pdf_id
                        ? {

                            id:
                                linha.pdf_id,

                            nomeArquivo:
                                linha.nome_arquivo,

                            tamanhoBytes:
                                linha.tamanho_bytes,

                            versao:
                                linha.versao,

                            urlDownload:
                                `/api/plano-estudo/${usuarioId}/${linha.plano_id}/pdf/download`

                        }
                        : null

            });


        } catch (erro) {

            console.error(
                "Erro ao verificar PDF:",
                erro
            );


            return res
                .status(500)
                .json({

                    sucesso: false,

                    erro:
                        "Não foi possível verificar o PDF."

                });

        }

    }
);


// =====================================================
// DOWNLOAD DO PDF
// =====================================================

app.get(
    "/api/plano-estudo/:usuarioId/:planoId/pdf/download",
    async (req, res) => {

        const usuarioId =
            parseInt(
                req.params.usuarioId,
                10
            );

        const planoId =
            parseInt(
                req.params.planoId,
                10
            );


        try {

            const resultado =
                await pool.query(
                    `
                    SELECT

                        nome_arquivo,
                        mime_type,
                        arquivo_pdf,
                        tamanho_bytes

                    FROM plano_estudo_pdf

                    WHERE plano_id = $1
                      AND usuario_id = $2
                    `,
                    [
                        planoId,
                        usuarioId
                    ]
                );


            if (
                resultado.rows.length === 0
            ) {

                return res
                    .status(404)
                    .json({

                        sucesso: false,

                        erro:
                            "PDF não encontrado."

                    });

            }


            const pdf =
                resultado.rows[0];


            res.setHeader(
                "Content-Type",
                pdf.mime_type
            );


            res.setHeader(
                "Content-Length",
                pdf.tamanho_bytes
            );


            res.setHeader(
                "Content-Disposition",
                `attachment; filename="${pdf.nome_arquivo}"`
            );


            res.setHeader(
                "Cache-Control",
                "private, no-store"
            );


            return res.end(
                pdf.arquivo_pdf
            );


        } catch (erro) {

            console.error(
                "Erro no download do PDF:",
                erro
            );


            return res
                .status(500)
                .json({

                    sucesso: false,

                    erro:
                        "Não foi possível baixar o PDF."

                });

        }

    }
);




// =====================================================
// FOTO DE PERFIL
// =====================================================


// =====================================================
// SALVAR / TROCAR FOTO
// =====================================================

app.put(
    "/api/usuario/:usuarioId/foto",
    async (req, res) => {

        const usuarioId =
            parseInt(req.params.usuarioId, 10);

        const {
            imagemBase64
        } = req.body;


        if (
            !Number.isInteger(usuarioId) ||
            usuarioId <= 0
        ) {

            return res.status(400).json({
                sucesso: false,
                erro: "ID de usuário inválido."
            });

        }


        if (
            !imagemBase64 ||
            typeof imagemBase64 !== "string"
        ) {

            return res.status(400).json({
                sucesso: false,
                erro: "Nenhuma imagem foi enviada."
            });

        }


        try {

            // ==========================================
            // CONFIRMA QUE O USUÁRIO EXISTE
            // ==========================================

            const usuario =
                await pool.query(
                    `
                    SELECT id
                    FROM usuario
                    WHERE id = $1
                    `,
                    [usuarioId]
                );


            if (usuario.rows.length === 0) {

                return res.status(404).json({
                    sucesso: false,
                    erro: "Usuário não encontrado."
                });

            }


            // ==========================================
            // SEPARA MIME TYPE E BASE64
            // ==========================================

            const correspondencia =
                imagemBase64.match(
                    /^data:(image\/(?:jpeg|png|webp));base64,(.+)$/
                );


            if (!correspondencia) {

                return res.status(400).json({
                    sucesso: false,
                    erro: "Formato de imagem inválido."
                });

            }


            const mimeType =
                correspondencia[1];


            const base64 =
                correspondencia[2];


            const imagemBuffer =
                Buffer.from(
                    base64,
                    "base64"
                );


            // ==========================================
            // SEGURANÇA - LIMITE DE 1 MB
            // ==========================================

            if (
                !imagemBuffer.length ||
                imagemBuffer.length > 1024 * 1024
            ) {

                return res.status(400).json({
                    sucesso: false,
                    erro:
                        "A foto processada ultrapassou o tamanho permitido."
                });

            }


            // ==========================================
            // SALVAR / ATUALIZAR
            // ==========================================

            const resultado =
                await pool.query(
                    `
                    INSERT INTO usuario_foto
                    (
                        usuario_id,
                        imagem,
                        mime_type
                    )

                    VALUES ($1, $2, $3)

                    ON CONFLICT (usuario_id)

                    DO UPDATE SET

                        imagem =
                            EXCLUDED.imagem,

                        mime_type =
                            EXCLUDED.mime_type,

                        atualizado_em =
                            CURRENT_TIMESTAMP

                    RETURNING
                        usuario_id,
                        mime_type,
                        atualizado_em
                    `,
                    [
                        usuarioId,
                        imagemBuffer,
                        mimeType
                    ]
                );


            console.log(
                "📷 Foto salva para o usuário:",
                usuarioId
            );


            return res.json({

                sucesso: true,

                mensagem:
                    "Foto de perfil salva com sucesso.",

                foto:
                    resultado.rows[0]

            });


        } catch (erro) {

            console.error(
                "❌ Erro ao salvar foto:",
                erro
            );


            return res.status(500).json({

                sucesso: false,

                erro:
                    "Não foi possível salvar a foto de perfil."

            });

        }

    }
);


// =====================================================
// BUSCAR FOTO
// =====================================================

app.get(
    "/api/usuario/:usuarioId/foto",
    async (req, res) => {

        const usuarioId =
            parseInt(req.params.usuarioId, 10);


        if (
            !Number.isInteger(usuarioId) ||
            usuarioId <= 0
        ) {

            return res.status(400).json({
                sucesso: false,
                erro: "ID de usuário inválido."
            });

        }


        try {

            const resultado =
                await pool.query(
                    `
                    SELECT
                        imagem,
                        mime_type

                    FROM usuario_foto

                    WHERE usuario_id = $1
                    `,
                    [usuarioId]
                );


            if (resultado.rows.length === 0) {

                return res.status(404).json({
                    sucesso: false,
                    erro: "Usuário não possui foto."
                });

            }


            const foto =
                resultado.rows[0];


            // Evita o navegador mostrar
            // uma foto antiga depois da troca.
            res.set(
                "Cache-Control",
                "no-store, no-cache, must-revalidate"
            );


            res.type(foto.mime_type);


            return res.send(
                foto.imagem
            );


        } catch (erro) {

            console.error(
                "❌ Erro ao carregar foto:",
                erro
            );


            return res.status(500).json({
                sucesso: false,
                erro:
                    "Não foi possível carregar a foto."
            });

        }

    }
);


// =====================================================
// EXCLUIR FOTO
// =====================================================

// Exclui a conta do aluno junto com os dados relacionados.
app.delete("/api/usuario/:usuarioId", async (req, res) => {
  const usuarioId = Number(req.params.usuarioId);
  if (!Number.isInteger(usuarioId) || usuarioId <= 0) {
    return res.status(400).json({ sucesso: false, erro: "ID de usuário inválido." });
  }

  let client;
  try {
    client = await pool.connect();
    await client.query("BEGIN");
    const usuario = await client.query(
      "SELECT id, tipo_usuario, senha_hash FROM usuario WHERE id = $1 FOR UPDATE",
      [usuarioId]
    );
    if (usuario.rowCount === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ sucesso: false, erro: "Usuário não encontrado." });
    }
    if (usuario.rows[0].tipo_usuario === "administrador") {
      await client.query("ROLLBACK");
      return res.status(403).json({ sucesso: false, erro: "A conta administrativa não pode ser excluída por esta opção." });
    }
    const senha = typeof req.body?.senha === "string" ? req.body.senha : "";
    if (!senha || !(await bcrypt.compare(senha, usuario.rows[0].senha_hash))) {
      await client.query("ROLLBACK");
      return res.status(401).json({ sucesso: false, erro: "Senha inválida." });
    }

    // exercicio.usuario_id ainda não usa ON DELETE CASCADE.
    await client.query("DELETE FROM exercicio WHERE usuario_id = $1", [usuarioId]);
    await client.query("DELETE FROM usuario WHERE id = $1", [usuarioId]);
    await client.query("COMMIT");
    return res.json({ sucesso: true });
  } catch (erro) {
    if (client) await client.query("ROLLBACK").catch(() => {});
    console.error("Erro ao excluir conta do usuário:", erro.message);
    return res.status(500).json({ sucesso: false, erro: "Não foi possível excluir a conta." });
  } finally {
    if (client) client.release();
  }
});

app.delete(
    "/api/usuario/:usuarioId/foto",
    async (req, res) => {

        const usuarioId =
            parseInt(req.params.usuarioId, 10);


        if (
            !Number.isInteger(usuarioId) ||
            usuarioId <= 0
        ) {

            return res.status(400).json({
                sucesso: false,
                erro: "ID de usuário inválido."
            });

        }


        try {

            const resultado =
                await pool.query(
                    `
                    DELETE FROM usuario_foto

                    WHERE usuario_id = $1

                    RETURNING usuario_id
                    `,
                    [usuarioId]
                );


            if (resultado.rows.length === 0) {

                return res.status(404).json({
                    sucesso: false,
                    erro:
                        "O usuário não possui foto cadastrada."
                });

            }


            console.log(
                "🗑️ Foto excluída do usuário:",
                usuarioId
            );


            return res.json({

                sucesso: true,

                mensagem:
                    "Foto excluída com sucesso."

            });


        } catch (erro) {

            console.error(
                "❌ Erro ao excluir foto:",
                erro
            );


            return res.status(500).json({

                sucesso: false,

                erro:
                    "Não foi possível excluir a foto."

            });

        }

    }
);

// =====================================================
// CALENDÁRIO DO USUÁRIO
// =====================================================

const TIPOS_CALENDARIO_USUARIO =
    new Set([
        "tarefa",
        "evento",
        "meta"
    ]);


// =====================================================
// LISTAR ITENS DO CALENDÁRIO
// =====================================================

app.get(
    "/api/calendario/:usuarioId",
    async (req, res) => {

        const usuarioId =
            parseInt(req.params.usuarioId, 10);

        const {
            inicio,
            fim
        } = req.query;


        if (
            !Number.isInteger(usuarioId) ||
            usuarioId <= 0
        ) {

            return res.status(400).json({
                sucesso: false,
                erro: "ID de usuário inválido."
            });

        }


        if (
            !/^\d{4}-\d{2}-\d{2}$/.test(inicio || "") ||
            !/^\d{4}-\d{2}-\d{2}$/.test(fim || "")
        ) {

            return res.status(400).json({
                sucesso: false,
                erro: "Período do calendário inválido."
            });

        }


        try {

            const resultado =
                await pool.query(
                    `
                    SELECT

                        ci.id,
                        ci.tipo,
                        ci.subtipo,
                        ci.titulo,
                        ci.descricao,
                        ci.disciplina_id,

                        d.nome AS disciplina,

                        TO_CHAR(
                            ci.data_inicio,
                            'YYYY-MM-DD'
                        ) AS "dataInicio",

                        CASE
                            WHEN ci.hora_inicio IS NULL
                            THEN NULL
                            ELSE TO_CHAR(
                                ci.hora_inicio,
                                'HH24:MI'
                            )
                        END AS "horaInicio",

                        CASE
                            WHEN ci.data_fim IS NULL
                            THEN NULL
                            ELSE TO_CHAR(
                                ci.data_fim,
                                'YYYY-MM-DD'
                            )
                        END AS "dataFim",

                        CASE
                            WHEN ci.hora_fim IS NULL
                            THEN NULL
                            ELSE TO_CHAR(
                                ci.hora_fim,
                                'HH24:MI'
                            )
                        END AS "horaFim",

                        ci.prioridade,
                        ci.concluido,
                        ci.origem,
                        ci.origem_id AS "origemId",
                        ci.editavel_usuario AS "editavelUsuario",
                        ci.criado_em AS "criadoEm",
                        ci.atualizado_em AS "atualizadoEm"

                    FROM calendario_item ci

                    LEFT JOIN disciplina d
                        ON d.id = ci.disciplina_id

                    WHERE ci.usuario_id = $1

                      AND ci.data_inicio
                          BETWEEN $2::date
                          AND $3::date

                    ORDER BY
                        ci.data_inicio ASC,
                        ci.hora_inicio ASC NULLS LAST,
                        ci.id ASC
                    `,
                    [
                        usuarioId,
                        inicio,
                        fim
                    ]
                );


            return res.json({

                sucesso: true,

                itens:
                    resultado.rows

            });


        } catch (erro) {

            console.error(
                "❌ Erro ao carregar calendário:",
                erro
            );


            return res.status(500).json({

                sucesso: false,

                erro:
                    "Não foi possível carregar o calendário."

            });

        }

    }
);


// =====================================================
// CADASTRAR ITEM DO CALENDÁRIO
// TAREFA / EVENTO / META
// =====================================================

app.post(
    "/api/calendario/:usuarioId",
    async (req, res) => {

        const usuarioId =
            parseInt(req.params.usuarioId, 10);


        if (
            !Number.isInteger(usuarioId) ||
            usuarioId <= 0
        ) {

            return res.status(400).json({
                sucesso: false,
                erro: "ID de usuário inválido."
            });

        }


        const {

            tipo,
            subtipo,
            titulo,
            descricao,
            disciplinaId,
            dataInicio,
            horaInicio,
            dataFim,
            horaFim,
            prioridade

        } = req.body;


        if (
            !TIPOS_CALENDARIO_USUARIO.has(tipo)
        ) {

            return res.status(400).json({
                sucesso: false,
                erro: "Tipo de item inválido."
            });

        }


        if (
            !String(titulo || "").trim()
        ) {

            return res.status(400).json({
                sucesso: false,
                erro: "Informe o título."
            });

        }


        if (
            !/^\d{4}-\d{2}-\d{2}$/.test(
                dataInicio || ""
            )
        ) {

            return res.status(400).json({
                sucesso: false,
                erro: "Informe uma data válida."
            });

        }


        if (
            prioridade &&
            !["normal", "alta"].includes(
                prioridade
            )
        ) {

            return res.status(400).json({
                sucesso: false,
                erro: "Prioridade inválida."
            });

        }


        try {

            // Confirma que o usuário existe
            const usuario =
                await pool.query(
                    `
                    SELECT id
                    FROM usuario
                    WHERE id = $1
                    `,
                    [usuarioId]
                );


            if (usuario.rows.length === 0) {

                return res.status(404).json({
                    sucesso: false,
                    erro: "Usuário não encontrado."
                });

            }


            const resultado =
                await pool.query(
                    `
                    INSERT INTO calendario_item
                    (
                        usuario_id,
                        criado_por_usuario_id,
                        tipo,
                        subtipo,
                        titulo,
                        descricao,
                        disciplina_id,
                        data_inicio,
                        hora_inicio,
                        data_fim,
                        hora_fim,
                        prioridade,
                        concluido,
                        origem,
                        editavel_usuario
                    )

                    VALUES
                    (
                        $1,
                        $1,
                        $2,
                        $3,
                        $4,
                        $5,
                        $6,
                        $7,
                        $8,
                        $9,
                        $10,
                        $11,
                        FALSE,
                        'usuario',
                        TRUE
                    )

                    RETURNING id
                    `,
                    [
                        usuarioId,
                        tipo,
                        subtipo || null,
                        String(titulo).trim(),
                        String(descricao || "").trim()
                            || null,
                        disciplinaId
                            ? Number(disciplinaId)
                            : null,
                        dataInicio,
                        horaInicio || null,
                        dataFim || null,
                        horaFim || null,
                        tipo === "tarefa"
                            ? prioridade || "normal"
                            : null
                    ]
                );


            return res.status(201).json({

                sucesso: true,

                mensagem:
                    "Item cadastrado com sucesso.",

                id:
                    resultado.rows[0].id

            });


        } catch (erro) {

            console.error(
                "❌ Erro ao cadastrar item do calendário:",
                erro
            );


            return res.status(500).json({

                sucesso: false,

                erro:
                    "Não foi possível cadastrar o item."

            });

        }

    }
);


// =====================================================
// MARCAR ITEM COMO CONCLUÍDO / NÃO CONCLUÍDO
// =====================================================

app.patch(
    "/api/calendario/:usuarioId/:itemId/conclusao",
    async (req, res) => {

        const usuarioId =
            parseInt(req.params.usuarioId, 10);

        const itemId =
            parseInt(req.params.itemId, 10);

        const concluido =
            req.body.concluido === true;


        if (
            !Number.isInteger(usuarioId) ||
            !Number.isInteger(itemId)
        ) {

            return res.status(400).json({
                sucesso: false,
                erro: "Dados inválidos."
            });

        }


        try {

            const resultado =
                await pool.query(
                    `
                    UPDATE calendario_item

                    SET
                        concluido = $1,
                        atualizado_em =
                            CURRENT_TIMESTAMP

                    WHERE id = $2
                      AND usuario_id = $3

                    RETURNING id
                    `,
                    [
                        concluido,
                        itemId,
                        usuarioId
                    ]
                );


            if (
                resultado.rowCount === 0
            ) {

                return res.status(404).json({
                    sucesso: false,
                    erro: "Item não encontrado."
                });

            }


            return res.json({
                sucesso: true
            });


        } catch (erro) {

            console.error(
                "❌ Erro ao alterar conclusão:",
                erro
            );


            return res.status(500).json({
                sucesso: false,
                erro:
                    "Não foi possível atualizar o item."
            });

        }

    }
);


// =====================================================
// EXCLUIR ITEM
// =====================================================

app.delete(
    "/api/calendario/:usuarioId/:itemId",
    async (req, res) => {

        const usuarioId =
            parseInt(req.params.usuarioId, 10);

        const itemId =
            parseInt(req.params.itemId, 10);


        if (
            !Number.isInteger(usuarioId) ||
            !Number.isInteger(itemId)
        ) {

            return res.status(400).json({
                sucesso: false,
                erro: "Dados inválidos."
            });

        }


        try {

            const resultado =
                await pool.query(
                    `
                    DELETE FROM calendario_item

                    WHERE id = $1
                      AND usuario_id = $2
                      AND editavel_usuario = TRUE

                    RETURNING id
                    `,
                    [
                        itemId,
                        usuarioId
                    ]
                );


            if (
                resultado.rowCount === 0
            ) {

                return res.status(404).json({
                    sucesso: false,

                    erro:
                        "Item não encontrado ou não pode ser excluído."
                });

            }


            return res.json({
                sucesso: true,
                mensagem:
                    "Item excluído com sucesso."
            });


        } catch (erro) {

            console.error(
                "❌ Erro ao excluir item:",
                erro
            );


            return res.status(500).json({
                sucesso: false,
                erro:
                    "Não foi possível excluir o item."
            });

        }

    }
);

// =====================================================
// LISTAR TAREFAS DO USUÁRIO
// =====================================================

// Resumo de progresso do aluno, calculado a partir das tarefas do calendário.
app.get("/api/progresso/:usuarioId", async (req, res) => {
  const usuarioId = parseInt(req.params.usuarioId, 10);
  if (!Number.isInteger(usuarioId) || usuarioId <= 0) {
    return res.status(400).json({ sucesso: false, erro: "ID de usuário inválido." });
  }

  try {
    const resultado = await pool.query(
      `SELECT ci.id, ci.titulo, ci.tipo, ci.subtipo, ci.disciplina_id,
              d.nome AS disciplina, ci.data_inicio, ci.hora_inicio, ci.hora_fim,
              ci.concluido, ci.atualizado_em
       FROM calendario_item ci
       LEFT JOIN disciplina d ON d.id = ci.disciplina_id
       WHERE ci.usuario_id = $1 AND ci.tipo = 'tarefa'
       ORDER BY ci.data_inicio ASC, ci.id ASC`,
      [usuarioId]
    );
    const tarefas = resultado.rows;
    const agora = new Date();
    const inicioSemana = new Date(agora);
    inicioSemana.setHours(0, 0, 0, 0);
    const diaSemana = (inicioSemana.getDay() + 6) % 7;
    inicioSemana.setDate(inicioSemana.getDate() - diaSemana);
    const inicioSemanaAnterior = new Date(inicioSemana);
    inicioSemanaAnterior.setDate(inicioSemanaAnterior.getDate() - 7);
    const chaveData = (valor) => {
      const data = new Date(valor);
      return Number.isNaN(data.getTime()) ? "" : data.toISOString().slice(0, 10);
    };
    const duracaoHoras = (tarefa) => {
      if (!tarefa.hora_inicio || !tarefa.hora_fim) return 0;
      const [hi, mi] = String(tarefa.hora_inicio).slice(0, 5).split(":").map(Number);
      const [hf, mf] = String(tarefa.hora_fim).slice(0, 5).split(":").map(Number);
      const minutos = hf * 60 + mf - (hi * 60 + mi);
      return minutos > 0 && minutos <= 24 * 60 ? minutos / 60 : 0;
    };
    const concluidas = tarefas.filter(t => t.concluido);
    const naSemana = (t, inicio, fim) => {
      const data = new Date(t.data_inicio);
      return data >= inicio && data < fim;
    };
    const concluidasSemana = concluidas.filter(t => naSemana(t, inicioSemana, new Date(+inicioSemana + 7 * 86400000)));
    const concluidasSemanaAnterior = concluidas.filter(t => naSemana(t, inicioSemanaAnterior, inicioSemana));
    const datasConcluidas = new Set(concluidas.map(t => chaveData(t.data_inicio)).filter(Boolean));
    let sequencia = 0;
    const cursor = new Date(agora);
    cursor.setHours(0, 0, 0, 0);
    if (!datasConcluidas.has(chaveData(cursor))) cursor.setDate(cursor.getDate() - 1);
    while (datasConcluidas.has(chaveData(cursor))) {
      sequencia += 1;
      cursor.setDate(cursor.getDate() - 1);
    }
    const porDisciplina = new Map();
    for (const tarefa of tarefas) {
      const nome = tarefa.disciplina || "Sem disciplina";
      const atual = porDisciplina.get(nome) || { nome, total: 0, concluidas: 0 };
      atual.total += 1;
      if (tarefa.concluido) atual.concluidas += 1;
      porDisciplina.set(nome, atual);
    }
    return res.json({
      sucesso: true,
      resumo: {
        tarefasConcluidas: concluidas.length,
        variacaoSemanal: concluidasSemana.length - concluidasSemanaAnterior.length,
        horasPlanejadasConcluidas: Number(concluidas.reduce((soma, t) => soma + duracaoHoras(t), 0).toFixed(1)),
        horasSemana: Number(concluidasSemana.reduce((soma, t) => soma + duracaoHoras(t), 0).toFixed(1)),
        sequenciaDias: sequencia,
        disciplinas: [...porDisciplina.values()].map(d => ({
          nome: d.nome,
          concluidas: d.concluidas,
          total: d.total,
          percentual: d.total ? Math.round(d.concluidas / d.total * 100) : 0
        })).sort((a, b) => a.nome.localeCompare(b.nome, "pt-BR"))
      }
    });
  } catch (erro) {
    console.error("Erro ao carregar progresso:", erro);
    return res.status(500).json({ sucesso: false, erro: "Não foi possível carregar o progresso." });
  }
});

app.get(
    "/api/tarefas/:usuarioId",
    async (req, res) => {

        const usuarioId =
            parseInt(req.params.usuarioId, 10);


        if (
            !Number.isInteger(usuarioId) ||
            usuarioId <= 0
        ) {

            return res.status(400).json({
                sucesso: false,
                erro: "ID de usuário inválido."
            });

        }


        try {

            const resultado =
                await pool.query(
                    `
                    SELECT

                        ci.id,

                        ci.titulo,

                        ci.descricao,

                        ci.disciplina_id,

                        d.nome AS disciplina,

                        TO_CHAR(
                            ci.data_inicio,
                            'YYYY-MM-DD'
                        ) AS "dataInicio",

                        CASE

                            WHEN ci.hora_inicio IS NULL
                            THEN NULL

                            ELSE TO_CHAR(
                                ci.hora_inicio,
                                'HH24:MI'
                            )

                        END AS "horaInicio",

                        ci.prioridade,

                        ci.concluido,

                        ci.origem,

                        ci.editavel_usuario
                            AS "editavelUsuario"

                    FROM calendario_item ci

                    LEFT JOIN disciplina d
                        ON d.id =
                           ci.disciplina_id

                    WHERE
                        ci.usuario_id = $1

                        AND ci.tipo = 'tarefa'

                    ORDER BY

                        ci.concluido ASC,

                        ci.data_inicio ASC,

                        ci.hora_inicio ASC
                            NULLS LAST,

                        ci.id DESC
                    `,
                    [usuarioId]
                );


            return res.json({

                sucesso: true,

                tarefas:
                    resultado.rows

            });


        } catch (erro) {

            console.error(
                "❌ Erro ao carregar tarefas:",
                erro
            );


            return res.status(500).json({

                sucesso: false,

                erro:
                    "Não foi possível carregar as tarefas."

            });

        }

    }
);

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
