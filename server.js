require("dotenv").config();
// teste 1
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const path = require("path");
const Anthropic = require("@anthropic-ai/sdk");

const app = express();
app.use(cors());
app.use(express.json());

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
app.use(express.static(path.join(__dirname, "public")));

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: { rejectUnauthorized: false },
});

pool
  .query("SELECT NOW()")
  .then(() => console.log("Conectado ao banco Neon com sucesso."))
  .catch((err) => console.error("Erro ao conectar no banco:", err.message));

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

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const existe = await client.query(
      "SELECT id FROM usuario WHERE email = $1",
      [email]
    );

    if (existe.rows.length > 0) {
      await client.query("ROLLBACK");
      return res
        .status(400)
        .json({ erro: "Este e-mail já está cadastrado." });
    }

    const hash = await bcrypt.hash(senha, 10);

    const resultadoUsuario = await client.query(
      `INSERT INTO usuario (nome, email, senha_hash) VALUES ($1, $2, $3) RETURNING id`,
      [nome, email, hash]
    );
    const usuarioId = resultadoUsuario.rows[0].id;

    await client.query(
      `INSERT INTO perfil_academico
        (usuario_id, data_nascimento, serie, etapa_atual, rede_ensino,
         curso_desejado, universidade_desejada, tipo_universidade, objetivo_geral)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        usuarioId,
        dataNascimento,
        SERIE_LABELS[serie] || String(serie),
        serie,
        REDE_LABELS[redeEnsino] || null,
        curso,
        universidade,
        REDE_LABELS[tipoInstituicao] || null,
        objetivoTextoFinal(objetivo, objetivoOutro),
      ]
    );

    await client.query("COMMIT");
    res.json({ sucesso: true, usuarioId });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error(err);
    res.status(500).json({ erro: "Erro ao cadastrar usuário." });
  } finally {
    client.release();
  }
});

// ---------- LOGIN ----------
app.post("/api/login", async (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha) {
    return res.status(400).json({ erro: "Preencha e-mail e senha." });
  }

  try {
    const resultado = await pool.query(
      "SELECT id, senha_hash FROM usuario WHERE email = $1",
      [email]
    );

    if (resultado.rows.length === 0) {
      return res.status(401).json({ erro: "E-mail ou senha inválidos." });
    }

    const usuario = resultado.rows[0];
    const senhaCorreta = await bcrypt.compare(senha, usuario.senha_hash);

    if (!senhaCorreta) {
      return res.status(401).json({ erro: "E-mail ou senha inválidos." });
    }

    await pool.query("UPDATE usuario SET ultimo_acesso = NOW() WHERE id = $1", [usuario.id]);

    res.json({ sucesso: true, usuarioId: usuario.id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro ao entrar." });
  }
});

// ---------- BUSCAR PERFIL ACADÊMICO ----------
app.get("/api/perfil/:usuarioId", async (req, res) => {
  const usuarioId = parseInt(req.params.usuarioId, 10);

  if (isNaN(usuarioId)) {
    return res.status(400).json({ erro: "ID de usuário inválido." });
  }

  try {
    const resultado = await pool.query(
      `SELECT u.nome, u.email,
              to_char(pa.data_nascimento, 'YYYY-MM-DD') AS data_nascimento,
              pa.etapa_atual, pa.rede_ensino, pa.curso_desejado,
              pa.universidade_desejada, pa.tipo_universidade, pa.objetivo_geral
       FROM usuario u
       JOIN perfil_academico pa ON pa.usuario_id = u.id
       WHERE u.id = $1`,
      [usuarioId]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({ erro: "Usuário não encontrado." });
    }

    const linha = resultado.rows[0];

    // objetivo/objetivoOutro viraram um texto único (objetivoGeral) no banco novo.
    res.json({
      nome: linha.nome,
      email: linha.email,
      dataNascimento: linha.data_nascimento,
      serie: linha.etapa_atual,
      redeEnsino: CODIGO_REDE[linha.rede_ensino] ?? null,
      curso: linha.curso_desejado,
      universidade: linha.universidade_desejada,
      tipoInstituicao: CODIGO_REDE[linha.tipo_universidade] ?? null,
      objetivoGeral: linha.objetivo_geral,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro ao buscar perfil." });
  }
});

// ---------- ATUALIZAR PERFIL ACADÊMICO ----------
app.put("/api/perfil/:usuarioId", async (req, res) => {
  const usuarioId = parseInt(req.params.usuarioId, 10);

  if (isNaN(usuarioId)) {
    return res.status(400).json({ erro: "ID de usuário inválido." });
  }

  const {
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

  try {
    const resultado = await pool.query(
      `UPDATE perfil_academico SET
        data_nascimento = $1,
        serie = $2,
        etapa_atual = $3,
        rede_ensino = $4,
        curso_desejado = $5,
        universidade_desejada = $6,
        tipo_universidade = $7,
        objetivo_geral = $8,
        atualizado_em = NOW()
       WHERE usuario_id = $9
       RETURNING usuario_id`,
      [
        dataNascimento,
        SERIE_LABELS[serie] || String(serie),
        serie,
        REDE_LABELS[redeEnsino] || null,
        curso,
        universidade,
        REDE_LABELS[tipoInstituicao] || null,
        objetivoTextoFinal(objetivo, objetivoOutro),
        usuarioId,
      ]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({ erro: "Perfil não encontrado para este usuário." });
    }

    res.json({ sucesso: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro ao atualizar perfil." });
  }
});

// ---------- CRONOGRAMA PERSONALIZADO ----------
// O formulário do cronograma grava diretamente em cronograma_preferencias,
// que é a tabela criada pelo schema do projeto e existente no banco.
// Cada usuário possui uma única linha nessa tabela.

const DIAS_VALIDOS = new Set(["seg", "ter", "qua", "qui", "sex", "sab", "dom"]);
const MATERIAS_VALIDAS = new Set([
  "matematica",
  "portugues",
  "fisica",
  "quimica",
  "biologia",
  "historia",
  "geografia",
  "ingles",
  "redacao",
  "outra",
]);
const PERIODOS_VALIDOS = new Set([1, 2, 3, 4]);
const DURACOES_VALIDAS = new Set([1, 2, 3, 4, 5]);

// ---------- ROTINA SEMANAL ("Como é sua rotina hoje?") ----------
// Fica nas tabelas rotina (1 linha ativa por aluno) + rotina_item (1 linha por
// atividade). rotina_item.dia_semana: 1 = seg ... 7 = dom.
// A descrição da atividade vai em rotina_item.descricao.
const DIA_NUMERO = { seg: 1, ter: 2, qua: 3, qui: 4, sex: 5, sab: 6, dom: 7 };
const NUMERO_DIA = { 1: "seg", 2: "ter", 3: "qua", 4: "qui", 5: "sex", 6: "sab", 7: "dom" };
const HORA_REGEX = /^([01]\d|2[0-3]):[0-5]\d$/;
const MAX_ATIVIDADES_POR_DIA = 20;
const TIPO_ROTINA_ATUAL = "rotina_atual";

// Valida o objeto { seg: [{ inicio, fim, descricao }], ... } vindo do front-end.
// Só considera os dias marcados como disponíveis; linhas totalmente vazias são ignoradas.
function normalizarRotina(rotina, diasSelecionados) {
  const itens = [];

  if (rotina === null || typeof rotina !== "object" || Array.isArray(rotina)) {
    return { erro: "Formato da rotina semanal inválido." };
  }

  for (const dia of diasSelecionados) {
    const linhas = rotina[dia];
    if (linhas === undefined || linhas === null) continue;

    if (!Array.isArray(linhas) || linhas.length > MAX_ATIVIDADES_POR_DIA) {
      return { erro: `Rotina de ${DIA_LABELS[dia]} inválida (máximo de ${MAX_ATIVIDADES_POR_DIA} atividades por dia).` };
    }

    for (const linha of linhas) {
      const inicio = String(linha?.inicio ?? "").trim();
      const fim = String(linha?.fim ?? "").trim();
      const descricao = String(linha?.descricao ?? "").trim();

      if (!inicio && !fim && !descricao) continue;

      if (!HORA_REGEX.test(inicio) || !HORA_REGEX.test(fim)) {
        return { erro: `Informe o horário de início e de fim de cada atividade em ${DIA_LABELS[dia]}.` };
      }
      if (inicio === fim) {
        return { erro: `Em ${DIA_LABELS[dia]}, o horário de início e de fim não podem ser iguais.` };
      }
      if (!descricao) {
        return { erro: `Descreva o que você faz em cada horário de ${DIA_LABELS[dia]}.` };
      }
      if (descricao.length > 100) {
        return { erro: `Descrição muito longa em ${DIA_LABELS[dia]} (máximo de 100 caracteres).` };
      }

      itens.push({ dia: DIA_NUMERO[dia], inicio, fim, descricao });
    }
  }

  return { itens };
}

// Devolve { seg: [{ inicio: "08:00", fim: "12:00", descricao }], ... } (só os dias que têm atividades).
async function buscarRotinaUsuario(usuarioId) {
  const resultado = await pool.query(
    `SELECT ri.dia_semana,
            to_char(ri.hora_inicio, 'HH24:MI') AS inicio,
            to_char(ri.hora_fim, 'HH24:MI') AS fim,
            ri.descricao
       FROM rotina_item ri
       JOIN rotina r ON r.id = ri.rotina_id
      WHERE r.usuario_id = $1
        AND r.ativa = true
        AND ri.tipo_atividade = $2
      ORDER BY ri.dia_semana, ri.hora_inicio, ri.id`,
    [usuarioId, TIPO_ROTINA_ATUAL]
  );

  const rotina = {};
  for (const linha of resultado.rows) {
    const dia = NUMERO_DIA[linha.dia_semana];
    if (!dia) continue;
    (rotina[dia] ||= []).push({
      inicio: linha.inicio,
      fim: linha.fim,
      descricao: linha.descricao || "",
    });
  }
  return rotina;
}

app.get("/api/cronograma/:usuarioId", async (req, res) => {
  const usuarioId = Number.parseInt(req.params.usuarioId, 10);

  if (Number.isNaN(usuarioId)) {
    return res.status(400).json({ erro: "ID de usuário inválido." });
  }

  try {
    const resultado = await pool.query(
      `SELECT horas_por_dia,
              dias_semana,
              materias_dificeis,
              materia_dificil_outra,
              periodo_preferido,
              duracao_foco
       FROM cronograma_preferencias
       WHERE usuario_id = $1`,
      [usuarioId]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({ erro: "Cronograma ainda não preenchido." });
    }

    const cronograma = resultado.rows[0];
    const rotina = await buscarRotinaUsuario(usuarioId);

    return res.json({
      rotina,
      horasPorDia: Number(cronograma.horas_por_dia),
      diasSemana: cronograma.dias_semana || [],
      materiasDificeis: cronograma.materias_dificeis || [],
      materiaDificilOutra: cronograma.materia_dificil_outra || "",
      periodoPreferido: Number(cronograma.periodo_preferido),
      duracaoFoco: Number(cronograma.duracao_foco),
    });
  } catch (err) {
    console.error("Erro ao buscar cronograma:", err);
    return res.status(500).json({ erro: "Erro ao buscar cronograma." });
  }
});

app.post("/api/cronograma/:usuarioId", async (req, res) => {
  const usuarioId = Number.parseInt(req.params.usuarioId, 10);

  if (Number.isNaN(usuarioId)) {
    return res.status(400).json({ erro: "ID de usuário inválido." });
  }

  const {
    horasPorDia,
    diasSemana,
    materiasDificeis,
    materiaDificilOutra,
    periodoPreferido,
    duracaoFoco,
    rotina,
  } = req.body || {};

  const horas = Number(horasPorDia);
  const periodo = Number(periodoPreferido);
  const duracao = Number(duracaoFoco);

  const diasNormalizados = Array.isArray(diasSemana)
    ? [...new Set(diasSemana.map(String))]
    : [];
  const materiasNormalizadas = Array.isArray(materiasDificeis)
    ? [...new Set(materiasDificeis.map(String))]
    : [];

  const diasValidos =
    diasNormalizados.length > 0 &&
    diasNormalizados.every((dia) => DIAS_VALIDOS.has(dia));
  const materiasValidas =
    materiasNormalizadas.length > 0 &&
    materiasNormalizadas.every((materia) => MATERIAS_VALIDAS.has(materia));

  if (!Number.isFinite(horas) || horas <= 0 || horas > 12) {
    return res.status(400).json({ erro: "Informe entre 0,5 e 12 horas por dia." });
  }

  if (!diasValidos) {
    return res.status(400).json({ erro: "Selecione pelo menos um dia válido da semana." });
  }

  if (!materiasValidas) {
    return res.status(400).json({ erro: "Selecione pelo menos uma matéria válida." });
  }

  if (!PERIODOS_VALIDOS.has(periodo)) {
    return res.status(400).json({ erro: "Selecione um período válido para estudar." });
  }

  if (!DURACOES_VALIDAS.has(duracao)) {
    return res.status(400).json({ erro: "Selecione uma duração de foco válida." });
  }

  // A rotina semanal é opcional. Se o front-end não mandar o campo "rotina",
  // o que já está salvo no banco não é alterado.
  let itensRotina = null;
  if (rotina !== undefined) {
    const rotinaNormalizada = normalizarRotina(rotina, diasNormalizados);
    if (rotinaNormalizada.erro) {
      return res.status(400).json({ erro: rotinaNormalizada.erro });
    }
    itensRotina = rotinaNormalizada.itens;
  }

  const usuarioExiste = await pool.query(
    "SELECT id FROM usuario WHERE id = $1",
    [usuarioId]
  );

  if (usuarioExiste.rows.length === 0) {
    return res.status(404).json({ erro: "Usuário não encontrado." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const valores = [
      horas,
      diasNormalizados,
      materiasNormalizadas,
      materiasNormalizadas.includes("outra")
        ? String(materiaDificilOutra || "").trim() || null
        : null,
      periodo,
      duracao,
    ];

    // Não dependemos de ON CONFLICT: assim funciona mesmo que a constraint
    // UNIQUE de usuario_id não tenha sido criada na tabela antiga do Neon.
    const atualizacao = await client.query(
      `UPDATE cronograma_preferencias
          SET horas_por_dia = $1,
              dias_semana = $2::text[],
              materias_dificeis = $3::text[],
              materia_dificil_outra = $4,
              periodo_preferido = $5,
              duracao_foco = $6,
              atualizado_em = NOW()
        WHERE usuario_id = $7
        RETURNING id`,
      [...valores, usuarioId]
    );

    let cronogramaId;

    if (atualizacao.rows.length > 0) {
      cronogramaId = atualizacao.rows[0].id;
    } else {
      const insercao = await client.query(
        `INSERT INTO cronograma_preferencias
          (usuario_id, horas_por_dia, dias_semana, materias_dificeis,
           materia_dificil_outra, periodo_preferido, duracao_foco, atualizado_em)
         VALUES ($1, $2, $3::text[], $4::text[], $5, $6, $7, NOW())
         RETURNING id`,
        [usuarioId, horas, diasNormalizados, materiasNormalizadas,
         valores[3], periodo, duracao]
      );
      cronogramaId = insercao.rows[0].id;
    }

    // Rotina semanal: troca todas as atividades "rotina_atual" do aluno pelas
    // que vieram no formulário (tudo dentro da mesma transação).
    if (itensRotina !== null) {
      const rotinaExistente = await client.query(
        `SELECT id FROM rotina
          WHERE usuario_id = $1 AND ativa = true
          ORDER BY id
          LIMIT 1`,
        [usuarioId]
      );

      let rotinaId = rotinaExistente.rows[0]?.id;

      if (rotinaId === undefined && itensRotina.length > 0) {
        const novaRotina = await client.query(
          `INSERT INTO rotina (usuario_id, nome, ativa)
           VALUES ($1, 'Rotina atual', true)
           RETURNING id`,
          [usuarioId]
        );
        rotinaId = novaRotina.rows[0].id;
      }

      if (rotinaId !== undefined) {
        await client.query(
          `DELETE FROM rotina_item WHERE rotina_id = $1 AND tipo_atividade = $2`,
          [rotinaId, TIPO_ROTINA_ATUAL]
        );

        for (const item of itensRotina) {
          await client.query(
            `INSERT INTO rotina_item
               (rotina_id, dia_semana, hora_inicio, hora_fim,
                tipo_atividade, descricao, fixo, bloqueia_estudo)
             VALUES ($1, $2, $3, $4, $5, $6, true, true)`,
            [rotinaId, item.dia, item.inicio, item.fim, TIPO_ROTINA_ATUAL, item.descricao]
          );
        }

        await client.query(
          `UPDATE rotina SET atualizada_em = NOW() WHERE id = $1`,
          [rotinaId]
        );
      }
    }

    await client.query("COMMIT");

    return res.json({
      sucesso: true,
      cronogramaId,
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Erro ao salvar cronograma:", err);

    if (err.code === "42P01") {
      return res.status(500).json({
        erro: "A tabela cronograma_preferencias não existe no banco. Rode o schema.sql no Neon.",
      });
    }

    return res.status(500).json({
      erro: "Erro ao salvar cronograma.",
      detalhe: process.env.NODE_ENV === "development" ? err.message : undefined,
    });
  }
});

// ---------- ASSISTENTE IA (cronograma personalizado, sem chat) ----------
// Mapas para transformar os códigos salvos no banco em texto legível para o prompt.
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
const REDE_LABELS = { 1: "Pública", 2: "Particular" };
const CODIGO_REDE = { Pública: 1, Particular: 2 };
const OBJETIVO_LABELS = {
  1: "Passar no ENEM",
  2: "Passar no vestibular",
  3: "Melhorar as notas",
  4: "Organizar os estudos",
  5: "Recuperação escolar",
  6: "Concurso",
  7: "Outro",
};

// perfil_academico.objetivo_geral guarda o texto final pronto (não código + outro).
function objetivoTextoFinal(objetivo, objetivoOutro) {
  return Number(objetivo) === 7
    ? `Outro: ${objetivoOutro || "não especificado"}`
    : OBJETIVO_LABELS[objetivo] || String(objetivo);
}

const PERIODO_LABELS = { 1: "Manhã", 2: "Tarde", 3: "Noite", 4: "Madrugada" };
const DURACAO_LABELS = {
  1: "15 minutos",
  2: "25 minutos",
  3: "30 minutos",
  4: "45 minutos",
  5: "1 hora ou mais",
};
const DIA_LABELS = {
  seg: "Segunda-feira",
  ter: "Terça-feira",
  qua: "Quarta-feira",
  qui: "Quinta-feira",
  sex: "Sexta-feira",
  sab: "Sábado",
  dom: "Domingo",
};
const DIAS_ORDEM = ["seg", "ter", "qua", "qui", "sex", "sab", "dom"];
const MATERIA_LABELS = {
  matematica: "Matemática",
  portugues: "Português",
  fisica: "Física",
  quimica: "Química",
  biologia: "Biologia",
  historia: "História",
  geografia: "Geografia",
  ingles: "Inglês",
  redacao: "Redação",
  outra: "Outra",
};

function montarPromptAssistente(perfil, cronograma, rotina = {}) {
  // perfil_academico já guarda texto pronto (serie, rede_ensino, tipo_universidade,
  // objetivo_geral) — não precisa mais de lookup de código aqui.
  const serieTexto = perfil.serie || "não informado";
  const redeTexto = perfil.rede_ensino || "não informado";
  const objetivoTexto = perfil.objetivo_geral || "não informado";

  const diasTexto = (cronograma.dias_semana || [])
    .map((d) => DIA_LABELS[d] || d)
    .join(", ");

  const materiasTexto = (cronograma.materias_dificeis || [])
    .map((m) =>
      m === "outra"
        ? `Outra (${cronograma.materia_dificil_outra || "não especificado"})`
        : MATERIA_LABELS[m] || m
    )
    .join(", ");

  const periodoTexto = PERIODO_LABELS[cronograma.periodo_preferido] || "não informado";
  const duracaoTexto = DURACAO_LABELS[cronograma.duracao_foco] || "não informado";

  // Rotina atual do aluno (horários já ocupados), só dos dias em que ele pode estudar.
  const rotinaTexto = DIAS_ORDEM.filter((d) => (rotina[d] || []).length > 0)
    .map(
      (d) =>
        `- ${DIA_LABELS[d]}: ` +
        rotina[d].map((i) => `${i.inicio} às ${i.fim} (${i.descricao})`).join("; ")
    )
    .join("\n");

  return `Você é um orientador de rotina e produtividade para estudantes.
Monte uma proposta de cronograma semanal de estudos PERSONALIZADO para este aluno, com base exclusivamente nos dados abaixo (não invente compromissos fixos como escola/trabalho que não foram informados).

Dados do perfil do aluno (criados na conta):
- Série/ano: ${serieTexto}
- Rede de ensino: ${redeTexto}
- Curso/foco: ${perfil.curso_desejado || "não informado"}
- Universidade de interesse: ${perfil.universidade_desejada || "não informado"}
- Tipo de instituição superior desejada: ${perfil.tipo_universidade || "não informado"}
- Meta/objetivo principal: ${objetivoTexto}

Preferências de estudo (formulário de cronograma personalizado):
- Horas disponíveis por dia: ${cronograma.horas_por_dia}
- Dias da semana disponíveis: ${diasTexto || "não informado"}
- Matérias consideradas mais difíceis (precisam de mais atenção): ${materiasTexto || "não informado"}
- Período do dia preferido para estudar: ${periodoTexto}
- Duração ideal de cada bloco de foco: ${duracaoTexto}
${
  rotinaTexto
    ? `
Rotina atual do aluno (horários já ocupados com estes compromissos):
${rotinaTexto}
`
    : ""
}
Instruções:
- Distribua os estudos apenas nos dias da semana informados como disponíveis.
- Priorize as matérias difíceis nos horários de melhor concentração (dentro do período preferido informado).
- Use blocos de foco com a duração informada, incluindo pequenas pausas entre eles.
- Respeite o total de horas por dia informado (não ultrapasse).${
    rotinaTexto
      ? "\n- NÃO marque estudo nos horários ocupados pela rotina atual do aluno; encaixe os estudos nos intervalos livres de cada dia."
      : ""
  }
- A rotina deve ajudar o aluno a atingir a meta/objetivo informado no perfil.
- Se algum dado estiver "não informado", monte algo simples e equilibrado para aquele ponto, sem inventar detalhes específicos.

Responda SOMENTE com um JSON válido, sem markdown, sem crases, no seguinte formato exato (inclua apenas os dias informados como disponíveis; para os demais dias, retorne "rotina": [] e um "resumo" curto dizendo que é um dia de descanso):
{
  "Segunda-feira": {
    "resumo": "uma frase curta explicando o foco do dia",
    "rotina": [
      { "horario": "19:00", "atividade": "Matemática - revisão de funções" }
    ]
  },
  "Terça-feira": { "resumo": "...", "rotina": [ ... ] },
  "Quarta-feira": { "resumo": "...", "rotina": [ ... ] },
  "Quinta-feira": { "resumo": "...", "rotina": [ ... ] },
  "Sexta-feira": { "resumo": "...", "rotina": [ ... ] },
  "Sábado": { "resumo": "...", "rotina": [ ... ] },
  "Domingo": { "resumo": "...", "rotina": [ ... ] }
}`;
}

// Gera (ou regenera) o cronograma personalizado via IA e salva em sugestoes_ia.
app.post("/api/assistente-ia/:usuarioId", async (req, res) => {
  const usuarioId = parseInt(req.params.usuarioId, 10);

  if (isNaN(usuarioId)) {
    return res.status(400).json({ erro: "ID de usuário inválido." });
  }

  if (!process.env.N8N_WEBHOOK_URL || !process.env.N8N_WEBHOOK_AUTH_VALUE) {
    return res
      .status(500)
      .json({ erro: "N8N_WEBHOOK_URL/N8N_WEBHOOK_AUTH_VALUE não configurados no servidor." });
  }

  try {
    const perfilResultado = await pool.query(
      `SELECT serie, rede_ensino, curso_desejado, universidade_desejada,
              tipo_universidade, objetivo_geral
       FROM perfil_academico WHERE usuario_id = $1`,
      [usuarioId]
    );

    if (perfilResultado.rows.length === 0) {
      return res.status(404).json({ erro: "Usuário não encontrado." });
    }

    const cronogramaResultado = await pool.query(
      `SELECT horas_por_dia, dias_semana, materias_dificeis,
              materia_dificil_outra, periodo_preferido, duracao_foco
       FROM cronograma_preferencias
       WHERE usuario_id = $1`,
      [usuarioId]
    );

    if (cronogramaResultado.rows.length === 0) {
      return res.status(404).json({
        erro: "Preencha o Cronograma Personalizado antes de gerar o Assistente IA.",
      });
    }

    const perfil = perfilResultado.rows[0];
    const cronograma = cronogramaResultado.rows[0];
    const rotina = await buscarRotinaUsuario(usuarioId);
    const prompt = montarPromptAssistente(perfil, cronograma, rotina);

    // Chama o webhook do seu workflow n8n (que por sua vez chama o Ollama
    // dentro do próprio workflow). Trocar de IA ou treinar o modelo no
    // futuro passa a ser só mexer no workflow — o server.js nem fica
    // sabendo, ele só manda o prompt e espera o texto de volta.
    const nomeCabecalho = process.env.N8N_WEBHOOK_AUTH_HEADER || "Authorization";

    const respostaN8n = await fetch(process.env.N8N_WEBHOOK_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        [nomeCabecalho]: process.env.N8N_WEBHOOK_AUTH_VALUE,
      },
      body: JSON.stringify({ prompt }),
    });

    if (!respostaN8n.ok) {
      const erroAPI = await respostaN8n.json().catch(() => ({}));
      console.error("Erro do webhook n8n:", erroAPI);
      return res.status(502).json({
        erro: `Erro ${respostaN8n.status} ao chamar o n8n: ${
          erroAPI.erro || erroAPI.error || erroAPI.message || "Falha na requisição"
        }`,
      });
    }

    const dataN8n = await respostaN8n.json();

    // O n8n pode devolver formatos diferentes dependendo de como o workflow
    // termina (nó "Respond to Webhook" ou resposta automática). Tentamos os
    // formatos mais comuns antes de desistir.
    const item = Array.isArray(dataN8n) ? dataN8n[0] : dataN8n;
    const corpo = item?.json ?? item;
    const textoResposta =
      corpo?.response ?? corpo?.text ?? corpo?.output ?? corpo?.message?.content;

    if (!textoResposta) {
      console.error("Formato de resposta do n8n não reconhecido:", JSON.stringify(dataN8n));
      return res.status(502).json({
        erro: "A IA não retornou uma resposta em um formato reconhecido (veja o log do servidor).",
      });
    }

    const limpo = textoResposta
      .trim()
      .replace(/^```json/i, "")
      .replace(/^```/, "")
      .replace(/```$/, "")
      .trim();

    let plano;
    try {
      plano = JSON.parse(limpo);
    } catch (e) {
      console.error("Erro no JSON retornado pela IA:", limpo);
      return res
        .status(502)
        .json({ erro: "A IA não respondeu no formato JSON correto." });
    }

    // interacao_ia exige plano_id (NOT NULL), então garante um objetivo_estudo
    // 'geral' e cria um plano_estudo novo a cada geração antes de logar a interação.
    const objetivoGeralResultado = await pool.query(
      `INSERT INTO objetivo_estudo (usuario_id, tipo_objetivo, descricao, objetivo_principal, ativo)
       VALUES ($1, 'geral', $2, true, true)
       ON CONFLICT (usuario_id, tipo_objetivo) DO UPDATE SET descricao = EXCLUDED.descricao
       RETURNING id`,
      [usuarioId, perfil.objetivo_geral || null]
    );

    const planoResultado = await pool.query(
      `INSERT INTO plano_estudo (usuario_id, objetivo_id, gerado_por_ia, status)
       VALUES ($1, $2, true, 1)
       RETURNING id`,
      [usuarioId, objetivoGeralResultado.rows[0].id]
    );

    await pool.query(
      `INSERT INTO interacao_ia
        (usuario_id, plano_id, tipo, prompt_enviado, resposta_recebida, modelo_ia, status)
       VALUES ($1, $2, 'cronograma', $3, $4, 'qwen3:1.7b', 'concluido')`,
      [usuarioId, planoResultado.rows[0].id, prompt, JSON.stringify(plano)]
    );

    res.json({ sucesso: true, plano });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro ao gerar cronograma com IA." });
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
      `SELECT resposta_recebida, criado_em
       FROM interacao_ia
       WHERE usuario_id = $1 AND tipo = 'cronograma'
       ORDER BY criado_em DESC
       LIMIT 1`,
      [usuarioId]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({ erro: "Nenhuma sugestão gerada ainda." });
    }

    let plano;
    try {
      plano = JSON.parse(resultado.rows[0].resposta_recebida);
    } catch (e) {
      return res.status(500).json({ erro: "Sugestão salva está corrompida." });
    }

    res.json({
      plano,
      geradoEm: resultado.rows[0].criado_em,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro ao buscar sugestão salva." });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});