-- =====================================================================
-- ROTA DO SUCESSO — Schema PostgreSQL
-- Módulos: Rotina Diária | Objetivos e Dificuldades de Estudo
--
-- Pressupõe que já existe uma tabela `usuarios(id SERIAL PRIMARY KEY, ...)`
-- criada pelo módulo de login/criação de conta. Ajuste o nome/tipo da FK
-- (usuario_id) se a tabela de usuários usar outro nome ou UUID.
-- =====================================================================

-- =====================================================================
-- MÓDULO 2 — ROTINA DIÁRIA
-- =====================================================================

-- Preferências gerais do aluno em relação aos estudos (1 registro por aluno).
CREATE TABLE IF NOT EXISTS rotina_preferencias (
    usuario_id          INTEGER PRIMARY KEY REFERENCES usuarios(id) ON DELETE CASCADE,
    horas_por_dia       NUMERIC(4,1) NOT NULL CHECK (horas_por_dia >= 0 AND horas_por_dia <= 24),
    dias_semana         TEXT[] NOT NULL DEFAULT '{}',      -- ex: {seg,ter,qua}
    periodo_preferido   SMALLINT,                          -- 1=Manhã 2=Tarde 3=Noite 4=Madrugada
    duracao_foco        SMALLINT,                          -- 1=15min 2=25min 3=30min 4=45min 5=1h+
    criado_em           TIMESTAMPTZ NOT NULL DEFAULT now(),
    atualizado_em       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Compromissos fixos da semana (escola, cursos, esportes, deslocamento,
-- sono, horários livres etc). Um compromisso é sempre amarrado a UM dia
-- da semana — dias diferentes podem ter rotinas totalmente diferentes.
CREATE TABLE IF NOT EXISTS rotina_compromissos (
    id              SERIAL PRIMARY KEY,
    usuario_id      INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
    dia_semana      VARCHAR(3) NOT NULL CHECK (dia_semana IN ('seg','ter','qua','qui','sex','sab','dom')),
    hora_inicio     TIME NOT NULL,
    hora_fim        TIME NOT NULL,
    descricao       VARCHAR(100) NOT NULL,
    tipo            VARCHAR(20) CHECK (tipo IN (
                        'escola','deslocamento','curso','esporte',
                        'atividade_fixa','horario_livre','sono','outro'
                    )),
    criado_em       TIMESTAMPTZ NOT NULL DEFAULT now(),
    atualizado_em   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (hora_fim <> hora_inicio)
);

CREATE INDEX IF NOT EXISTS idx_rotina_compromissos_usuario_dia
    ON rotina_compromissos (usuario_id, dia_semana);

-- =====================================================================
-- MÓDULO 3 — OBJETIVOS E DIFICULDADES DE ESTUDO
-- =====================================================================

CREATE TABLE IF NOT EXISTS objetivos_estudo (
    usuario_id                   INTEGER PRIMARY KEY REFERENCES usuarios(id) ON DELETE CASCADE,
    objetivos                    TEXT[] NOT NULL DEFAULT '{}',   -- ex: {"passar no ENEM","subir a média em matemática"}
    disciplinas_dificuldade      TEXT[] NOT NULL DEFAULT '{}',
    disciplina_dificuldade_outra VARCHAR(100),
    prioridades                  TEXT[] NOT NULL DEFAULT '{}',   -- o que o aluno quer atacar primeiro
    tem_prova_marcada            BOOLEAN NOT NULL DEFAULT false,
    data_prova                   DATE,
    detalhes_prova               VARCHAR(255),
    tipo_vestibular              VARCHAR(30) CHECK (tipo_vestibular IN ('enem','vestibular','concurso','nenhum','outro')),
    vestibular_outro             VARCHAR(100),
    observacoes                  TEXT,
    criado_em                    TIMESTAMPTZ NOT NULL DEFAULT now(),
    atualizado_em                TIMESTAMPTZ NOT NULL DEFAULT now()
);
