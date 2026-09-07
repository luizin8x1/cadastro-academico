-- Rode este script UMA VEZ no SQL Editor do Neon (ou pela extensão do VS Code).
-- Ele NÃO cria a tabela "usuario" (ela já existe no banco) — apenas:
--   1) remove as tabelas antigas (usuarios / perfil_academico), que não são mais usadas
--   2) ajusta duas coisas na tabela "usuario" que já existe, para o site funcionar

DROP TABLE IF EXISTS perfil_academico;
DROP TABLE IF EXISTS usuarios;

ALTER TABLE public.usuario
    ALTER COLUMN senha TYPE character varying(60);

ALTER TABLE public.usuario
    ADD COLUMN IF NOT EXISTS objetivo_outro character varying(150);

-- Referência dos códigos numéricos usados pelo site nesta tabela:
--
-- serie (integer):
--   1 = 5º Ano - Ensino Fundamental      5 = 9º Ano - Ensino Fundamental
--   2 = 6º Ano - Ensino Fundamental      6 = 1º Ano - Ensino Médio
--   3 = 7º Ano - Ensino Fundamental      7 = 2º Ano - Ensino Médio
--   4 = 8º Ano - Ensino Fundamental      8 = 3º Ano - Ensino Médio
--
-- rede_de_ensino / tipo_instituicao_superior (smallint):
--   1 = Pública     2 = Particular
--
-- objetivo (integer):
--   1 = Passar no ENEM              5 = Recuperação escolar
--   2 = Passar no vestibular        6 = Concurso
--   3 = Melhorar minhas notas       7 = Outro (ver objetivo_outro)
--   4 = Organizar meus estudos

-- Tabela do "Cronograma Personalizado" — uma linha por aluno (usuario_id é
-- UNIQUE), guardando as respostas do questionário usado para montar o plano
-- de estudos. Rode isso também no SQL Editor do Neon.
CREATE TABLE IF NOT EXISTS cronograma_preferencias (
    id SERIAL PRIMARY KEY,
    usuario_id INTEGER NOT NULL UNIQUE REFERENCES usuario(id) ON DELETE CASCADE,
    horas_por_dia NUMERIC(3,1) NOT NULL,
    dias_semana TEXT[] NOT NULL,
    materias_dificeis TEXT[] NOT NULL,
    materia_dificil_outra VARCHAR(100),
    periodo_preferido SMALLINT NOT NULL,
    duracao_foco SMALLINT NOT NULL,
    atualizado_em TIMESTAMP DEFAULT NOW()
);

-- Tabela da Sugestão de Estudos gerada por IA — uma linha por aluno
-- (guarda sempre a sugestão mais recente; gerar de novo substitui a anterior).
CREATE TABLE IF NOT EXISTS sugestoes_ia (
    id SERIAL PRIMARY KEY,
    usuario_id INTEGER NOT NULL UNIQUE REFERENCES usuario(id) ON DELETE CASCADE,
    sugestao TEXT NOT NULL,
    gerado_em TIMESTAMP DEFAULT NOW()
);
--
-- dias_semana (cada item do array): 'seg','ter','qua','qui','sex','sab','dom'
--
-- materias_dificeis (cada item do array):
--   'matematica','portugues','fisica','quimica','biologia',
--   'historia','geografia','ingles','redacao','outra'
--   (se incluir 'outra', o texto fica em materia_dificil_outra)
--
-- periodo_preferido (smallint):
--   1 = Manhã   2 = Tarde   3 = Noite   4 = Madrugada
--
-- duracao_foco (smallint):
--   1 = 15 minutos   2 = 25 minutos   3 = 30 minutos
--   4 = 45 minutos   5 = 1 hora ou mais
    