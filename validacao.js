// src/utils/validacao.js

const DIAS_VALIDOS = ['seg', 'ter', 'qua', 'qui', 'sex', 'sab', 'dom'];
const TIPOS_COMPROMISSO_VALIDOS = [
    'escola', 'deslocamento', 'curso', 'esporte',
    'atividade_fixa', 'horario_livre', 'sono', 'outro',
];
const TIPOS_VESTIBULAR_VALIDOS = ['enem', 'vestibular', 'concurso', 'nenhum', 'outro'];

const HORA_REGEX = /^([01]\d|2[0-3]):[0-5]\d$/;

function usuarioIdValido(valor) {
    const id = Number(valor);
    return Number.isInteger(id) && id > 0 ? id : null;
}

function validarCompromisso({ diaSemana, inicio, fim, descricao, tipo }) {
    const erros = [];

    if (!DIAS_VALIDOS.includes(diaSemana)) {
        erros.push('Dia da semana inválido.');
    }
    if (!HORA_REGEX.test(inicio || '')) {
        erros.push('Horário de início inválido (use HH:MM).');
    }
    if (!HORA_REGEX.test(fim || '')) {
        erros.push('Horário de fim inválido (use HH:MM).');
    }
    if (inicio === fim) {
        erros.push('O horário de início e de fim não podem ser iguais.');
    }
    if (!descricao || !descricao.trim()) {
        erros.push('Descreva o que você faz nesse horário.');
    } else if (descricao.trim().length > 100) {
        erros.push('A descrição pode ter no máximo 100 caracteres.');
    }
    if (tipo && !TIPOS_COMPROMISSO_VALIDOS.includes(tipo)) {
        erros.push('Tipo de compromisso inválido.');
    }

    return erros;
}

function validarObjetivos(body) {
    const erros = [];
    const {
        objetivos,
        disciplinasDificuldade,
        prioridades,
        temProvaMarcada,
        dataProva,
        tipoVestibular,
    } = body;

    if (objetivos !== undefined && !Array.isArray(objetivos)) {
        erros.push('objetivos deve ser uma lista de textos.');
    }
    if (disciplinasDificuldade !== undefined && !Array.isArray(disciplinasDificuldade)) {
        erros.push('disciplinasDificuldade deve ser uma lista.');
    }
    if (prioridades !== undefined && !Array.isArray(prioridades)) {
        erros.push('prioridades deve ser uma lista.');
    }
    if (temProvaMarcada && !dataProva) {
        erros.push('Informe a data da prova/avaliação.');
    }
    if (tipoVestibular && !TIPOS_VESTIBULAR_VALIDOS.includes(tipoVestibular)) {
        erros.push('Tipo de vestibular/prova inválido.');
    }

    return erros;
}

module.exports = {
    DIAS_VALIDOS,
    TIPOS_COMPROMISSO_VALIDOS,
    TIPOS_VESTIBULAR_VALIDOS,
    usuarioIdValido,
    validarCompromisso,
    validarObjetivos,
};
