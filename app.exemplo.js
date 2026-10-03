// EXEMPLO de como plugar os dois módulos no seu app Express já existente.
// Não é para substituir seu server.js — copie só as partes relevantes
// (os "require" das rotas e os dois "app.use") para dentro do seu arquivo atual.

const express = require('express');
const app = express();

app.use(express.json());

// ...suas rotas já existentes (login, create_account, etc.) continuam aqui.. .

const rotinaRoutes = require('./routes/rotinaRoutes');
const objetivosRoutes = require('./routes/objetivosRoutes');

app.use('/api/rotina', rotinaRoutes);
app.use('/api/objetivos', objetivosRoutes);

// Observação sobre compatibilidade com o cronograma.html atual:
// o front-end hoje chama GET/POST em /api/cronograma/:usuarioId enviando
// junto materiasDificeis. Como "disciplinas com dificuldade" passou a
// pertencer ao módulo de Objetivos, há duas opções:
//   1) Atualizar o front-end para chamar /api/rotina (sem materiasDificeis)
//      e /api/objetivos (com disciplinasDificuldade) separadamente; ou
//   2) Manter uma rota /api/cronograma/:usuarioId "adaptadora" que recebe
//      o payload antigo e internamente chama os dois controllers acima.
// Recomendo a opção 1, já que separa os dois módulos como pedido.

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));

module.exports = app;
