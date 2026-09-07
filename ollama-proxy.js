// ollama-proxy.js
//
// Roda AO LADO do Ollama na sua VM da Oracle Cloud (não no Render/Vercel).
// O Ollama sozinho não tem senha nenhuma na API dele — esse proxy fica na
// frente, exige uma chave secreta em todo pedido, e só então repassa pro
// Ollama (que fica escutando só em 127.0.0.1, nunca exposto direto).
//
// Como rodar (na VM):
//   PROXY_SECRET="sua_chave_secreta" PORT=8443 node ollama-proxy.js
//
// Requer Node.js 18+ (usa o fetch() nativo).

const http = require("http");

const OLLAMA_URL = "http://127.0.0.1:11434";
const SECRET = process.env.PROXY_SECRET;
const PORT = process.env.PORT || 8443;

if (!SECRET) {
  console.error("Defina a variável PROXY_SECRET antes de iniciar o proxy.");
  process.exit(1);
}

const server = http.createServer((req, res) => {
  const auth = req.headers["authorization"];

  if (auth !== `Bearer ${SECRET}`) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ erro: "Não autorizado." }));
    return;
  }

  let body = "";
  req.on("data", (chunk) => {
    body += chunk;
  });

  req.on("end", async () => {
    try {
      const respostaOllama = await fetch(`${OLLAMA_URL}${req.url}`, {
        method: req.method,
        headers: { "Content-Type": "application/json" },
        body: req.method === "POST" ? body : undefined,
      });

      const texto = await respostaOllama.text();
      res.writeHead(respostaOllama.status, { "Content-Type": "application/json" });
      res.end(texto);
    } catch (err) {
      console.error("Erro ao repassar para o Ollama:", err.message);
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ erro: "Erro ao falar com o Ollama." }));
    }
  });
});

server.listen(PORT, () => {
  console.log(`Proxy do Ollama rodando na porta ${PORT}`);
});
