const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

// JWT_SECRET precisa ser configurado como variável de ambiente no Railway (Settings -> Variables).
// Se não for definido, o servidor gera um valor aleatório só para essa execução (todo mundo
// é deslogado a cada reinício) -- funciona para testar, mas defina uma variável fixa em produção.
const JWT_SECRET = process.env.JWT_SECRET || require("crypto").randomBytes(32).toString("hex");
const IS_PROD = process.env.NODE_ENV === "production";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

app.use(express.json({ limit: "5mb" }));
app.use(cookieParser());
app.use(express.static(__dirname));

const ROLES = ["admin", "comercial", "operacional"];

async function initDb() {
  await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto;`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin','comercial','operacional')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS clients (
      id TEXT PRIMARY KEY,
      data JSONB NOT NULL,
      updated_by TEXT,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pricing_config (
      id INTEGER PRIMARY KEY DEFAULT 1,
      data JSONB NOT NULL DEFAULT '{}',
      updated_by TEXT,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS google_accounts (
      user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      access_token TEXT NOT NULL,
      refresh_token TEXT,
      expiry_date TIMESTAMPTZ NOT NULL,
      email TEXT
    );
  `);

  // Migração de continuidade: se existir o antigo app_state (versão anterior, sem login),
  // importa os dados de lá para as tabelas novas na primeira vez que o servidor novo sobe.
  const legacy = await pool.query("SELECT to_regclass('app_state') as exists");
  if (legacy.rows[0].exists) {
    const { rows } = await pool.query("SELECT clients, pricing_config FROM app_state WHERE id = 1");
    if (rows.length) {
      const clientCount = await pool.query("SELECT count(*) FROM clients");
      if (Number(clientCount.rows[0].count) === 0 && Array.isArray(rows[0].clients)) {
        for (const c of rows[0].clients) {
          await pool.query(
            "INSERT INTO clients (id, data, updated_by) VALUES ($1, $2, 'migração') ON CONFLICT (id) DO NOTHING",
            [c.id, JSON.stringify(c)]
          );
        }
        console.log(`Migrados ${rows[0].clients.length} clientes do app_state antigo.`);
      }
      const pricingCount = await pool.query("SELECT count(*) FROM pricing_config");
      if (Number(pricingCount.rows[0].count) === 0 && rows[0].pricing_config) {
        await pool.query("INSERT INTO pricing_config (id, data, updated_by) VALUES (1, $1, 'migração')", [
          JSON.stringify(rows[0].pricing_config),
        ]);
        console.log("Precificação migrada do app_state antigo.");
      }
    }
  }

  const pricingRow = await pool.query("SELECT id FROM pricing_config WHERE id = 1");
  if (pricingRow.rows.length === 0) {
    await pool.query("INSERT INTO pricing_config (id, data, updated_by) VALUES (1, '{}', 'sistema')");
  }
}

// ---- Autenticação ----

function setAuthCookie(res, user) {
  const token = jwt.sign({ id: user.id, email: user.email, name: user.name, role: user.role }, JWT_SECRET, {
    expiresIn: "30d",
  });
  res.cookie("crm_token", token, {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: "lax",
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
}

function requireAuth(req, res, next) {
  const token = req.cookies.crm_token;
  if (!token) return res.status(401).json({ error: "Não autenticado." });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Sessão inválida ou expirada." });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Você não tem permissão para fazer isso." });
    }
    next();
  };
}

// Primeiro acesso: cria a conta admin, só funciona se ainda não existir nenhum usuário.
app.post("/api/auth/setup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password || password.length < 6) {
    return res.status(400).json({ error: "Preencha nome, e-mail e uma senha com pelo menos 6 caracteres." });
  }
  const { rows } = await pool.query("SELECT count(*) FROM users");
  if (Number(rows[0].count) > 0) {
    return res.status(403).json({ error: "Já existe uma conta configurada. Peça um convite ao administrador." });
  }
  const hash = await bcrypt.hash(password, 10);
  const result = await pool.query(
    "INSERT INTO users (email, password_hash, name, role) VALUES ($1,$2,$3,'admin') RETURNING id, email, name, role",
    [email.toLowerCase().trim(), hash, name.trim()]
  );
  setAuthCookie(res, result.rows[0]);
  res.json({ user: result.rows[0] });
});

app.get("/api/auth/needs-setup", async (req, res) => {
  const { rows } = await pool.query("SELECT count(*) FROM users");
  res.json({ needsSetup: Number(rows[0].count) === 0 });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const { rows } = await pool.query("SELECT * FROM users WHERE email = $1", [(email || "").toLowerCase().trim()]);
  if (rows.length === 0) return res.status(401).json({ error: "E-mail ou senha incorretos." });
  const ok = await bcrypt.compare(password || "", rows[0].password_hash);
  if (!ok) return res.status(401).json({ error: "E-mail ou senha incorretos." });
  const user = { id: rows[0].id, email: rows[0].email, name: rows[0].name, role: rows[0].role };
  setAuthCookie(res, user);
  res.json({ user });
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("crm_token");
  res.json({ ok: true });
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// Gestão de equipe (só admin)
app.get("/api/users", requireAuth, requireRole("admin"), async (req, res) => {
  const { rows } = await pool.query("SELECT id, email, name, role, created_at FROM users ORDER BY created_at");
  res.json({ users: rows });
});

app.post("/api/users", requireAuth, requireRole("admin"), async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password || password.length < 6 || !ROLES.includes(role)) {
    return res.status(400).json({ error: "Dados inválidos. Confira nome, e-mail, senha (6+ caracteres) e papel." });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (email, password_hash, name, role) VALUES ($1,$2,$3,$4) RETURNING id, email, name, role",
      [email.toLowerCase().trim(), hash, name.trim(), role]
    );
    res.json({ user: result.rows[0] });
  } catch (err) {
    if (err.code === "23505") return res.status(409).json({ error: "Já existe uma conta com esse e-mail." });
    console.error(err);
    res.status(500).json({ error: "Não foi possível criar o usuário." });
  }
});

app.delete("/api/users/:id", requireAuth, requireRole("admin"), async (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: "Você não pode remover sua própria conta." });
  await pool.query("DELETE FROM users WHERE id = $1", [req.params.id]);
  res.json({ ok: true });
});

// ---- Clientes (um registro por linha) ----

app.get("/api/clients", requireAuth, async (req, res) => {
  const { rows } = await pool.query("SELECT data FROM clients ORDER BY updated_at");
  res.json({ clients: rows.map((r) => r.data) });
});

// Upsert em lote -- comercial e admin podem criar/editar clientes e vendas.
app.put("/api/clients", requireAuth, requireRole("admin", "comercial"), async (req, res) => {
  const { clients } = req.body;
  if (!Array.isArray(clients)) return res.status(400).json({ error: "Formato inválido." });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const c of clients) {
      await client.query(
        `INSERT INTO clients (id, data, updated_by, updated_at) VALUES ($1,$2,$3, now())
         ON CONFLICT (id) DO UPDATE SET data = $2, updated_by = $3, updated_at = now()`,
        [c.id, JSON.stringify(c), req.user.email]
      );
    }
    await client.query("COMMIT");
    res.json({ ok: true });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error(err);
    res.status(500).json({ error: "Não foi possível salvar os clientes." });
  } finally {
    client.release();
  }
});

// Caminho restrito para o time operacional: só pode mexer na etapa de integração de um cliente,
// nunca nos dados comerciais, valores ou cadastro.
app.put("/api/clients/:id/onboard-stage", requireAuth, requireRole("admin", "comercial", "operacional"), async (req, res) => {
  const { onboardStage } = req.body;
  const { rows } = await pool.query("SELECT data FROM clients WHERE id = $1", [req.params.id]);
  if (rows.length === 0) return res.status(404).json({ error: "Cliente não encontrado." });
  const updated = { ...rows[0].data, onboardStage };
  await pool.query("UPDATE clients SET data = $1, updated_by = $2, updated_at = now() WHERE id = $3", [
    JSON.stringify(updated),
    req.user.email,
    req.params.id,
  ]);
  res.json({ client: updated });
});

app.delete("/api/clients/:id", requireAuth, requireRole("admin"), async (req, res) => {
  await pool.query("DELETE FROM clients WHERE id = $1", [req.params.id]);
  res.json({ ok: true });
});

// ---- Estrutura de precificação (sensível -- só admin e comercial visualizam, só admin edita) ----

app.get("/api/pricing", requireAuth, requireRole("admin", "comercial"), async (req, res) => {
  const { rows } = await pool.query("SELECT data FROM pricing_config WHERE id = 1");
  res.json({ pricingConfig: rows[0] ? rows[0].data : {} });
});

app.put("/api/pricing", requireAuth, requireRole("admin"), async (req, res) => {
  const { pricingConfig } = req.body;
  await pool.query(
    `INSERT INTO pricing_config (id, data, updated_by, updated_at) VALUES (1, $1, $2, now())
     ON CONFLICT (id) DO UPDATE SET data = $1, updated_by = $2, updated_at = now()`,
    [JSON.stringify(pricingConfig || {}), req.user.email]
  );
  res.json({ ok: true });
});

// ---- Lista básica de usuários (qualquer pessoa logada pode ver nome/id, para escolher o
// responsável por uma próxima ação -- sem dados sensíveis, diferente de /api/users que é admin-only) ----

app.get("/api/users/basic", requireAuth, async (req, res) => {
  const { rows } = await pool.query("SELECT id, name FROM users ORDER BY name");
  res.json({ users: rows });
});

// ---- Google Agenda (OAuth por usuário) ----

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI; // ex: https://seu-app.up.railway.app/api/google/callback

app.get("/api/google/connect", requireAuth, (req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_REDIRECT_URI) {
    return res.status(500).send("Integração com Google não configurada (faltam variáveis de ambiente no servidor).");
  }
  const state = jwt.sign({ userId: req.user.id }, JWT_SECRET, { expiresIn: "10m" });
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: "code",
    scope: "https://www.googleapis.com/auth/calendar.events email",
    access_type: "offline",
    prompt: "consent",
    state,
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
});

app.get("/api/google/callback", async (req, res) => {
  const { code, state } = req.query;
  try {
    const { userId } = jwt.verify(state, JWT_SECRET);
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: GOOGLE_REDIRECT_URI,
        grant_type: "authorization_code",
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error("Falha ao obter token do Google");

    const profileRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const profile = await profileRes.json();

    const expiryDate = new Date(Date.now() + (tokenData.expires_in || 3600) * 1000);
    await pool.query(
      `INSERT INTO google_accounts (user_id, access_token, refresh_token, expiry_date, email)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (user_id) DO UPDATE SET
         access_token = $2,
         refresh_token = COALESCE($3, google_accounts.refresh_token),
         expiry_date = $4,
         email = $5`,
      [userId, tokenData.access_token, tokenData.refresh_token || null, expiryDate, profile.email || null]
    );
    res.send(`<script>window.close ? window.close() : window.location.href="/"; window.location.href="/";</script>Conectado! Pode fechar esta aba e voltar ao CRM.`);
  } catch (err) {
    console.error("Erro no callback do Google:", err);
    res.status(500).send("Não foi possível conectar sua conta do Google. Feche esta aba e tente novamente.");
  }
});

app.get("/api/google/status", requireAuth, async (req, res) => {
  const { rows } = await pool.query("SELECT email FROM google_accounts WHERE user_id = $1", [req.user.id]);
  res.json({ connected: rows.length > 0, email: rows.length > 0 ? rows[0].email : null });
});

app.post("/api/google/disconnect", requireAuth, async (req, res) => {
  await pool.query("DELETE FROM google_accounts WHERE user_id = $1", [req.user.id]);
  res.json({ ok: true });
});

async function getValidGoogleAccessToken(userId) {
  const { rows } = await pool.query("SELECT * FROM google_accounts WHERE user_id = $1", [userId]);
  if (rows.length === 0) return null;
  const acc = rows[0];
  if (new Date(acc.expiry_date) > new Date(Date.now() + 60000)) {
    return acc.access_token;
  }
  if (!acc.refresh_token) return null;
  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      refresh_token: acc.refresh_token,
      grant_type: "refresh_token",
    }),
  });
  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) return null;
  const expiryDate = new Date(Date.now() + (tokenData.expires_in || 3600) * 1000);
  await pool.query("UPDATE google_accounts SET access_token = $1, expiry_date = $2 WHERE user_id = $3", [
    tokenData.access_token,
    expiryDate,
    userId,
  ]);
  return tokenData.access_token;
}

// Cria (ou atualiza, se já existir eventId salvo) um evento no Google Agenda do responsável indicado.
app.post("/api/google/events", requireAuth, async (req, res) => {
  const { responsavelUserId, title, description, date, existingEventId } = req.body;
  if (!responsavelUserId || !title || !date) {
    return res.status(400).json({ error: "Faltam dados (responsável, título ou data)." });
  }
  const accessToken = await getValidGoogleAccessToken(responsavelUserId);
  if (!accessToken) {
    return res.status(409).json({ error: "Essa pessoa ainda não conectou o Google Agenda dela." });
  }

  const eventBody = {
    summary: title,
    description: description || "",
    start: { date }, // evento de dia inteiro
    end: { date },
  };

  try {
    const url = existingEventId
      ? `https://www.googleapis.com/calendar/v3/calendars/primary/events/${existingEventId}`
      : `https://www.googleapis.com/calendar/v3/calendars/primary/events`;
    const method = existingEventId ? "PATCH" : "POST";
    const gRes = await fetch(url, {
      method,
      headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify(eventBody),
    });
    const gData = await gRes.json();
    if (!gRes.ok) throw new Error(gData.error?.message || "Erro do Google Agenda");
    res.json({ eventId: gData.id, htmlLink: gData.htmlLink });
  } catch (err) {
    console.error("Erro ao criar evento no Google:", err);
    res.status(500).json({ error: "Não foi possível criar o evento no Google Agenda." });
  }
});

app.delete("/api/google/events/:eventId", requireAuth, async (req, res) => {
  const { responsavelUserId } = req.query;
  const accessToken = await getValidGoogleAccessToken(responsavelUserId);
  if (!accessToken) return res.json({ ok: true }); // sem conta conectada, nada a apagar
  try {
    await fetch(`https://www.googleapis.com/calendar/v3/calendars/primary/events/${req.params.eventId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${accessToken}` },
    });
  } catch (err) {
    console.error("Erro ao remover evento do Google:", err);
  }
  res.json({ ok: true });
});

app.get("*", (req, res) => {
  res.set("Cache-Control", "no-cache, no-store, must-revalidate");
  res.sendFile(path.join(__dirname, "index.html"));
});

initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`CRM rodando na porta ${PORT}`));
  })
  .catch((err) => {
    console.error("Erro ao iniciar o banco de dados:", err);
    process.exit(1);
  });
