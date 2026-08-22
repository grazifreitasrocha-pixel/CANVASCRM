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
  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      message TEXT NOT NULL,
      client_id TEXT,
      read BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS integration_settings (
      id INTEGER PRIMARY KEY DEFAULT 1,
      trello_board_id TEXT,
      trello_list_map JSONB NOT NULL DEFAULT '{}',
      trello_webhook_id TEXT,
      trello_template_card_id TEXT,
      legal_board_id TEXT,
      legal_list_map JSONB NOT NULL DEFAULT '{}',
      legal_webhook_id TEXT,
      legal_template_card_id TEXT,
      updated_by TEXT,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  // Migração leve: garante as colunas novas em bancos que já tinham a tabela antiga.
  await pool.query(`ALTER TABLE integration_settings ADD COLUMN IF NOT EXISTS trello_template_card_id TEXT;`);
  await pool.query(`ALTER TABLE integration_settings ADD COLUMN IF NOT EXISTS legal_board_id TEXT;`);
  await pool.query(`ALTER TABLE integration_settings ADD COLUMN IF NOT EXISTS legal_list_map JSONB NOT NULL DEFAULT '{}';`);
  await pool.query(`ALTER TABLE integration_settings ADD COLUMN IF NOT EXISTS legal_webhook_id TEXT;`);
  await pool.query(`ALTER TABLE integration_settings ADD COLUMN IF NOT EXISTS legal_template_card_id TEXT;`);
  await pool.query(`ALTER TABLE integration_settings ADD COLUMN IF NOT EXISTS agenda_base_url TEXT;`);
  await pool.query(`ALTER TABLE integration_settings ADD COLUMN IF NOT EXISTS agenda_slug_map JSONB NOT NULL DEFAULT '{}';`);
  await pool.query(`INSERT INTO integration_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING`);

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

// ---- Notificações internas ----

app.get("/api/notifications", requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    "SELECT id, message, client_id, read, created_at FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 30",
    [req.user.id]
  );
  res.json({ notifications: rows });
});

app.post("/api/notifications", requireAuth, async (req, res) => {
  // Qualquer usuário autenticado pode criar uma notificação para outro usuário (ex: vendedor
  // notificando o responsável pela integração ao marcar uma venda como ganha).
  const { userId, message, clientId } = req.body;
  if (!userId || !message) return res.status(400).json({ error: "Faltam dados." });
  const result = await pool.query(
    "INSERT INTO notifications (user_id, message, client_id) VALUES ($1, $2, $3) RETURNING id, message, client_id, read, created_at",
    [userId, message, clientId || null]
  );
  res.json({ notification: result.rows[0] });
});

app.post("/api/notifications/:id/read", requireAuth, async (req, res) => {
  await pool.query("UPDATE notifications SET read = true WHERE id = $1 AND user_id = $2", [req.params.id, req.user.id]);
  res.json({ ok: true });
});

app.post("/api/notifications/read-all", requireAuth, async (req, res) => {
  await pool.query("UPDATE notifications SET read = true WHERE user_id = $1 AND read = false", [req.user.id]);
  res.json({ ok: true });
});

// ---- Integração com Trello (dois boards: "Integração do Cliente" para Assessoria Contábil,
// e "Legal – Serviços Empresariais" para os demais produtos) ----

const TRELLO_API_KEY = process.env.TRELLO_API_KEY;
const TRELLO_TOKEN = process.env.TRELLO_TOKEN;
const TRELLO_CONFIGURED = !!(TRELLO_API_KEY && TRELLO_TOKEN);

function trelloAuthQS() {
  return `key=${TRELLO_API_KEY}&token=${TRELLO_TOKEN}`;
}

// board: "integracao" | "legal"
const BOARD_COLUMNS = {
  integracao: { boardId: "trello_board_id", listMap: "trello_list_map", webhookId: "trello_webhook_id", templateCardId: "trello_template_card_id" },
  legal: { boardId: "legal_board_id", listMap: "legal_list_map", webhookId: "legal_webhook_id", templateCardId: "legal_template_card_id" },
};

app.get("/api/trello/settings", requireAuth, requireRole("admin"), async (req, res) => {
  const { rows } = await pool.query(
    "SELECT trello_board_id, trello_list_map, trello_webhook_id, trello_template_card_id, legal_board_id, legal_list_map, legal_webhook_id, legal_template_card_id FROM integration_settings WHERE id = 1"
  );
  const row = rows[0] || {};
  res.json({
    configured: TRELLO_CONFIGURED,
    integracao: {
      boardId: row.trello_board_id || "",
      listMap: row.trello_list_map || {},
      webhookActive: !!row.trello_webhook_id,
      templateCardId: row.trello_template_card_id || "",
    },
    legal: {
      boardId: row.legal_board_id || "",
      listMap: row.legal_list_map || {},
      webhookActive: !!row.legal_webhook_id,
      templateCardId: row.legal_template_card_id || "",
    },
  });
});

app.put("/api/trello/settings/:board", requireAuth, requireRole("admin"), async (req, res) => {
  const cols = BOARD_COLUMNS[req.params.board];
  if (!cols) return res.status(400).json({ error: "Board inválido." });
  const { boardId, listMap, templateCardId } = req.body;
  await pool.query(
    `UPDATE integration_settings SET ${cols.boardId} = $1, ${cols.listMap} = $2, ${cols.templateCardId} = $3, updated_by = $4, updated_at = now() WHERE id = 1`,
    [boardId || null, JSON.stringify(listMap || {}), templateCardId || null, req.user.email]
  );
  res.json({ ok: true });
});

// Busca as listas de um board do Trello, pra montar os selects de mapeamento na tela.
app.get("/api/trello/board-lists", requireAuth, requireRole("admin"), async (req, res) => {
  if (!TRELLO_CONFIGURED) return res.status(500).json({ error: "Integração com Trello não configurada (faltam variáveis de ambiente no servidor)." });
  const { boardId } = req.query;
  if (!boardId) return res.status(400).json({ error: "Informe o ID do board." });
  try {
    const r = await fetch(`https://api.trello.com/1/boards/${boardId}/lists?${trelloAuthQS()}&fields=name`);
    if (!r.ok) throw new Error("Board não encontrado ou credenciais inválidas.");
    const lists = await r.json();
    res.json({ lists: lists.map((l) => ({ id: l.id, name: l.name })) });
  } catch (err) {
    res.status(500).json({ error: err.message || "Não foi possível buscar as listas do board." });
  }
});

async function getBoardSettings(board) {
  const cols = BOARD_COLUMNS[board];
  const { rows } = await pool.query(
    `SELECT ${cols.boardId} as "boardId", ${cols.listMap} as "listMap", ${cols.webhookId} as "webhookId", ${cols.templateCardId} as "templateCardId" FROM integration_settings WHERE id = 1`
  );
  return rows[0] || {};
}

// Cria um card no board indicado ("integracao" ou "legal"), na lista mapeada pra etapa informada.
// Se houver um card-modelo configurado, copia dele (mantém checklists/estrutura padrão do time).
app.post("/api/trello/create-card", requireAuth, async (req, res) => {
  if (!TRELLO_CONFIGURED) return res.status(500).json({ error: "Integração com Trello não configurada." });
  const { board, name, desc, stage } = req.body;
  const cols = BOARD_COLUMNS[board];
  if (!cols) return res.status(400).json({ error: "Board inválido." });
  const settings = await getBoardSettings(board);
  const listId = (settings.listMap || {})[stage];
  if (!listId) return res.status(409).json({ error: `Etapa "${stage}" ainda não está mapeada nesse board. Configure em Integrações.` });
  try {
    const params = new URLSearchParams({
      ...(TRELLO_API_KEY ? { key: TRELLO_API_KEY } : {}),
      token: TRELLO_TOKEN,
      idList: listId,
      name: name || "",
      desc: desc || "",
    });
    if (settings.templateCardId) params.set("idCardSource", settings.templateCardId);
    const r = await fetch(`https://api.trello.com/1/cards?${params.toString()}`, { method: "POST" });
    if (!r.ok) throw new Error("Não foi possível criar o card no Trello.");
    const data = await r.json();
    res.json({ cardId: data.id, url: data.shortUrl });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Move um card existente pra outra lista, conforme a etapa mudar no CRM.
app.put("/api/trello/move-card/:cardId", requireAuth, async (req, res) => {
  if (!TRELLO_CONFIGURED) return res.status(500).json({ error: "Integração com Trello não configurada." });
  const { board, stage } = req.body;
  const cols = BOARD_COLUMNS[board];
  if (!cols) return res.status(400).json({ error: "Board inválido." });
  const settings = await getBoardSettings(board);
  const listId = (settings.listMap || {})[stage];
  if (!listId) return res.status(409).json({ error: "Etapa não mapeada." });
  try {
    const r = await fetch(`https://api.trello.com/1/cards/${req.params.cardId}?${trelloAuthQS()}&idList=${listId}`, { method: "PUT" });
    if (!r.ok) throw new Error("Não foi possível mover o card no Trello.");
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Apaga um card do Trello -- usado quando uma venda/produto é excluído, ou o cliente inteiro é removido.
app.delete("/api/trello/card/:cardId", requireAuth, async (req, res) => {
  if (!TRELLO_CONFIGURED) return res.json({ ok: true }); // sem integração configurada, não há o que apagar
  try {
    await fetch(`https://api.trello.com/1/cards/${req.params.cardId}?${trelloAuthQS()}`, { method: "DELETE" });
  } catch (err) {
    console.error("Erro ao apagar card do Trello:", err);
  }
  res.json({ ok: true });
});

// Registra o webhook de um board específico -- o Trello avisa nosso servidor quando um card mudar.
app.post("/api/trello/register-webhook/:board", requireAuth, requireRole("admin"), async (req, res) => {
  if (!TRELLO_CONFIGURED) return res.status(500).json({ error: "Integração com Trello não configurada." });
  const cols = BOARD_COLUMNS[req.params.board];
  if (!cols) return res.status(400).json({ error: "Board inválido." });
  const settings = await getBoardSettings(req.params.board);
  if (!settings.boardId) return res.status(400).json({ error: "Salve o ID do board antes de registrar a sincronização." });

  const callbackURL = `${req.protocol}://${req.get("host")}/api/trello/webhook`;
  try {
    const r = await fetch(`https://api.trello.com/1/webhooks?${trelloAuthQS()}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ description: `CRM Canvas — ${req.params.board}`, callbackURL, idModel: settings.boardId }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.message || "Não foi possível registrar o webhook.");
    await pool.query(`UPDATE integration_settings SET ${cols.webhookId} = $1 WHERE id = 1`, [data.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/trello/unregister-webhook/:board", requireAuth, requireRole("admin"), async (req, res) => {
  const cols = BOARD_COLUMNS[req.params.board];
  if (!cols) return res.status(400).json({ error: "Board inválido." });
  const settings = await getBoardSettings(req.params.board);
  if (settings.webhookId && TRELLO_CONFIGURED) {
    try {
      await fetch(`https://api.trello.com/1/webhooks/${settings.webhookId}?${trelloAuthQS()}`, { method: "DELETE" });
    } catch {}
  }
  await pool.query(`UPDATE integration_settings SET ${cols.webhookId} = NULL WHERE id = 1`);
  res.json({ ok: true });
});

// O Trello valida a URL do webhook com uma chamada HEAD/GET antes de aceitar o registro.
app.head("/api/trello/webhook", (req, res) => res.sendStatus(200));
app.get("/api/trello/webhook", (req, res) => res.sendStatus(200));

// Recebe os eventos dos dois boards (card movido de lista) -- rota pública, o Trello não manda cookie de login.
app.post("/api/trello/webhook", async (req, res) => {
  res.sendStatus(200); // responde rápido, processa depois
  try {
    const action = req.body && req.body.action;
    if (!action || action.type !== "updateCard" || !action.data || !action.data.listAfter) return;
    const cardId = action.data.card.id;
    const newListId = action.data.listAfter.id;
    const boardId = action.data.board && action.data.board.id;

    const { rows } = await pool.query(
      "SELECT trello_board_id, trello_list_map, legal_board_id, legal_list_map FROM integration_settings WHERE id = 1"
    );
    const settings = rows[0] || {};

    if (boardId && boardId === settings.trello_board_id) {
      // Board de Integração do Cliente -> atualiza client.onboardStage
      const listMap = settings.trello_list_map || {};
      const novaEtapa = Object.keys(listMap).find((stage) => listMap[stage] === newListId);
      if (!novaEtapa) return;
      const { rows: clientRows } = await pool.query("SELECT id, data FROM clients WHERE data->>'trelloCardId' = $1", [cardId]);
      if (clientRows.length === 0) return;
      const client = clientRows[0];
      const updated = { ...client.data, onboardStage: novaEtapa };
      await pool.query("UPDATE clients SET data = $1, updated_by = 'trello', updated_at = now() WHERE id = $2", [
        JSON.stringify(updated),
        client.id,
      ]);
    } else if (boardId && boardId === settings.legal_board_id) {
      // Board Legal – Serviços Empresariais -> atualiza a etapaExecucao do produto correspondente
      const listMap = settings.legal_list_map || {};
      const novaEtapa = Object.keys(listMap).find((stage) => listMap[stage] === newListId);
      if (!novaEtapa) return;
      const { rows: allClients } = await pool.query("SELECT id, data FROM clients");
      const match = allClients.find((c) => (c.data.produtosContratados || []).some((p) => p.trelloCardId === cardId));
      if (!match) return;
      const updatedProdutos = (match.data.produtosContratados || []).map((p) =>
        p.trelloCardId === cardId ? { ...p, etapaExecucao: novaEtapa } : p
      );
      const updated = { ...match.data, produtosContratados: updatedProdutos };
      await pool.query("UPDATE clients SET data = $1, updated_by = 'trello', updated_at = now() WHERE id = $2", [
        JSON.stringify(updated),
        match.id,
      ]);
    }
  } catch (err) {
    console.error("Erro processando webhook do Trello:", err);
  }
});

// ---- Integração com o sistema de agendamento (agenda-app) ----
// Cada colaborador tem um "slug" naquele sistema (ex: sergio-vendas) -- guardamos o mapa
// userId (deste CRM) -> slug (do sistema de agenda) pra saber pra quem bloquear/notificar.

app.get("/api/agenda/settings", requireAuth, requireRole("admin"), async (req, res) => {
  const { rows } = await pool.query("SELECT agenda_base_url, agenda_slug_map FROM integration_settings WHERE id = 1");
  const row = rows[0] || {};
  res.json({ baseUrl: row.agenda_base_url || "", slugMap: row.agenda_slug_map || {} });
});

// Normaliza a URL configurada pra só o domínio (descarta /app.html, /marcar/..., barra final,
// etc.) -- assim cola a URL do jeito que estiver que funciona igual.
function normalizeBaseUrl(url) {
  if (!url) return null;
  try {
    return new URL(url).origin;
  } catch {
    return url.replace(/\/+$/, "");
  }
}

app.put("/api/agenda/settings", requireAuth, requireRole("admin"), async (req, res) => {
  const { baseUrl, slugMap } = req.body;
  await pool.query(
    "UPDATE integration_settings SET agenda_base_url = $1, agenda_slug_map = $2, updated_by = $3, updated_at = now() WHERE id = 1",
    [normalizeBaseUrl(baseUrl), JSON.stringify(slugMap || {}), req.user.email]
  );
  res.json({ ok: true });
});

const AGENDA_INTEGRATION_KEY = process.env.AGENDA_INTEGRATION_KEY;

// CRM -> Agenda: cria ou atualiza a "próxima ação" no calendário do vendedor. Usa o endpoint
// próprio de integração do agenda-app (autenticado por chave, cria/atualiza sem duplicar --
// reenviar o mesmo external_id atualiza em vez de criar de novo).
app.post("/api/agenda/block-slot", requireAuth, async (req, res) => {
  try {
    const { vendedorUserId, externalId, date, time, title, clientName, notes } = req.body;
    if (!vendedorUserId || !date) return res.status(400).json({ error: "Faltam dados (responsável ou data)." });
    if (!AGENDA_INTEGRATION_KEY) return res.status(500).json({ error: "Falta configurar AGENDA_INTEGRATION_KEY no servidor do CRM." });

    const { rows: settingsRows } = await pool.query("SELECT agenda_base_url FROM integration_settings WHERE id = 1");
    const baseUrl = normalizeBaseUrl(settingsRows[0] && settingsRows[0].agenda_base_url);
    if (!baseUrl) return res.status(409).json({ error: "Sistema de agendamento não configurado. Configure a URL em Integrações." });

    const { rows: userRows } = await pool.query("SELECT email FROM users WHERE id = $1", [vendedorUserId]);
    const vendedorEmail = userRows[0] && userRows[0].email;
    if (!vendedorEmail) return res.status(404).json({ error: "Vendedor não encontrado." });

    const r = await fetch(`${baseUrl}/api/integrations/crm/actions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": AGENDA_INTEGRATION_KEY },
      body: JSON.stringify({
        external_id: externalId,
        user_email: vendedorEmail,
        title: title || "Próxima ação (CRM)",
        client_name: clientName || undefined,
        date,
        start_time: time || undefined,
        notes: notes || undefined,
      }),
    });
    const contentType = r.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) {
      const text = await r.text();
      throw new Error(`O sistema de agendamento respondeu algo inesperado (status ${r.status}). Confira a URL configurada. Início da resposta: ${text.slice(0, 120)}`);
    }
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || "Não foi possível sincronizar com a agenda.");
    res.json({ ok: true, bookingId: externalId });
  } catch (err) {
    console.error("Erro em /api/agenda/block-slot:", err);
    res.status(500).json({ error: err.message || "Erro inesperado ao sincronizar com a agenda." });
  }
});

app.post("/api/agenda/remove-action", requireAuth, async (req, res) => {
  const { externalId } = req.body;
  if (!externalId) return res.status(400).json({ error: "Falta o identificador da ação." });
  if (!AGENDA_INTEGRATION_KEY) return res.json({ ok: true }); // sem integração configurada, nada a remover
  const { rows } = await pool.query("SELECT agenda_base_url FROM integration_settings WHERE id = 1");
  const baseUrl = normalizeBaseUrl(rows[0] && rows[0].agenda_base_url);
  if (!baseUrl) return res.json({ ok: true });
  try {
    await fetch(`${baseUrl}/api/integrations/crm/actions/${externalId}`, {
      method: "DELETE",
      headers: { "x-api-key": AGENDA_INTEGRATION_KEY },
    });
  } catch (err) {
    console.error("Erro ao remover ação da agenda:", err);
  }
  res.json({ ok: true });
});

// Agenda -> CRM: recebida quando alguém agenda um horário com um colaborador pelo link
// público do agenda-app. Rota pública -- o agenda-app não manda cookie de login deste CRM.
app.post("/api/agenda/webhook", async (req, res) => {
  res.sendStatus(200); // responde rápido, processa depois
  try {
    const { slug, guest_name, guest_email, date, start_time, notes } = req.body || {};
    if (!slug) return;
    const { rows } = await pool.query("SELECT agenda_slug_map FROM integration_settings WHERE id = 1");
    const slugMap = (rows[0] && rows[0].agenda_slug_map) || {};
    const vendedorUserId = Object.keys(slugMap).find((userId) => slugMap[userId] === slug);
    if (!vendedorUserId) return;

    const message = `Novo agendamento: ${guest_name || "alguém"} marcou um horário com você em ${date} às ${start_time}.${notes ? " Obs: " + notes : ""}`;
    await pool.query("INSERT INTO notifications (user_id, message, client_id) VALUES ($1, $2, NULL)", [vendedorUserId, message]);
  } catch (err) {
    console.error("Erro processando webhook da Agenda:", err);
  }
});

// Rede de segurança: qualquer rota /api/* não encontrada responde em JSON, nunca em HTML
// (isso evita o erro "Unexpected token < in JSON" no navegador quando algo muda de nome/quebra).
app.use("/api", (req, res) => {
  res.status(404).json({ error: `Rota não encontrada: ${req.method} ${req.originalUrl}` });
});

app.get("*", (req, res) => {
  res.set("Cache-Control", "no-cache, no-store, must-revalidate");
  res.sendFile(path.join(__dirname, "index.html"));
});

// Rede de segurança final: qualquer erro não tratado em alguma rota também responde em JSON.
app.use((err, req, res, next) => {
  console.error("Erro não tratado:", err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: "Erro interno do servidor." });
});

initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`CRM rodando na porta ${PORT}`));
  })
  .catch((err) => {
    console.error("Erro ao iniciar o banco de dados:", err);
    process.exit(1);
  });
