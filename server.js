require("dotenv").config();

const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const session = require("express-session");
const cors = require("cors");
const path = require("path");
const http = require("http");
const WebSocket = require("ws");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const db = new sqlite3.Database("./messages.db");
const clients = new Map();

/* ================= SECURITY ================= */

app.use(helmet());

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* Login rate limiter */

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15
});

app.use("/login", loginLimiter);

/* ================= SESSION ================= */

app.use(
  session({
    secret: "chat_secure_secret_super_random",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false
    }
  })
);

app.use(express.static(path.join(__dirname, "public")));

/* ================= DATABASE ================= */

db.serialize(() => {

  db.run(`
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      role TEXT DEFAULT 'user'
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS messages(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sender TEXT,
      recipient TEXT,
      content TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  /* Default admin */

  bcrypt.hash("0-admini-1", 10).then(hash => {

    db.get(
      "SELECT * FROM users WHERE username='admin'",
      (err, row) => {

        if (!row) {
          db.run(
            "INSERT INTO users(username,password,role) VALUES(?,?,?)",
            ["admin", hash, "admin"]
          );
        }

      }
    );

  });

});

/* ================= HELPERS ================= */

function sanitizeText(text) {
  return String(text).substring(0, 1000);
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ error: "Admin only" });
  }
  next();
}

/* ================= JWT ================= */

function createToken(user) {

  return jwt.sign(
    {
      username: user.username,
      role: user.role
    },
    process.env.JWT_SECRET || "chat_secret",
    { expiresIn: "24h" }
  );

}

function verifyToken(token) {

  try {
    return jwt.verify(
      token,
      process.env.JWT_SECRET || "chat_secret"
    );
  } catch {
    return null;
  }

}

/* ================= WEBSOCKET ================= */

wss.on("connection", (ws) => {

  let username = null;

  ws.on("message", (data) => {

    if (Buffer.byteLength(data) > 5000) return;

    try {

      const msg = JSON.parse(data);

      if (msg.type === "auth") {

        const decoded = verifyToken(msg.token);

        if (!decoded) return;

        username = decoded.username;
        clients.set(username, ws);

        return;
      }

      if (msg.type === "chat") {

        if (!username) return;

        const content = sanitizeText(msg.content);

        db.run(
          "INSERT INTO messages(sender,recipient,content) VALUES(?,?,?)",
          [username, msg.recipient, content]
        );

        const target = clients.get(msg.recipient);

        if (target && target.readyState === WebSocket.OPEN) {

          target.send(JSON.stringify({
            type: "new_message",
            sender: username,
            content
          }));

        }

      }

    } catch (e) {
      console.log(e);
    }

  });

  ws.on("close", () => {
    if (username) clients.delete(username);
  });

});

/* ================= REGISTER ================= */

app.post("/register", async (req, res) => {

  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: "Missing fields" });
  }

  const hash = await bcrypt.hash(password, 10);

  db.run(
    "INSERT INTO users(username,password) VALUES(?,?)",
    [username, hash],
    (err) => {

      if (err) return res.json({ error: "Username exists" });

      res.json({ success: true });

    }
  );

});

/* ================= LOGIN ================= */

app.post("/login", (req, res) => {

  const { username, password } = req.body || {};

  db.get(
    "SELECT * FROM users WHERE username=?",
    [username],
    async (err, user) => {

      if (!user)
        return res.status(400).json({ error: "User not found" });

      const match = await bcrypt.compare(password, user.password);

      if (!match)
        return res.status(401).json({ error: "Wrong password" });

      req.session.user = {
        username: user.username,
        role: user.role
      };

      req.session.save();

      res.json({
        success: true,
        role: user.role,
        token: createToken(user)
      });

    }
  );

});

/* ================= INBOX ================= */

app.get("/inbox", requireLogin, (req, res) => {

  const username = req.session.user.username;

  db.all(
    "SELECT * FROM messages WHERE recipient=?",
    [username],
    (err, rows) => {
      res.json(rows || []);
    }
  );

});

/* ================= ADMIN ================= */

app.get("/admin/users", requireAdmin, (req, res) => {

  db.all(
    "SELECT id,username,role FROM users",
    (err, rows) => {
      res.json(rows || []);
    }
  );

});

app.get("/admin/messages", requireAdmin, (req, res) => {

  db.all(
    "SELECT * FROM messages ORDER BY created_at DESC",
    (err, rows) => {
      res.json(rows || []);
    }
  );

});

/* ================= START SERVER ================= */

server.listen(3000, () => {
  console.log("🔥 ULTRA SECURE CHAT RUNNING http://localhost:3000");
});