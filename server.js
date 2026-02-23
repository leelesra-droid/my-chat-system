require("dotenv").config();

const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const session = require("express-session");
const cors = require("cors");
const path = require("path");
const http = require("http");
const WebSocket = require("ws");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

/* ================= APP INIT ================= */

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const db = new Database("./messages.db");
const clients = new Map();

/* ================= SECURITY ================= */

app.use(helmet());

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* ================= RATE LIMIT ================= */

app.use("/login", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15
}));

/* ================= SESSION ================= */

app.use(session({
  secret: "chat_secure_super_random",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax"
  }
}));

/* ================= STATIC FILES ================= */

app.use(express.static(path.join(__dirname, "public")));

/* ================= DATABASE TABLES ================= */

db.exec(`
CREATE TABLE IF NOT EXISTS users(
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT UNIQUE,
password TEXT,
role TEXT DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS messages(
id INTEGER PRIMARY KEY AUTOINCREMENT,
sender TEXT,
recipient TEXT,
content TEXT,
is_read INTEGER DEFAULT 0,
created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`);

/* Default admin */

const adminExists = db.prepare(
"SELECT * FROM users WHERE username=?"
).get("admin");

if (!adminExists) {

const hash = bcrypt.hashSync("0-admini-1", 10);

db.prepare(
"INSERT INTO users(username,password,role) VALUES(?,?,?)"
).run("admin", hash, "admin");

}

/* ================= HELPERS ================= */

function sanitizeText(text) {
return String(text).substring(0, 1000);
}

function requireLogin(req,res,next){
if(!req.session.user)
return res.status(401).json({error:"Unauthorized"});
next();
}

function requireAdmin(req,res,next){
if(!req.session.user || req.session.user.role!=="admin")
return res.status(403).json({error:"Admin only"});
next();
}

/* ================= JWT ================= */

function createToken(user){

return jwt.sign(
{
username:user.username,
role:user.role
},
process.env.JWT_SECRET || "chat_secret",
{expiresIn:"24h"}
);

}

function verifyToken(token){

try{
return jwt.verify(
token,
process.env.JWT_SECRET || "chat_secret"
);
}catch{
return null;
}

}

/* ================= WEBSOCKET ================= */

wss.on("connection",(ws)=>{

let username=null;

ws.on("message",(data)=>{

if(Buffer.byteLength(data)>5000) return;

try{

const msg=JSON.parse(data);

/* AUTH */

if(msg.type==="auth"){

const decoded=verifyToken(msg.token);
if(!decoded) return;

username=decoded.username;
clients.set(username,ws);

return;
}

/* CHAT */

if(msg.type==="chat"){

if(!username) return;

const content=sanitizeText(msg.content);

db.prepare(`
INSERT INTO messages(sender,recipient,content,is_read)
VALUES(?,?,?,0)
`).run(username,msg.recipient,content);

const target=clients.get(msg.recipient);

if(target && target.readyState===WebSocket.OPEN){

target.send(JSON.stringify({
type:"new_message",
sender:username,
content
}));

}

}

}catch(e){
console.log(e);
}

});

ws.on("close",()=>{
if(username) clients.delete(username);
});

});

/* ================= REGISTER ================= */

app.post("/register",async(req,res)=>{

const {username,password}=req.body||{};

if(!username || !password)
return res.status(400).json({error:"Missing fields"});

const hash=await bcrypt.hash(password,10);

try{

db.prepare(`
INSERT INTO users(username,password)
VALUES(?,?)
`).run(username,hash);

res.json({success:true});

}catch{
res.json({error:"Username exists"});
}

});

/* ================= LOGIN ================= */

app.post("/login",(req,res)=>{

const {username,password}=req.body||{};

const user=db.prepare(`
SELECT * FROM users WHERE username=?
`).get(username);

if(!user)
return res.status(400).json({error:"User not found"});

const match=bcrypt.compareSync(password,user.password);

if(!match)
return res.status(401).json({error:"Wrong password"});

req.session.user={
username:user.username,
role:user.role
};

req.session.save();

res.json({
success:true,
role:user.role,
token:createToken(user)
});

});

/* ================= AUTO DELETE VIEWED MESSAGES ================= */

app.post("/mark-read",requireLogin,(req,res)=>{

const username=req.session.user.username;

db.prepare(`
DELETE FROM messages
WHERE recipient=? AND is_read=1
`).run(username);

res.json({success:true});

});

/* ================= INBOX ================= */

app.get("/inbox",requireLogin,(req,res)=>{

const username=req.session.user.username;

const rows=db.prepare(`
SELECT * FROM messages
WHERE recipient=?
`).all(username);

res.json(rows||[]);

});

/* ================= ADMIN ================= */

app.get("/admin/users",requireAdmin,(req,res)=>{

const rows=db.prepare(`
SELECT id,username,role FROM users
`).all();

res.json(rows||[]);

});

app.get("/admin/messages",requireAdmin,(req,res)=>{

const rows=db.prepare(`
SELECT * FROM messages
ORDER BY created_at DESC
`).all();

res.json(rows||[]);

});

/* ================= SERVER START ================= */

const PORT = process.env.PORT || 3000;

server.listen(PORT,()=>{
console.log("🔥 ULTRA SECURE CHAT RUNNING");
});