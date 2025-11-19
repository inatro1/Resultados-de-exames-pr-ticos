// server.js
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const mysql = require("mysql2/promise");
const bcrypt = require('bcrypt');
bcrypt.hash('admin123, 10).then(h => console.log(h));
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(bodyParser.json());

const PORT = 3000;
const JWT_SECRET = "troque_isto_para_um_seguro_secret";

// Configure a conexão MySQL
const pool = mysql.createPool({
  host: "localhost",
  user: "seu_user",
  password: "sua_senha",
  database: "inatro_db",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Login (POST /api/login) -> return token + user
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const [rows] = await pool.query("SELECT id, username, password_hash, role FROM users WHERE username = ?", [username]);
    if (!rows.length) return res.status(401).json({ error: "Credenciais inválidas" });
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Credenciais inválidas" });
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: "8h" });
    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  } catch (err) {
    console.error(err); res.status(500).json({ error: "erro no servidor" });
  }
});

// middleware simples (valida token)
function auth(req, res, next){
  const authHeader = req.headers.authorization;
  if(!authHeader) return res.status(401).json({error:"Sem autorização"});
  const token = authHeader.split(" ")[1];
  try{
    const data = jwt.verify(token, JWT_SECRET);
    req.user = data;
    next();
  }catch(e){ return res.status(401).json({error:"Token inválido"}); }
}

// GET candidates
app.get("/api/candidates", auth, async (req,res)=>{
  try{
    const [rows] = await pool.query("SELECT id,name,code,delegation AS deleg, `date`, ingresso as `in`, saida as `out`, points AS pts, status, fraude FROM candidates ORDER BY id ASC");
    res.json(rows);
  }catch(err){ console.error(err); res.status(500).json({error:"db"}); }
});

// PUT update candidate (id)
app.put("/api/candidates/:id", auth, async (req,res)=>{
  const id = Number(req.params.id);
  const body = req.body;
  try{
    await pool.query("UPDATE candidates SET name=?, status=?, fraude=?, points=? WHERE id=?", [body.name, body.status, body.fraude?1:0, body.pts || 0, id]);
    res.json({ok:true});
  }catch(err){ console.error(err); res.status(500).json({error:"db update"}); }
});

app.listen(PORT, ()=> console.log("API running on http://localhost:" + PORT));
