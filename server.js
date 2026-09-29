require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const BOT_TOKEN = process.env.BOT_TOKEN;
const ADMIN_ID = parseInt(process.env.ADMIN_ID || '0');

if (!BOT_TOKEN || !ADMIN_ID) {
  console.error('❌ Ошибка: задайте BOT_TOKEN и ADMIN_ID в .env');
  process.exit(1);
}

let db;
const DB_FILE = './genym.db';

async function initDB() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_FILE)) {
    const fileBuffer = fs.readFileSync(DB_FILE);
    db = new SQL.Database(fileBuffer);
    console.log('✅ База данных загружена');
  } else {
    db = new SQL.Database();
    run(`
      CREATE TABLE IF NOT EXISTS users (
        telegram_id INTEGER PRIMARY KEY,
        first_name TEXT,
        last_name TEXT,
        username TEXT,
        balance INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now'))
      )
    `);
    run(`
      CREATE TABLE IF NOT EXISTS results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        telegram_id INTEGER,
        model TEXT,
        description TEXT,
        media_url TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (telegram_id) REFERENCES users(telegram_id)
      )
    `);
    saveDB();
    console.log('✅ Новая база данных создана');
  }
}

function run(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.run(params);
  return stmt;
}

function all(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const results = [];
  while (stmt.step()) {
    results.push(stmt.getAsObject());
  }
  return results;
}

function get(sql, params = []) {
  return all(sql, params)[0];
}

function saveDB() {
  const data = db.export();
  fs.writeFileSync(DB_FILE, Buffer.from(data));
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function verifyTelegramAuth(data) {
  const { hash, ...rest } = data;
  if (!hash) return false;
  const secretKey = crypto.createHash('sha256').update(BOT_TOKEN).digest();
  const dataCheck = Object.entries(rest)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join('\n');
  const computedHash = crypto
    .createHmac('sha256', secretKey)
    .update(dataCheck)
    .digest('hex');
  return crypto.timingSafeEqual(Buffer.from(computedHash), Buffer.from(hash));
}

app.post('/api/auth', (req, res) => {
  try {
    if (!verifyTelegramAuth(req.body)) {
      return res.status(403).json({ error: 'Неверная подпись' });
    }
    if (Date.now() / 1000 - req.body.auth_date > 86400) {
      return res.status(403).json({ error: 'Данные устарели' });
    }
    const { id, first_name, last_name, username } = req.body;
    
    const existing = get('SELECT telegram_id FROM users WHERE telegram_id = ?', [id]);
    if (!existing) {
      run(`INSERT INTO users (telegram_id, first_name, last_name, username) VALUES (?, ?, ?, ?)`,
        [id, first_name || '', last_name || '', username || '']);
    } else {
      run(`UPDATE users SET first_name=?, last_name=?, username=? WHERE telegram_id=?`,
        [first_name || '', last_name || '', username || '', id]);
    }
    saveDB();
    
    res.json({ ok: true, userId: id, firstName: first_name });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/user/:id', (req, res) => {
  const userId = parseInt(req.params.id);
  const user = get('SELECT * FROM users WHERE telegram_id = ?', [userId]);
  if (!user) return res.status(404).json({ error: 'Не найден' });
  const results = all('SELECT * FROM results WHERE telegram_id = ? ORDER BY created_at DESC', [userId]);
  res.json({ user, results });
});

app.post('/api/admin/update-balance', (req, res) => {
  const { adminId, targetUserId, newBalance } = req.body;
  if (adminId !== ADMIN_ID) return res.status(403).json({ error: 'Нет прав' });
  run('UPDATE users SET balance = ? WHERE telegram_id = ?', [newBalance, targetUserId]);
  saveDB();
  res.json({ ok: true });
});

app.post('/api/admin/add-result', (req, res) => {
  const { adminId, targetUserId, model, description, mediaUrl } = req.body;
  if (adminId !== ADMIN_ID) return res.status(403).json({ error: 'Нет прав' });
  run(`INSERT INTO results (telegram_id, model, description, media_url) VALUES (?, ?, ?, ?)`,
    [targetUserId, model, description, mediaUrl]);
  saveDB();
  res.json({ ok: true });
});

app.get('/api/admin/users', (req, res) => {
  const { adminId } = req.query;
  if (parseInt(adminId) !== ADMIN_ID) return res.status(403).json({ error: 'Нет прав' });
  const users = all('SELECT * FROM users ORDER BY created_at DESC');
  res.json({ users });
});

initDB().then(() => {
  app.listen(PORT, () => console.log(`✅ Сервер запущен: порт ${PORT}`));
});