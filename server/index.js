const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.use(cors());
app.use(express.json());

const db = new sqlite3.Database('./rbac.db');

db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
  )
`);

const JWT_SECRET = 'rbac_secret_key';

const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
};

const verifyAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied. Admins only.' });
  }
  next();
};

app.post('/api/register', async (req, res) => {
  const { username, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  db.run(
    'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
    [username, hashedPassword, role || 'user'],
    (err) => {
      if (err) return res.status(400).json({ message: 'Username already exists' });
      res.json({ message: 'User registered successfully' });
    }
  );
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (!user) return res.status(400).json({ message: 'User not found' });
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(400).json({ message: 'Invalid password' });
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ token, role: user.role, username: user.username });
  });
});

app.get('/api/profile', verifyToken, (req, res) => {
  db.get('SELECT id, username, role FROM users WHERE id = ?', [req.user.id], (err, user) => {
    res.json(user);
  });
});

app.get('/api/users', verifyToken, verifyAdmin, (req, res) => {
  db.all('SELECT id, username, role FROM users', [], (err, users) => {
    res.json(users);
  });
});

app.delete('/api/users/:id', verifyToken, verifyAdmin, (req, res) => {
  db.run('DELETE FROM users WHERE id = ?', [req.params.id], (err) => {
    res.json({ message: 'User deleted successfully' });
  });
});

app.listen(5000, () => console.log('Server running on port 5000'));