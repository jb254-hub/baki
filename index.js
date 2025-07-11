require('dotenv').config(); // Load .env variables in local dev

const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// === POSTGRES SETUP ===
const pgPool = new Pool({
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
  host: process.env.PG_HOST,
  port: process.env.PG_PORT || 5432,
  database: process.env.PG_DATABASE,
});

// === DB INIT ===
async function initDB() {
  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      recovery_question VARCHAR(50) NOT NULL,
      recovery_answer_hash TEXT NOT NULL
    );
  `);

  await pgPool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'session') THEN
        CREATE TABLE "session" (
          "sid" varchar NOT NULL COLLATE "default",
          "sess" json NOT NULL,
          "expire" timestamp(6) NOT NULL,
          CONSTRAINT "session_pkey" PRIMARY KEY ("sid")
        );
        CREATE INDEX "IDX_session_expire" ON "session" ("expire");
      END IF;
    END
    $$;
  `);
}

initDB().catch(err => {
  console.error('Error initializing DB:', err);
  process.exit(1);
});

// === MIDDLEWARES ===
app.use(helmet()); // Security headers

// Rate limiter to prevent brute-force & spam
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

app.use(express.json());

app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000', // Set your frontend URL here
  credentials: true,
}));

app.use(session({
  store: new pgSession({
    pool: pgPool,
    tableName: 'session',
  }),
  secret: process.env.SESSION_SECRET || 'your_super_secret_session_key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // only over HTTPS in production
    sameSite: 'lax',
  },
}));

// === UTILS ===
const SALT_ROUNDS = 12;

async function hashPassword(password) {
  return await bcrypt.hash(password, SALT_ROUNDS);
}

async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// === ROUTES ===

// Health check
app.get('/healthz', (req, res) => res.send('OK'));

// Register
app.post('/api/register', async (req, res) => {
  const { user, pass, question, answer } = req.body;

  if (!user || !pass || !question || !answer) {
    return res.status(400).json({ success: false, error: 'Missing fields' });
  }

  try {
    const userExists = await pgPool.query('SELECT id FROM users WHERE username = $1', [user]);
    if (userExists.rowCount > 0) {
      return res.status(409).json({ success: false, error: 'User already exists' });
    }

    const passHash = await hashPassword(pass);
    const answerHash = await hashPassword(answer);

    await pgPool.query(
      'INSERT INTO users (username, password_hash, recovery_question, recovery_answer_hash) VALUES ($1, $2, $3, $4)',
      [user, passHash, question, answerHash]
    );

    req.session.user = user;
    res.json({ success: true });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { user, pass } = req.body;

  if (!user || !pass) {
    return res.status(400).json({ success: false, error: 'Missing fields' });
  }

  try {
    const userData = await pgPool.query('SELECT password_hash FROM users WHERE username = $1', [user]);
    if (userData.rowCount === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const { password_hash } = userData.rows[0];
    const valid = await verifyPassword(pass, password_hash);
    if (!valid) {
      return res.status(401).json({ success: false, error: 'Incorrect password' });
    }

    req.session.user = user;
    res.json({ success: true });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Get recovery question
app.get('/api/recover-question', async (req, res) => {
  const user = (req.query.user || '').toLowerCase();

  if (!user) {
    return res.status(400).json({ success: false, error: 'Missing user' });
  }

  try {
    const userData = await pgPool.query('SELECT recovery_question FROM users WHERE username = $1', [user]);
    if (userData.rowCount === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const { recovery_question } = userData.rows[0];
    res.json({ success: true, question: recovery_question });
  } catch (err) {
    console.error('Recover question error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Verify recovery answer
app.post('/api/verify-answer', async (req, res) => {
  const { user, answer } = req.body;

  if (!user || !answer) {
    return res.status(400).json({ success: false, error: 'Missing fields' });
  }

  try {
    const userData = await pgPool.query('SELECT recovery_answer_hash FROM users WHERE username = $1', [user]);
    if (userData.rowCount === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const { recovery_answer_hash } = userData.rows[0];
    const valid = await verifyPassword(answer, recovery_answer_hash);

    if (!valid) {
      return res.status(401).json({ success: false, error: 'Incorrect answer' });
    }

    req.session.recoveryUser = user;
    res.json({ success: true });
  } catch (err) {
    console.error('Verify answer error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Reset password
app.post('/api/reset-password', async (req, res) => {
  const { user, newPass } = req.body;

  if (!user || !newPass) {
    return res.status(400).json({ success: false, error: 'Missing fields' });
  }

  if (req.session.recoveryUser !== user) {
    return res.status(403).json({ success: false, error: 'Not authorized to reset password' });
  }

  try {
    const passHash = await hashPassword(newPass);
    await pgPool.query('UPDATE users SET password_hash = $1 WHERE username = $2', [passHash, user]);

    delete req.session.recoveryUser;
    res.json({ success: true });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// Check session status
app.get('/api/status', (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, user: req.session.user });
  } else {
    res.json({ loggedIn: false });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
