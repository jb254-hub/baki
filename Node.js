const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
const PORT = 3000;

// === POSTGRES SETUP ===
const pgPool = new Pool({
  connectionString: 'postgresql://bookingservices_user:iMT2BtyQUVXtqMas0BsuoveCJBfNgF7Y@dpg-d1oc25ruibrs73civ41g-a.oregon-postgres.render.com/bookingservices',
  ssl: {
    rejectUnauthorized: false
  }
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
app.use(express.json());

app.use(cors({
  origin: ['http://127.0.0.1:5500', 'https://your-frontend-domain.com'], // Add your deployed frontend domain
  credentials: true
}));

app.use(session({
  store: new pgSession({
    pool: pgPool,
    tableName: 'session'
  }),
  secret: 'your_super_secret_session_key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    httpOnly: true,
    secure: false, // Set to true if using HTTPS
    sameSite: 'lax'
  }
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

// Register
app.post('/api/register', async (req, res) => {
  const { user, pass, question, answer } = req.body;

  if (!user || !pass || !question || !answer) {
    return res.json({ success: false, error: 'Missing fields' });
  }

  try {
    const userExists = await pgPool.query('SELECT id FROM users WHERE username = $1', [user]);
    if (userExists.rowCount > 0) {
      return res.json({ success: false, error: 'User already exists' });
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
    res.json({ success: false, error: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { user, pass } = req.body;

  if (!user || !pass) {
    return res.json({ success: false, error: 'Missing fields' });
  }

  try {
    const userData = await pgPool.query('SELECT password_hash FROM users WHERE username = $1', [user]);
    if (userData.rowCount === 0) {
      return res.json({ success: false, error: 'User not found' });
    }

    const { password_hash } = userData.rows[0];
    const valid = await verifyPassword(pass, password_hash);
    if (!valid) {
      return res.json({ success: false, error: 'Incorrect password' });
    }

    req.session.user = user;
    res.json({ success: true });
  } catch (err) {
    console.error('Login error:', err);
    res.json({ success: false, error: 'Server error' });
  }
});

// Get recovery question
app.get('/api/recover-question', async (req, res) => {
  const user = (req.query.user || '').toLowerCase();

  if (!user) {
    return res.json({ success: false, error: 'Missing user' });
  }

  try {
    const userData = await pgPool.query('SELECT recovery_question FROM users WHERE username = $1', [user]);
    if (userData.rowCount === 0) {
      return res.json({ success: false, error: 'User not found' });
    }

    const { recovery_question } = userData.rows[0];
    res.json({ success: true, question: recovery_question });
  } catch (err) {
    console.error('Recover question error:', err);
    res.json({ success: false, error: 'Server error' });
  }
});

// Verify recovery answer
app.post('/api/verify-answer', async (req, res) => {
  const { user, answer } = req.body;

  if (!user || !answer) {
    return res.json({ success: false, error: 'Missing fields' });
  }

  try {
    const userData = await pgPool.query('SELECT recovery_answer_hash FROM users WHERE username = $1', [user]);
    if (userData.rowCount === 0) {
      return res.json({ success: false, error: 'User not found' });
    }

    const { recovery_answer_hash } = userData.rows[0];
    const valid = await verifyPassword(answer, recovery_answer_hash);

    if (!valid) {
      return res.json({ success: false, error: 'Incorrect answer' });
    }

    req.session.recoveryUser = user;
    res.json({ success: true });
  } catch (err) {
    console.error('Verify answer error:', err);
    res.json({ success: false, error: 'Server error' });
  }
});

// Reset password
app.post('/api/reset-password', async (req, res) => {
  const { user, newPass } = req.body;

  if (!user || !newPass) {
    return res.json({ success: false, error: 'Missing fields' });
  }

  if (req.session.recoveryUser !== user) {
    return res.json({ success: false, error: 'Not authorized to reset password' });
  }

  try {
    const passHash = await hashPassword(newPass);
    await pgPool.query('UPDATE users SET password_hash = $1 WHERE username = $2', [passHash, user]);

    delete req.session.recoveryUser;
    res.json({ success: true });
  } catch (err) {
    console.error('Reset password error:', err);
    res.json({ success: false, error: 'Server error' });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// Session status check
app.get('/api/status', (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, user: req.session.user });
  } else {
    res.json({ loggedIn: false });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
