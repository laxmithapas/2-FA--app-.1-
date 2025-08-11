// index.js

// 1. Import necessary packages
require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
// NEW: Import the PostgreSQL driver
const { Pool } = require('pg');

// 2. Set up the Database Connection Pool
// The pool manages multiple client connections to the database.
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

// 3. Initialize the Express app
const app = express();
const PORT = process.env.PORT || 3000;

// 4. Set up middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  store: new FileStore({ path: './sessions' }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 }
}));

// 5. Define API Routes

// --- REGISTRATION: STEP 1 (Generate Secret) ---
app.post('/api/register', async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;
    if (!firstName || !email || !password) {
      return res.status(400).json({ message: 'Please fill out all required fields.' });
    }

    // Check if user already exists
    const existingUserResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUserResult.rows.length > 0) {
      return res.status(409).json({ message: 'You already have an account, please log in.' });
    }
    
    const secret = speakeasy.generateSecret({ name: `AuraSecure (${email})` });
    const password_hash = await bcrypt.hash(password, 10);
    const id = Date.now().toString(); // Simple unique ID

    // Insert new user with a temporary secret
    const insertQuery = 'INSERT INTO users(id, first_name, last_name, email, password_hash, two_fa_secret, two_fa_enabled) VALUES($1, $2, $3, $4, $5, $6, $7)';
    await pool.query(insertQuery, [id, firstName, lastName, email, password_hash, secret.base32, false]);

    qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
      if (err) throw err;
      res.status(200).json({ userId: id, qrCodeUrl: data_url });
    });
  } catch (error) {
    console.error('Registration Error:', error);
    res.status(500).json({ message: 'An error occurred on the server.' });
  }
});

// --- REGISTRATION: STEP 2 (Verify Token and Enable 2FA) ---
app.post('/api/verify-2fa', async (req, res) => {
  try {
    const { userId, token } = req.body;
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }
    const user = userResult.rows[0];

    const verified = speakeasy.totp.verify({ secret: user.two_fa_secret, encoding: 'base32', token, window: 1 });
    
    if (verified) {
      // Finalize 2FA by setting the enabled flag to true
      await pool.query('UPDATE users SET two_fa_enabled = TRUE WHERE id = $1', [userId]);
      res.status(200).json({ message: 'Success! 2FA enabled. Please log in.' });
    } else {
      res.status(400).json({ message: 'Invalid 2FA code. Please try again.' });
    }
  } catch (error) {
    console.error('2FA Verification Error:', error);
    res.status(500).json({ message: 'An error occurred on the server.' });
  }
});

// --- LOGIN: STEP 1 (Password Verification) ---
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'Account not found.' });
    }
    const user = userResult.rows[0];

    if (!user.two_fa_enabled) {
      return res.status(401).json({ message: '2FA is not enabled for this account.' });
    }

    const passwordIsValid = await bcrypt.compare(password, user.password_hash);
    if (!passwordIsValid) {
      return res.status(401).json({ message: 'Incorrect password. Please try again.' });
    }

    req.session.loginChallenge = { userId: user.id };
    res.status(200).json({ message: 'Password correct. Please provide 2FA token.' });
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ message: 'An error occurred on the server.' });
  }
});

// --- LOGIN: STEP 2 (2FA Token Verification) ---
app.post('/api/login/verify', async (req, res) => {
  try {
    if (!req.session.loginChallenge || !req.session.loginChallenge.userId) {
      return res.status(401).json({ message: 'Please enter your password first.' });
    }
    const userId = req.session.loginChallenge.userId;
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) return res.status(404).json({ message: 'User not found.' });
    
    const user = userResult.rows[0];
    const { token } = req.body;
    const verified = speakeasy.totp.verify({ secret: user.two_fa_secret, encoding: 'base32', token, window: 1 });

    if (verified) {
      req.session.userId = user.id;
      req.session.loginChallenge = undefined;
      res.status(200).json({ message: 'Login successful!' });
    } else {
      res.status(401).json({ message: 'Invalid 2FA code.' });
    }
  } catch (error) {
    console.error('Login Verification Error:', error);
    res.status(500).json({ message: 'An error occurred on the server.' });
  }
});

// --- LOGOUT ROUTE ---
app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ message: 'Could not log out, please try again.' });
    }
    res.clearCookie('connect.sid');
    res.status(200).json({ message: 'Logout successful.' });
  });
});

// 6. Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
