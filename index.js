// index.js

// 1. Import necessary packages
require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const session = require('express-session');
const FileStore = require('session-file-store')(session);

// 2. Set up the database
const adapter = new FileSync('db.json');
const db = low(adapter);
db.defaults({ users: [] }).write();

// 3. Initialize the Express app
const app = express();
const PORT = process.env.PORT || 3000;

// 4. Set up middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  store: new FileStore({ path: './sessions' }),
  secret: process.env.SESSION_SECRET || 'a very secret key',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 }
}));

// 5. Define API Routes

// --- REGISTRATION: STEP 1 (Generate Secret) ---
app.post('/api/register', (req, res) => {
  try {
    const { firstName, email, password } = req.body;
    if (!firstName || !email || !password) {
      return res.status(400).json({ message: 'Please fill out all required fields.' });
    }

    // UPDATED LOGIC: Check for existing user
    const existingUser = db.get('users').find({ email }).value();
    if (existingUser) {
      // Send a specific status code (409 Conflict) for existing user
      return res.status(409).json({ message: 'You already have an account, please log in.' });
    }
    
    const secret = speakeasy.generateSecret({ name: `AuraSecure (${email})` });
    const hashedPassword = bcrypt.hashSync(password, 10);
    
    const newUser = { id: Date.now().toString(), firstName, email, password: hashedPassword, tempTwoFaSecret: secret.base32, twoFaEnabled: false };
    db.get('users').push(newUser).write();

    qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
      if (err) throw new Error('Could not generate QR code.');
      res.status(200).json({ userId: newUser.id, qrCodeUrl: data_url });
    });
  } catch (error) {
    console.error('Registration Error:', error);
    res.status(500).json({ message: 'An error occurred on the server.' });
  }
});

// --- REGISTRATION: STEP 2 (Verify Token and Enable 2FA) ---
app.post('/api/verify-2fa', (req, res) => {
  try {
    const { userId, token } = req.body;
    const user = db.get('users').find({ id: userId }).value();
    if (!user) return res.status(404).json({ message: 'User not found.' });

    const verified = speakeasy.totp.verify({ secret: user.tempTwoFaSecret, encoding: 'base32', token, window: 1 });
    if (verified) {
      db.get('users').find({ id: userId }).assign({ twoFaSecret: user.tempTwoFaSecret, tempTwoFaSecret: undefined, twoFaEnabled: true }).write();
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
app.post('/api/login', (req, res) => {
  try {
    const { email, password } = req.body;
    const user = db.get('users').find({ email }).value();

    if (!user || !user.twoFaEnabled) {
      return res.status(401).json({ message: 'Invalid credentials or 2FA not enabled.' });
    }

    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    req.session.loginChallenge = { userId: user.id };
    res.status(200).json({ message: 'Password correct. Please provide 2FA token.' });
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ message: 'An error occurred on the server.' });
  }
});

// --- LOGIN: STEP 2 (2FA Token Verification) ---
app.post('/api/login/verify', (req, res) => {
  try {
    if (!req.session.loginChallenge || !req.session.loginChallenge.userId) {
      return res.status(401).json({ message: 'Please enter your password first.' });
    }

    const userId = req.session.loginChallenge.userId;
    const user = db.get('users').find({ id: userId }).value();
    if (!user) return res.status(404).json({ message: 'User not found.' });

    const { token } = req.body;
    const verified = speakeasy.totp.verify({ secret: user.twoFaSecret, encoding: 'base32', token, window: 1 });

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
  console.log(`Server is running on http://localhost:3000`);
});
