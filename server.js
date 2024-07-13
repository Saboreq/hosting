require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const db = require('./db');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const session = require('express-session');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(helmet());
app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using HTTPS
  }));

app.get('/', (req, res) => {
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.get('/dashboard', (req, res) => {
    const { user } = req.session;
    if (!user) {
      return res.status(401).send('Unauthorized');
    }
    res.render('dashboard', { username: user.username, role: user.role });
  });

  app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
      const [rows] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
      if (rows.length > 0 && await bcrypt.compare(password, rows[0].password)) {
        const role = rows[0].role;
        req.session.user = { username, role };
        res.render('dashboard', { username, role });
      } else {
        res.status(401).send('Invalid credentials');
      }
    } catch (error) {
      res.status(500).send('Error during login');
    }
  });

app.post('/register', async (req, res) => {
  const { username, password, inviteCode } = req.body;
  try {
    const [inviteRows] = await db.execute('SELECT * FROM invites WHERE code = ? AND used = 0', [inviteCode]);
    if (inviteRows.length === 0) {
      return res.send('Invalid or used invite code');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const role = inviteRows[0].role;
    await db.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hashedPassword, role]);
    await db.execute('UPDATE invites SET used = 1 WHERE code = ?', [inviteCode]);
    res.redirect('/login');
  } catch (error) {
    res.status(500).send('Error during registration');
  }
});

app.get('/files', (req, res) => {
    const { user } = req.session;
    if (!user) {
      return res.status(401).send('Unauthorized');
    }
    const filesPath = path.join(__dirname, 'Files');
    const directories = fs.readdirSync(filesPath, { withFileTypes: true })
      .filter(dirent => dirent.isDirectory())
      .map(dirent => dirent.name);
  
    if (user.role === 'admin') {
      res.render('files', { directories, files: [], role: user.role });
    } else if (user.role === 'member') {
      res.render('files', { directories: directories.filter(dir => dir === 'Public'), files: [], role: user.role });
    } else {
      res.status(403).send('Access denied');
    }
  });

  app.get('/files/:directory', (req, res) => {
    const { user } = req.session;
    if (!user) {
      return res.status(401).send('Unauthorized');
    }
    const directory = req.params.directory;
    const filesPath = path.join(__dirname, 'Files', directory);
  
    if (!fs.existsSync(filesPath)) {
      return res.status(404).send('Directory not found');
    }
  
    const files = fs.readdirSync(filesPath, { withFileTypes: true })
      .filter(dirent => dirent.isFile())
      .map(dirent => dirent.name);
  
    if (user.role === 'admin' || (user.role === 'member' && directory === 'Public')) {
      res.render('files', { directories: [], files, directory, role: user.role });
    } else {
      res.status(403).send('Access denied');
    }
  });

app.get('/download/:directory/:file', (req, res) => {
  const { directory, file } = req.params;
  const filePath = path.join(__dirname, 'Files', directory, file);

  if (!fs.existsSync(filePath)) {
    return res.status(404).send('File not found');
  }

  res.download(filePath, (err) => {
    if (err) {
      res.status(500).send('Error downloading file');
    }
  });
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something went wrong!');
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
