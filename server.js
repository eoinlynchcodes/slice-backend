const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());

// Database setup
const db = new sqlite3.Database('./database.sqlite', (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('Connected to SQLite database');
  }
});

// Create users and links tables
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      fullName TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS links (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      link TEXT NOT NULL,
      category TEXT NOT NULL,
      description TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);
});

// Auth Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

app.get('/api/test', (req, res) => {
  res.send('Yes Eoin, I work');
});

// Auth Routes
app.post('/api/signup', async (req, res) => {
  const { username, fullName, email, password } = req.body;

  // Validate input fields
  if (!username || !fullName || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user into the database
    db.run(
      'INSERT INTO users (username, fullname, email, password) VALUES (?, ?, ?, ?)',
      [username, fullName, email, hashedPassword],
      function (err) {
        if (err) {
          // Handle unique constraint error for username/email
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'Username or email already exists' });
          }
          // Handle other database errors
          return res.status(500).json({ error: err.message });
        }

        // Retrieve the last inserted ID
        const userId = this.lastID;

        // Generate a JWT token
        const token = jwt.sign(
          { id: userId, username },
          process.env.JWT_SECRET,
          { expiresIn: '24h' }
        );

        // Return the user details and token
        res.status(201).json({ userId, token, username, fullName });
      }
    );
  } catch (err) {
    // Handle server-side errors
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      userId: user.id,
      token,
      username: user.username,
      fullName: user.fullName,
    });
  });
});

// Protected route example
app.get('/api/profile', authenticateToken, (req, res) => {
  db.get('SELECT id, username, email, created_at FROM users WHERE id = ?', 
    [req.user.id], 
    (err, user) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      res.json(user);
    }
  );
});

// User search endpoint
app.get('/api/users/search', authenticateToken, (req, res) => {
  const searchString = req.query.q;
  
  if (!searchString) {
    return res.status(400).json({ error: 'Search query is required' });
  }

  // Use LIKE with wildcards for partial matches
  // Using LOWER() to make the search case-insensitive
  const searchQuery = `
    SELECT id, username, fullName, email, created_at 
    FROM users 
    WHERE LOWER(username) LIKE LOWER(?) 
    OR LOWER(fullName) LIKE LOWER(?)
    ORDER BY username ASC
  `;

  const searchPattern = `%${searchString}%`;

  db.all(searchQuery, [searchPattern, searchPattern], (err, users) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    // Remove sensitive information and return results
    const safeUsers = users.map(user => ({
      id: user.id,
      username: user.username,
      fullName: user.fullName,
      created_at: user.created_at
    }));

    res.json(safeUsers);
  });
});

// Links Routes
app.post('/api/links/:userId', authenticateToken, (req, res) => {
  const { title, link, category, description } = req.body;
  const userId = parseInt(req.params.userId); // Get userId from params
  
  if (!title || !link) {
    return res.status(400).json({ error: 'Title and link are required' });
  }

  // Optional: Check if the userId from params matches the authenticated user's id
  if (userId !== req.user.id) {
    return res.status(403).json({ error: 'Unauthorized: Cannot create links for other users' });
  }

  db.run(
    'INSERT INTO links (user_id, title, link, category, description) VALUES (?, ?, ?, ?, ?)',
    [userId, title, link, category, description || ''],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      res.status(201).json({
        id: this.lastID,
        title,
        link,
        category,
        description,
        user_id: userId
      });
    }
  );
});

// Get all links for the authenticated user
app.get('/api/links', authenticateToken, (req, res) => {
  db.all(
    'SELECT * FROM links WHERE user_id = ? ORDER BY created_at DESC',
    [req.user.id],
    (err, links) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(links);
    }
  );
});

// Get a specific link
app.get('/api/links/:id', authenticateToken, (req, res) => {
  db.get(
    'SELECT * FROM links WHERE id = ? AND user_id = ?',
    [req.params.id, req.user.id],
    (err, link) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      if (!link) {
        return res.status(404).json({ error: 'Link not found' });
      }
      res.json(link);
    }
  );
});

// Delete a link
app.delete('/api/links/:id', authenticateToken, (req, res) => {
  db.run(
    'DELETE FROM links WHERE id = ? AND user_id = ?',
    [req.params.id, req.user.id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Link not found or unauthorized' });
      }
      res.status(200).json({ message: 'Link deleted successfully' });
    }
  );
});

// Update a link
app.put('/api/links/:id', authenticateToken, (req, res) => {
  const { title, link, category, description } = req.body;
  
  if (!title || !link) {
    return res.status(400).json({ error: 'Title and link are required' });
  }

  db.run(
    'UPDATE links SET title = ?, link = ?, category = ?, description = ? WHERE id = ? AND user_id = ?',
    [title, link, category, description || '', req.params.id, req.user.id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Link not found or unauthorized' });
      }
      
      res.json({
        id: parseInt(req.params.id),
        title,
        link,
        category,
        description,
        user_id: req.user.id
      });
    }
  );
});

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));