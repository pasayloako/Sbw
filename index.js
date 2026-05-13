const express = require('express');
const session = require('express-session');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use(session({
  secret: 'a7f3e9c2b8d1f4a6e7c9b3d5f8a2c6e9f7a4b1c8d3e5f7a9b2c4d6e8f0a1b3c5',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set to true if using HTTPS
}));

// Database setup
const db = new sqlite3.Database('./access.db');

// Create tables
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT,
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  // Access permissions table
  db.run(`CREATE TABLE IF NOT EXISTS access_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    duration TEXT CHECK(duration IN ('1 day', '3 days', '7 days', '1 month', '1 year', 'lifetime')),
    usage_limit INTEGER,
    usage_count INTEGER DEFAULT 0,
    expiry_date DATETIME,
    is_active BOOLEAN DEFAULT 1,
    created_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  // Usage logs table
  db.run(`CREATE TABLE IF NOT EXISTS usage_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    action TEXT,
    endpoint TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  // Create default admin user (password: admin123)
  const hashedPassword = bcrypt.hashSync('admin123', 10);
  db.run(`INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)`, 
    ['admin', hashedPassword, 'admin']);
});

// Helper functions
function calculateExpiryDate(duration) {
  const now = new Date();
  switch(duration) {
    case '1 day': return new Date(now.setDate(now.getDate() + 1));
    case '3 days': return new Date(now.setDate(now.getDate() + 3));
    case '7 days': return new Date(now.setDate(now.getDate() + 7));
    case '1 month': return new Date(now.setMonth(now.getMonth() + 1));
    case '1 year': return new Date(now.setFullYear(now.getFullYear() + 1));
    case 'lifetime': return new Date('2099-12-31');
    default: return null;
  }
}

function checkAccess(username, callback) {
  db.get(`SELECT * FROM access_permissions 
          WHERE username = ? AND is_active = 1 
          ORDER BY created_at DESC LIMIT 1`, 
    [username], (err, permission) => {
    if (err || !permission) {
      callback(false, 'No access permission found');
      return;
    }
    
    // Check expiry
    if (permission.expiry_date && new Date(permission.expiry_date) < new Date()) {
      callback(false, 'Access has expired');
      return;
    }
    
    // Check usage limit
    if (permission.usage_limit !== -1 && permission.usage_count >= permission.usage_limit) {
      callback(false, 'Usage limit exceeded');
      return;
    }
    
    callback(true, permission);
  });
}

// API Routes

// Login endpoint
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err || !user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    if (user.role === 'admin') {
      if (!bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
      }
      req.session.user = { username, role: 'admin' };
      return res.json({ success: true, role: 'admin' });
    }
    
    // Regular user - check if they have access
    checkAccess(username, (hasAccess, permission) => {
      if (hasAccess) {
        req.session.user = { username, role: 'user' };
        res.json({ success: true, role: 'user', permission });
      } else {
        res.status(403).json({ success: false, message: permission || 'No access permission' });
      }
    });
  });
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Check access status
app.get('/api/check-access', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ hasAccess: false, message: 'Not logged in' });
  }
  
  if (req.session.user.role === 'admin') {
    return res.json({ hasAccess: true, role: 'admin' });
  }
  
  checkAccess(req.session.user.username, (hasAccess, data) => {
    res.json({ 
      hasAccess, 
      role: 'user',
      message: !hasAccess ? data : null,
      permission: hasAccess ? data : null
    });
  });
});

// Use the SMS API (protected endpoint)
app.post('/api/use-sms-service', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ success: false, message: 'Please login first' });
  }
  
  const { phone, amount = 1 } = req.body;
  
  if (!phone) {
    return res.status(400).json({ success: false, message: 'Phone number is required' });
  }
  
  // Check if user has access
  checkAccess(req.session.user.username, async (hasAccess, permission) => {
    if (!hasAccess) {
      return res.status(403).json({ success: false, message: permission });
    }
    
    try {
      // Call the external API
      const response = await axios.get('https://pasayloakomego.onrender.com/api/smsbombv2', {
        params: {
          phone: phone,
          amount: amount,
          apikey: 'selovasx123'
        }
      });
      
      // Update usage count
      if (permission.usage_limit !== -1) {
        db.run(`UPDATE access_permissions 
                SET usage_count = usage_count + 1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE username = ? AND is_active = 1`, 
          [req.session.user.username]);
      }
      
      // Log usage
      db.run(`INSERT INTO usage_logs (username, action, endpoint) 
              VALUES (?, ?, ?)`, 
        [req.session.user.username, 'sms_service_used', '/api/use-sms-service']);
      
      res.json({ 
        success: true, 
        message: 'SMS service executed successfully',
        data: response.data,
        remaining_uses: permission.usage_limit === -1 ? 'Unlimited' : 
                       (permission.usage_limit - permission.usage_count - 1)
      });
      
    } catch (error) {
      console.error('API Error:', error.message);
      res.status(500).json({ 
        success: false, 
        message: 'Failed to execute SMS service',
        error: error.message 
      });
    }
  });
});

// Admin Routes

// Get all users with their access permissions
app.get('/api/admin/users', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Admin access required' });
  }
  
  db.all(`SELECT u.username, u.created_at, 
          ap.duration, ap.usage_limit, ap.usage_count, ap.expiry_date, ap.is_active
          FROM users u
          LEFT JOIN access_permissions ap ON u.username = ap.username
          WHERE u.role = 'user'
          ORDER BY u.created_at DESC`, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, users: rows });
  });
});

// Grant or update access permission
app.post('/api/admin/grant-access', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Admin access required' });
  }
  
  const { username, duration, usage_limit, expiry_date } = req.body;
  
  if (!username || !duration) {
    return res.status(400).json({ success: false, message: 'Username and duration required' });
  }
  
  // Check if user exists, if not create them
  db.run(`INSERT OR IGNORE INTO users (username, role) VALUES (?, ?)`, 
    [username, 'user']);
  
  // Convert usage_limit string to number
  let limit = -1; // -1 means unlimited
  if (usage_limit === '1 test') limit = 1;
  else if (usage_limit === '2 tests') limit = 2;
  else if (usage_limit === '3 tests') limit = 3;
  else if (usage_limit === 'unlimited') limit = -1;
  
  // Calculate expiry date
  let expiry = expiry_date;
  if (!expiry && duration !== 'lifetime') {
    expiry = calculateExpiryDate(duration);
  }
  
  // Deactivate previous permissions
  db.run(`UPDATE access_permissions SET is_active = 0 WHERE username = ?`, [username]);
  
  // Insert new permission
  db.run(`INSERT INTO access_permissions (username, duration, usage_limit, usage_count, expiry_date, created_by)
          VALUES (?, ?, ?, 0, ?, ?)`,
    [username, duration, limit, expiry, req.session.user.username], function(err) {
    if (err) {
      return res.status(500).json({ success: false, message: 'Failed to grant access' });
    }
    
    // Log action
    db.run(`INSERT INTO usage_logs (username, action, endpoint) VALUES (?, ?, ?)`,
      [username, 'access_granted', '/api/admin/grant-access']);
    
    res.json({ success: true, message: `Access granted to ${username}` });
  });
});

// Revoke access
app.post('/api/admin/revoke-access', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Admin access required' });
  }
  
  const { username } = req.body;
  
  db.run(`UPDATE access_permissions SET is_active = 0 WHERE username = ?`, [username], (err) => {
    if (err) {
      return res.status(500).json({ success: false, message: 'Failed to revoke access' });
    }
    
    res.json({ success: true, message: `Access revoked for ${username}` });
  });
});

// Get usage logs
app.get('/api/admin/logs', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Admin access required' });
  }
  
  db.all(`SELECT * FROM usage_logs ORDER BY timestamp DESC LIMIT 100`, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    res.json({ success: true, logs: rows });
  });
});

// Serve the main HTML file
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('Admin login: admin / admin123');
});
