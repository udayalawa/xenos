const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// JWT Secret - In production, use environment variable
const JWT_SECRET = 'aO/qX6uCFvzak8vUaS7CEAMBAjRtQIoauUAen4SJXXLN+bCD0r20nFerKMyCDVf6PfrAOLoch7yGfFBtO4jDpA==';

// Initialize SQLite database
const db = new sqlite3.Database('./emi-lock.db', (err) => {
    if (err) {
        console.error('Error opening database', err);
        return;
    }
    console.log('Connected to SQLite database');
    
    // Create tables if they don't exist
    db.serialize(() => {
        // Agents table
        db.run(`CREATE TABLE IF NOT EXISTS agents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);

        // Enrollments table
        db.run(`CREATE TABLE IF NOT EXISTS enrollments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL,
            customer_name TEXT NOT NULL,
            customer_phone TEXT NOT NULL,
            imei1 TEXT NOT NULL,
            imei2 TEXT,
            secret_code TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'PENDING',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (agent_id) REFERENCES agents (id)
        )`);

        // Devices table
        db.run(`CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            enrollment_id INTEGER NOT NULL,
            fcm_token TEXT,
            imei TEXT NOT NULL,
            status TEXT DEFAULT 'ACTIVE',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP,
            FOREIGN KEY (enrollment_id) REFERENCES enrollments (id)
        )`);

        // Create a default admin agent if none exists
        const defaultPassword = 'admin123';
        bcrypt.hash(defaultPassword, 10, (err, hash) => {
            if (err) return console.error('Error hashing password:', err);
            
            db.get('SELECT id FROM agents WHERE username = ?', ['admin'], (err, row) => {
                if (!row) {
                    db.run(
                        'INSERT INTO agents (username, password_hash) VALUES (?, ?)',
                        ['admin', hash],
                        (err) => {
                            if (err) {
                                console.error('Error creating default admin:', err);
                            } else {
                                console.log('Default admin created. Username: admin, Password: admin123');
                            }
                        }
                    );
                }
            });
        });
    });
});

// Helper function to generate secret code
function generateSecretCode(length = 8) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.sendStatus(401);
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Routes

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Agent Registration
app.post('/api/agents/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        const hash = await bcrypt.hash(password, 10);
        
        db.run(
            'INSERT INTO agents (username, password_hash) VALUES (?, ?)',
            [username, hash],
            function(err) {
                if (err) {
                    if (err.code === 'SQLITE_CONSTRAINT') {
                        return res.status(409).json({ error: 'Username already exists' });
                    }
                    throw err;
                }
                res.status(201).json({ id: this.lastID });
            }
        );
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Agent Login
app.post('/api/agents/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        db.get('SELECT * FROM agents WHERE username = ?', [username], async (err, agent) => {
            if (err) throw err;
            if (!agent) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const valid = await bcrypt.compare(password, agent.password_hash);
            if (!valid) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const token = jwt.sign(
                { agentId: agent.id, username: agent.username },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.json({ token });
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Create Enrollment (Protected)
app.post('/api/enrollments', authenticateToken, (req, res) => {
    try {
        const { customer_name, customer_phone, imei1, imei2 } = req.body;
        if (!customer_name || !customer_phone || !imei1) {
            return res.status(400).json({ error: 'Customer name, phone, and IMEI1 are required' });
        }

        const secretCode = generateSecretCode();
        
        db.run(
            'INSERT INTO enrollments (agent_id, customer_name, customer_phone, imei1, imei2, secret_code) VALUES (?, ?, ?, ?, ?, ?)',
            [req.user.agentId, customer_name, customer_phone, imei1, imei2, secretCode],
            function(err) {
                if (err) {
                    console.error('Error creating enrollment:', err);
                    return res.status(500).json({ error: 'Failed to create enrollment' });
                }
                
                res.status(201).json({
                    id: this.lastID,
                    secret_code: secretCode,
                    message: 'Enrollment created successfully'
                });
            }
        );
    } catch (error) {
        console.error('Enrollment error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// List Enrollments (Protected)
app.get('/api/enrollments', authenticateToken, (req, res) => {
    try {
        db.all(
            'SELECT * FROM enrollments WHERE agent_id = ?',
            [req.user.agentId],
            (err, rows) => {
                if (err) throw err;
                res.json(rows);
            }
        );
    } catch (error) {
        console.error('List enrollments error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Device Activation
app.post('/api/devices/activate', async (req, res) => {
    try {
        console.log('Device activation request received:', JSON.stringify(req.body, null, 2));
        const { secret_code, device_reported_imei, fcm_token } = req.body;
        
        if (!secret_code || !device_reported_imei) {
            const error = 'Secret code and IMEI are required';
            console.error('Activation error:', error);
            return res.status(400).json({ error });
        }

        // Find enrollment by secret code
        console.log(`Looking up enrollment with secret code: ${secret_code}`);
        db.get(
            'SELECT * FROM enrollments WHERE secret_code = ?',
            [secret_code],
            (err, enrollment) => {
                if (err) {
                    console.error('Database error when finding enrollment:', err);
                    return res.status(500).json({ error: 'Database error' });
                }
                if (!enrollment) {
                    const error = `No enrollment found with secret code: ${secret_code}`;
                    console.error('Activation error:', error);
                    return res.status(404).json({ error: 'Invalid secret code' });
                }
                console.log('Found enrollment:', JSON.stringify(enrollment, null, 2));

                // Check if device already exists
                console.log(`Checking for existing device with enrollment ID: ${enrollment.id}`);
                db.get(
                    'SELECT * FROM devices WHERE enrollment_id = ?',
                    [enrollment.id],
                    (err, existingDevice) => {
                        if (err) {
                            console.error('Database error when checking for existing device:', err);
                            return res.status(500).json({ error: 'Database error' });
                        }
                        
                        if (existingDevice) {
                            console.log('Found existing device, updating...');
                            // Update existing device
                            db.run(
                                'UPDATE devices SET fcm_token = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?',
                                [fcm_token || existingDevice.fcm_token, existingDevice.id],
                                (err) => {
                                    if (err) {
                                        console.error('Error updating device:', err);
                                        return res.status(500).json({ error: 'Failed to update device' });
                                    }
                                    
                                    // Update enrollment status to ACTIVE
                                    db.run(
                                        'UPDATE enrollments SET status = ? WHERE id = ?',
                                        ['ACTIVE', enrollment.id],
                                        (updateErr) => {
                                            if (updateErr) {
                                                console.error('Error updating enrollment status:', updateErr);
                                                // Continue even if status update fails
                                            }
                                            
                                            console.log('Device reactivated successfully');
                                            res.json({
                                                device_id: existingDevice.id,
                                                message: 'Device reactivated',
                                                enrollment_id: enrollment.id
                                            });
                                        }
                                    );
                                }
                            );
                        } else {
                            console.log('No existing device found, creating new device...');
                            // Create new device
                            db.run(
                                'INSERT INTO devices (enrollment_id, fcm_token, imei) VALUES (?, ?, ?)',
                                [enrollment.id, fcm_token, device_reported_imei],
                                function(err) {
                                    if (err) {
                                        console.error('Error creating device:', err);
                                        return res.status(500).json({ error: 'Failed to create device' });
                                    }
                                    
                                    const deviceId = this.lastID;
                                    console.log(`New device created with ID: ${deviceId}`);
                                    
                                    // Update enrollment status to ACTIVE
                                    db.run(
                                        'UPDATE enrollments SET status = ? WHERE id = ?',
                                        ['ACTIVE', enrollment.id],
                                        (updateErr) => {
                                            if (updateErr) {
                                                console.error('Error updating enrollment status:', updateErr);
                                                // Continue even if status update fails
                                            }
                                            
                                            console.log('Device activated successfully');
                                            res.status(201).json({
                                                device_id: deviceId,
                                                message: 'Device activated successfully',
                                                enrollment_id: enrollment.id
                                            });
                                        }
                                    );
                                }
                            );
                        }
                    }
                );
            }
        );
    } catch (error) {
        console.error('Device activation error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

// Handle shutdown
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            console.error('Error closing database', err);
        } else {
            console.log('Database connection closed');
        }
        process.exit(0);
    });
});

module.exports = app; 
