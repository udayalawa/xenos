const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = 'your_jwt_secret_key';

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

// Create a write stream for request logging
const requestLogStream = fs.createWriteStream(
    path.join(logsDir, 'requests.log'),
    { flags: 'a' }
);

// Middleware
app.use(cors());
app.use(express.json());

// Request logging middleware
app.use((req, res, next) => {
    const timestamp = new Date().toISOString();
    const logData = {
        timestamp,
        method: req.method,
        url: req.originalUrl,
        headers: req.headers,
        body: req.body,
        query: req.query,
        params: req.params
    };
    
    // Log to console with clear formatting
    console.log('\n' + '='.repeat(80));
    console.log(`[${timestamp}] ${req.method} ${req.originalUrl}`);
    if (Object.keys(req.body).length > 0) {
        console.log('Request Body:', JSON.stringify(req.body, null, 2));
    }
    
    // Log to file
    requestLogStream.write(JSON.stringify(logData) + '\n');
    
    // Store the original send function
    const originalSend = res.send;
    
    // Override the send function to log the response
    res.send = function(body) {
        // Log response
        console.log(`Response Status: ${res.statusCode}`);
        try {
            const jsonBody = typeof body === 'string' ? JSON.parse(body) : body;
            console.log('Response Body:', JSON.stringify(jsonBody, null, 2));
        } catch (e) {
            console.log('Response Body:', body);
        }
        console.log('='.repeat(80) + '\n');
        
        // Call the original send function
        return originalSend.call(this, body);
    };
    
    next();
});

// Database setup
const db = new sqlite3.Database('./emi-lock.db', (err) => {
    if (err) {
        console.error('Error connecting to database:', err.message);
        process.exit(1);
    }
    console.log('Connected to SQLite database');
    
    // Create tables if they don't exist
    db.serialize(() => {
        // Enrollments table
        db.run(`CREATE TABLE IF NOT EXISTS enrollments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_name TEXT NOT NULL,
            customer_email TEXT,
            customer_phone TEXT,
            imei TEXT NOT NULL,
            secret_code TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'PENDING',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);
        
        // Devices table
        db.run(`CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            enrollment_id INTEGER NOT NULL,
            device_reported_imei TEXT NOT NULL,
            fcm_token TEXT,
            os_version TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (enrollment_id) REFERENCES enrollments (id)
        )`);
        
        console.log('Database tables verified/created');
    });
});

// Helper function to generate secret code
function generateSecretCode(length = 8) {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
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

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Create new enrollment
app.post('/api/enrollments', authenticateToken, (req, res) => {
    const { customer_name, customer_email, customer_phone, imei } = req.body;
    
    if (!customer_name || !imei) {
        return res.status(400).json({ 
            error: 'Customer name and IMEI are required' 
        });
    }
    
    const secret_code = generateSecretCode();
    const enrollment = {
        customer_name,
        customer_email,
        customer_phone,
        imei,
        secret_code,
        status: 'PENDING'
    };
    
    db.run(
        'INSERT INTO enrollments (customer_name, customer_email, customer_phone, imei, secret_code, status) VALUES (?, ?, ?, ?, ?, ?)',
        [customer_name, customer_email, customer_phone, imei, secret_code, 'PENDING'],
        function(err) {
            if (err) {
                console.error('Error creating enrollment:', err);
                return res.status(500).json({ error: 'Failed to create enrollment' });
            }
            
            enrollment.id = this.lastID;
            res.status(201).json(enrollment);
        }
    );
});

// Device activation endpoint
app.post('/api/devices/activate', (req, res) => {
    console.log('\n=== DEVICE ACTIVATION REQUEST ===');
    console.log('Request Body:', JSON.stringify(req.body, null, 2));
    
    const { secret_code, device_reported_imei, fcm_token, os_version } = req.body;
    
    // Log all received values
    console.log('\n=== PARSED REQUEST VALUES ===');
    console.log(`secret_code: ${secret_code ? '*** (present)' : 'MISSING'}`);
    console.log(`device_reported_imei: ${device_reported_imei || 'MISSING'}`);
    console.log(`fcm_token: ${fcm_token ? '*** (present)' : 'MISSING'}`);
    console.log(`os_version: ${os_version || 'MISSING'}`);

    // Validate required fields
    if (!secret_code || !device_reported_imei) {
        const error = 'Missing required fields: secret_code and device_reported_imei are required';
        console.error('\n!!! VALIDATION ERROR !!!');
        console.error('Error:', error);
        console.log('=== ACTIVATION REQUEST FAILED (validation) ===\n');
        return res.status(400).json({ 
            success: false,
            error,
            received_fields: {
                secret_code: !!secret_code,
                device_reported_imei: !!device_reported_imei,
                fcm_token: !!fcm_token,
                os_version: !!os_version
            },
            timestamp: new Date().toISOString()
        });
    }
    
    console.log('\n=== DATABASE QUERY ===');
    const enrollmentQuery = 'SELECT * FROM enrollments WHERE secret_code = ?';
    console.log(`Executing: ${enrollmentQuery} with params: [${secret_code}]`);
    
    db.get(enrollmentQuery, [secret_code], (err, enrollment) => {
        if (err) {
            console.error('\n!!! DATABASE ERROR !!!');
            console.error('Error when finding enrollment:', err);
            console.log('=== ACTIVATION REQUEST FAILED (database error) ===\n');
            return res.status(500).json({ 
                success: false,
                error: 'Database error when finding enrollment',
                details: err.message,
                timestamp: new Date().toISOString()
            });
        }
        
        console.log('\n=== ENROLLMENT LOOKUP RESULT ===');
        if (!enrollment) {
            const error = `No enrollment found with secret code: ${secret_code}`;
            console.error('Error:', error);
            console.log('=== ACTIVATION REQUEST FAILED (not found) ===\n');
            return res.status(404).json({ 
                success: false,
                error: 'Invalid activation code',
                details: error,
                secret_code_used: secret_code,
                timestamp: new Date().toISOString()
            });
        }
        
        console.log('Enrollment found:', JSON.stringify({
            id: enrollment.id,
            status: enrollment.status,
            created_at: enrollment.created_at,
            updated_at: enrollment.updated_at
        }, null, 2));
        
        // Check if enrollment is already used
        if (enrollment.status === 'USED') {
            const error = `Enrollment ${enrollment.id} is already used`;
            console.error('\n!!! ENROLLMENT ALREADY USED !!!');
            console.error('Error:', error);
            console.log('=== ACTIVATION REQUEST FAILED (already used) ===\n');
            return res.status(400).json({ 
                success: false,
                error: 'This activation code has already been used',
                enrollment_id: enrollment.id,
                status: enrollment.status,
                timestamp: new Date().toISOString()
            });
        }
        
        // Check if device is already registered with this enrollment
        console.log('\n=== CHECKING FOR EXISTING DEVICE ===');
        const deviceCheckQuery = 'SELECT * FROM devices WHERE enrollment_id = ?';
        console.log(`Executing: ${deviceCheckQuery} with params: [${enrollment.id}]`);
        
        db.get(deviceCheckQuery, [enrollment.id], (err, existingDevice) => {
            if (err) {
                console.error('\n!!! DATABASE ERROR !!!');
                console.error('Error checking for existing device:', err);
                console.log('=== ACTIVATION REQUEST FAILED (database error) ===\n');
                return res.status(500).json({ 
                    success: false,
                    error: 'Database error when checking for existing device',
                    details: err.message,
                    timestamp: new Date().toISOString()
                });
            }
            
            const now = new Date().toISOString();
            console.log('Current timestamp:', now);
            
            if (existingDevice) {
                console.log('\n=== UPDATING EXISTING DEVICE ===');
                console.log('Device exists, updating with data:', {
                    fcm_token: fcm_token ? '*** (present)' : 'MISSING',
                    last_seen: now,
                    os_version: os_version || 'MISSING',
                    device_id: existingDevice.id
                });
                
                const updateDeviceQuery = `
                    UPDATE devices 
                    SET fcm_token = ?, 
                        last_seen = ?, 
                        os_version = ? 
                    WHERE id = ?
                `;
                console.log(`Executing: ${updateDeviceQuery} with params: [${fcm_token || 'null'}, ${now}, ${os_version || 'null'}, ${existingDevice.id}]`);
                
                db.run(updateDeviceQuery, [fcm_token, now, os_version, existingDevice.id], function(err) {
                    if (err) {
                        console.error('\n!!! DATABASE ERROR !!!');
                        console.error('Error updating existing device:', err);
                        console.log('=== ACTIVATION REQUEST FAILED (database error) ===\n');
                        return res.status(500).json({ 
                            success: false,
                            error: 'Database error when updating device',
                            details: err.message,
                            timestamp: now
                        });
                    }
                    
                    // Update enrollment status to USED
                    console.log('\n=== UPDATING ENROLLMENT STATUS ===');
                    const updateEnrollmentQuery = `
                        UPDATE enrollments 
                        SET status = 'USED', 
                            updated_at = ? 
                        WHERE id = ?
                    `;
                    console.log(`Executing: ${updateEnrollmentQuery} with params: [${now}, ${enrollment.id}]`);
                    
                    db.run(updateEnrollmentQuery, [now, enrollment.id], function(err) {
                        if (err) {
                            console.error('\n!!! WARNING: Failed to update enrollment status !!!');
                            console.error('Error:', err);
                            // Continue with response even if enrollment update fails
                        } else {
                            console.log(`Successfully marked enrollment ${enrollment.id} as USED`);
                        }
                        
                        console.log('\n=== DEVICE REACTIVATION SUCCESSFUL ===');
                        const response = {
                            success: true,
                            message: 'Device reactivated successfully',
                            deviceId: existingDevice.id,
                            enrollmentId: enrollment.id,
                            timestamp: now,
                            action: 'updated',
                            enrollmentStatus: 'USED'
                        };
                        
                        console.log('Sending success response:', JSON.stringify(response, null, 2));
                        console.log('=== ACTIVATION REQUEST COMPLETED SUCCESSFULLY ===\n');
                        res.status(200).json(response);
                    });
                });
            } else {
                console.log('\n=== CREATING NEW DEVICE ===');
                console.log('No existing device found, creating new device with data:', {
                    enrollment_id: enrollment.id,
                    device_reported_imei,
                    fcm_token: fcm_token ? '*** (present)' : 'MISSING',
                    os_version: os_version || 'MISSING',
                    created_at: now,
                    last_seen: now
                });
                
                const insertDeviceQuery = `
                    INSERT INTO devices (
                        enrollment_id, 
                        device_reported_imei, 
                        fcm_token, 
                        os_version, 
                        created_at, 
                        last_seen
                    ) VALUES (?, ?, ?, ?, ?, ?)
                `;
                console.log(`Executing: ${insertDeviceQuery} with params: [${enrollment.id}, ${device_reported_imei}, ${fcm_token || 'null'}, ${os_version || 'null'}, ${now}, ${now}]`);
                
                db.run(insertDeviceQuery, [enrollment.id, device_reported_imei, fcm_token, os_version, now, now], function(err) {
                    if (err) {
                        console.error('\n!!! DATABASE ERROR !!!');
                        console.error('Error creating new device:', err);
                        console.log('=== ACTIVATION REQUEST FAILED (database error) ===\n');
                        return res.status(500).json({ 
                            success: false,
                            error: 'Database error when creating device',
                            details: err.message,
                            timestamp: now
                        });
                    }
                    
                    const deviceId = this.lastID;
                    console.log(`Successfully created new device with ID: ${deviceId}`);
                    
                    // Update enrollment status to USED
                    console.log('\n=== UPDATING ENROLLMENT STATUS ===');
                    const updateEnrollmentQuery = `
                        UPDATE enrollments 
                        SET status = 'USED', 
                            updated_at = ? 
                        WHERE id = ?
                    `;
                    console.log(`Executing: ${updateEnrollmentQuery} with params: [${now}, ${enrollment.id}]`);
                    
                    db.run(updateEnrollmentQuery, [now, enrollment.id], function(err) {
                        if (err) {
                            console.error('\n!!! WARNING: Failed to update enrollment status !!!');
                            console.error('Error:', err);
                            // Continue with response even if enrollment update fails
                        } else {
                            console.log(`Successfully marked enrollment ${enrollment.id} as USED`);
                        }
                        
                        console.log('\n=== DEVICE ACTIVATION SUCCESSFUL ===');
                        const response = {
                            success: true,
                            message: 'Device activated successfully',
                            deviceId: deviceId,
                            enrollmentId: enrollment.id,
                            timestamp: now,
                            action: 'created',
                            enrollmentStatus: 'USED'
                        };
                        
                        console.log('Sending success response:', JSON.stringify(response, null, 2));
                        console.log('=== ACTIVATION REQUEST COMPLETED SUCCESSFULLY ===\n');
                        res.status(201).json(response);
                    });
                });
            }
        });
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log('Logs directory:', logsDir);
});

// Handle process termination
process.on('SIGINT', () => {
    console.log('\nShutting down server...');
    // Close database connection
    db.close((err) => {
        if (err) {
            console.error('Error closing database connection:', err);
        } else {
            console.log('Database connection closed');
        }
        process.exit(0);
    });
});

module.exports = app;
