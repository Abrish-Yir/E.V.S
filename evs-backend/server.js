// server.js
// This Node.js server now handles user registration, login, and vote submission
// by connecting to a PostgreSQL database.

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { Pool } = require('pg'); // Import the PostgreSQL client library

const app = express();
const PORT = 3001; // The port your backend server will listen on

// --- Middleware Setup ---
// Enable CORS to allow your frontend to make requests.
app.use(cors());
// Use body-parser to parse JSON formatted request bodies.
app.use(bodyParser.json());

// --- Database Connection Pool Setup ---
// IMPORTANT: You must replace the placeholder values below with your actual
// PostgreSQL database credentials. It's highly recommended to use environment
// variables for production.
// Change this
// To this
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Test the database connection on server start.
pool.connect()
    .then(() => {
        console.log('Connected to PostgreSQL database successfully!');
    })
    .catch(err => {
        console.error('Error connecting to the database', err.stack);
        process.exit(1); // Exit the process if the database connection fails
    });

// --- API Endpoints ---

/**
 * POST /register
 * Handles new user registration. It inserts the user's nationalId and a
 * hashed password into the 'users' table.
 */
app.post('/register', async (req, res) => {
    const { nationalId, password } = req.body;

    // Basic validation: check if nationalId and password are provided
    if (!nationalId || !password) {
        return res.status(400).json({ success: false, message: 'National ID and password are required.' });
    }

    try {
        // Assume the database has a 'users' table with 'national_id' and 'password_hash' columns.
        // Check if a user with the given nationalId already exists.
        const userCheckQuery = 'SELECT national_id FROM users WHERE national_id = $1';
        const userCheckResult = await pool.query(userCheckQuery, [nationalId]);

        if (userCheckResult.rows.length > 0) {
            return res.status(409).json({ success: false, message: 'National ID already registered.' });
        }

        // Hash the password for security before storing it in the database.
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the new user into the 'users' table.
        const insertUserQuery = 'INSERT INTO users (national_id, password_hash) VALUES ($1, $2)';
        await pool.query(insertUserQuery, [nationalId, hashedPassword]);

        res.status(201).json({ success: true, message: 'Registration successful!' });
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ success: false, message: 'An error occurred during registration.' });
    }
});

/**
 * POST /login
 * Handles user login. It queries the database for the user and compares the
 * provided password with the stored hash.
 */
app.post('/login', async (req, res) => {
    const { nationalId, password } = req.body;

    if (!nationalId || !password) {
        return res.status(400).json({ success: false, message: 'National ID and password are required.' });
    }

    try {
        // Assume the database has a 'users' table with 'national_id' and 'password_hash' columns.
        // Retrieve the user from the database.
        const userQuery = 'SELECT national_id, password_hash FROM users WHERE national_id = $1';
        const userResult = await pool.query(userQuery, [nationalId]);
        const user = userResult.rows[0];

        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid National ID or password.' });
        }

        // Compare the provided password with the stored hashed password.
        const passwordMatch = await bcrypt.compare(password, user.password_hash);

        if (passwordMatch) {
            res.status(200).json({ success: true, message: 'Login successful!', userId: user.national_id });
        } else {
            res.status(401).json({ success: false, message: 'Invalid National ID or password.' });
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ success: false, message: 'An error occurred during login.' });
    }
});

/**
 * POST /vote
 * Handles vote submission. It checks if the user has already voted and
 * inserts a new vote record into the 'votes' table.
 */
app.post('/vote', async (req, res) => {
    const { userId, candidate } = req.body;

    if (!userId || !candidate) {
        return res.status(400).json({ success: false, message: 'User ID (National ID) and candidate are required.' });
    }

    try {
        // Assume the database has a 'votes' table with 'user_id' and 'candidate_name' columns.
        // Check if the user has already voted.
        const voteCheckQuery = 'SELECT user_id FROM votes WHERE user_id = $1';
        const voteCheckResult = await pool.query(voteCheckQuery, [userId]);
        
        if (voteCheckResult.rows.length > 0) {
            return res.status(409).json({ success: false, message: 'You have already voted.' });
        }

        // Insert the new vote into the 'votes' table.
        const insertVoteQuery = 'INSERT INTO votes (user_id, candidate_name) VALUES ($1, $2)';
        await pool.query(insertVoteQuery, [userId, candidate]);

        res.status(200).json({ success: true, message: `Vote for ${candidate} submitted successfully!` });
    } catch (error) {
        console.error('Error submitting vote:', error);
        res.status(500).json({ success: false, message: 'An error occurred while submitting your vote.' });
    }
});

// --- Start the Server ---
app.listen(PORT, () => {
    console.log(`Node.js backend running on http://localhost:${PORT}`);
});
