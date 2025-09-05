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
// The connectionString is read from the DATABASE_URL environment variable on Render.
// The ssl option is required to connect to the PostgreSQL database on Render.
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

// --- User Registration Endpoint ---
/**
 * Handles user registration. It hashes the user's password and stores the national ID
 * and hashed password in the 'users' table.
 */
app.post('/register', async (req, res) => {
    const { nationalId, password } = req.body;

    // Basic validation
    if (!nationalId || !password) {
        return res.status(400).json({ success: false, message: 'National ID and password are required.' });
    }

    try {
        // Check if user already exists
        const userCheckQuery = 'SELECT national_id FROM users WHERE national_id = $1';
        const userCheckResult = await pool.query(userCheckQuery, [nationalId]);

        if (userCheckResult.rows.length > 0) {
            return res.status(409).json({ success: false, message: 'National ID already registered.' });
        }

        // Hash the password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Insert new user into the database
        const insertUserQuery = 'INSERT INTO users (national_id, password_hash) VALUES ($1, $2)';
        await pool.query(insertUserQuery, [nationalId, hashedPassword]);

        res.status(201).json({ success: true, message: 'Registration successful. You can now log in.' });
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ success: false, message: 'An unexpected error occurred during registration.' });
    }
});

// --- User Login Endpoint ---
/**
 * Handles user login. It compares the provided password with the stored hashed password.
 */
app.post('/login', async (req, res) => {
    const { nationalId, password } = req.body;

    if (!nationalId || !password) {
        return res.status(400).json({ success: false, message: 'National ID and password are required.' });
    }

    try {
        // Find the user by national ID
        const userQuery = 'SELECT national_id, password_hash FROM users WHERE national_id = $1';
        const result = await pool.query(userQuery, [nationalId]);

        if (result.rows.length === 0) {
            return res.status(401).json({ success: false, message: 'Invalid National ID or password.' });
        }

        const user = result.rows[0];
        // Compare the provided password with the hashed password in the database
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (isMatch) {
            // Check if the user has already voted
            const voteCheckQuery = 'SELECT user_id FROM votes WHERE user_id = $1';
            const voteCheckResult = await pool.query(voteCheckQuery, [nationalId]);
            
            if (voteCheckResult.rows.length > 0) {
                return res.status(403).json({ success: false, message: 'You have already voted.' });
            }

            res.status(200).json({ success: true, message: 'Login successful!', userId: user.national_id });
        } else {
            res.status(401).json({ success: false, message: 'Invalid National ID or password.' });
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ success: false, message: 'An unexpected error occurred during login.' });
    }
});

// --- Vote Submission Endpoint ---
/**
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
        res.status(500).json({ success: false, message: 'An unexpected error occurred while submitting the vote.' });
    }
});


// Start the server
app.listen(PORT, () => {
    console.log(`Node.js backend running on http://localhost:${PORT}`);
});
// Function to create tables if they don't exist
async function createTables() {
    const createUsersTable = `
        CREATE TABLE IF NOT EXISTS users (
            national_id VARCHAR(255) PRIMARY KEY,
            password_hash VARCHAR(255) NOT NULL
        );
    `;
    const createVotesTable = `
        CREATE TABLE IF NOT EXISTS votes (
            user_id VARCHAR(255) PRIMARY KEY,
            candidate_name VARCHAR(255) NOT NULL,
            voted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
    `;
    try {
        await pool.query(createUsersTable);
        await pool.query(createVotesTable);
        console.log('Tables created successfully or already exist!');
    } catch (err) {
        console.error('Error creating tables:', err);
    }
}

// Call the function to create tables when the server starts
createTables();

// --- Get Voting Results Endpoint ---
/**
 * Handles requests for voting results. It queries the 'votes' table,
 * groups votes by candidate, and returns a count for each.
 */
app.get('/results', async (req, res) => {
    try {
        const resultsQuery = `
            SELECT candidate_name, COUNT(*) AS vote_count
            FROM votes
            GROUP BY candidate_name
            ORDER BY vote_count DESC;
        `;
        const result = await pool.query(resultsQuery);
        res.status(200).json({ success: true, results: result.rows });
    } catch (error) {
        console.error('Error fetching results:', error);
        res.status(500).json({ success: false, message: 'An unexpected error occurred while fetching results.' });
    }
});
