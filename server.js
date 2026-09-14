const express = require('express');
const mysql = require('mysql');

const app = express();
const port = 3000;

var pool = mysql.createPool({
    connectionLimit: 10,
    host:'localhost',
    user:'root',
    password:'',
    port:3307,
    database:'stepcounter'
});

app.use(express.urlencoded({ extended: true })); // ez kell, hogy a req.body működjön

app.get('/', (_req, res) => {
    res.send('Welcome to the Stepconter API!')
})

// USERS ENDPOINTS -----------------------------

// registration
app.post('/users/register', (req, res) => {
    const { name, email, password, confirm} = req.body;

    //Validate input

    // Check for missing fields
    if (!name || !email || !password || !confirm) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    // Check if password match
    if (password !== confirm) {
        return res.status(400).json({ error: 'Passwords do not match' });
    }

    // Check password strength (later...)

    // Check if email aready exists
    pool.query('SELECT * FROM users WHERE email = ?', [email], (error, results) => {
        if (error) {
            return res.status(500).json({ error: 'Database query error' });
        }

        if (results.length > 0) {
            return res.status(400).json({ error: 'This e-mail aready exists' });
        }

        // Insert new user into database
        pool.query('INSERT INTO users (name, email, password, role) VALUES (?, ?, SHA1(?), "user")', [name, email, password], (error, results) => {
            if (error) {
                return res.status(500).json({ error: 'Database insert error' });
            }
            res.status(201).json({ message: 'User registered successfully' });
        });
    });
});

// login

// logout ?

// password change

// get profile

// update profile

// delete profile

// STEPS ENDPOINTS ----------------------------

// create step

// get steps (user) // table view, calendar view, char view

// update step

// delete step

//ADMIN ENDPOINTS

// get all users
app.get('/admin/users', (_req, res) => {
    pool.query('SELECT * FROM users', (error, results) => {
        if (error){
            res.status(500).json({ 'Database query error: ': error });
        }
        else {
            res.status(200).json(results);
        }
    });
});

// deny user

// statistics (total steps, average steps, top users)

app.listen(port, () => {
    console.log(`Server is running on http:/localhost:${port}`);
});

/**
 * spec:
 * stepcounter app
 * -------------------------------------
 * role:
 * - user
 * - admin
 * 
 * users:
 * - registration
 * - login
 * - logout
 * - password change
 * - get profile
 * - update profile
 * - delete profile
 * 
 * steps:
 * - create step
 * - get steps (user) // table view, calendar view, char view
 * - update step
 * - delete step
 * 
 * admin:
 * - get all users
 * - deny user
 * - statistics (total steps, average steps, top users)
 * 
 * database tables:
 *  - users: id, name, email, password, role, created_at, updated_at, last_login, login_count, is_active
 *  - steps: id, user_id, step_count, date, created_at, updated_at
 */