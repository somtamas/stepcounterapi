const express = require('express');
const mysql = require('mysql');
var sha1 = require('sha1');
var cors = require('cors');

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

app.use(cors()); // Access-Control-Allow-Origin: *
app.use(express.urlencoded({ extended: true })); // ez kell, hogy a req.body működjön
app.use(express.json()); //kommunikáció json formában

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

    //TODO: Check password strength (with regular expression)

    // Check if email aready exists
    pool.query('SELECT * FROM users WHERE email = ?', [email], (error, results) => { // SQL injection !!!
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
app.post('/users/login', (req, res) => {
    const { email, password } = req.body;

    // VALIDATION

    // Check for missing fields
    if (!email || !password) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    // Check email and password exists
    pool.query('SELECT * FROM users WHERE email=? AND password=SHA1(?)', [email, password], (error, results) => {
        if (error) {
            return res.status(500).json({ error: 'Database query error' });
        }
        
        // if this user doesn't exists with this email and password
        if (results.length == 0) {
            return res.status(400).json({ error: 'Invalid credentials! '})
        }

        //TODO: check user is active?
        if (results[0].is_active == 0) {
            return res.status(400).json({ error: 'This user is banned by admin!' });
        }

        // if this user exists with these credentials
        // res.status(200).json({ message: 'You are successfully logged in!'});
        // const loggedUser = results[0];
        const loggedUser = {
            ID: results[0].ID,
            name: results[0].name,
            email: results[0].email,
            role: results[0].role
        }

        //TODO: update last_login and login_count fields in users table
        pool.query('UPDATE users SET last_login=CURRENT_TIMESTAMP, login_count=login_count+1 WHERE ID=?', [results[0].ID,], (error, result)=> {
            if (error) {
                return res.status(500).json({ error: 'Database query error' });
            }

            //TODO: send logged user data to frontend
            return res.status(200).json({ message: 'You are successfully logged in!', loggedUser });
        });
    });
});

// logout ? elvileg ebben a projektben nem kell rá backend endpoint

// password change
app.post('/users/:uid/passmod', (req, res) => {
    const {oldpassword, newpassword, confirm} = req.body; // átvesszük a frontend-ről érkező adatokat
    const uid = req.params.uid; // kiolvassuk az url-ből a userID-t

    // megnézzük hogy minden kötelező mezőt megadott-e
    if (!oldpassword || !newpassword || !confirm) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    // összehasonlítjuk az új jelszavakat
    if (newpassword != confirm) {
        return res.status(400).json({ error: 'The new password and it\'s confirm doesn\'t match!'});
    }

    // megnézzük, hogy az új megegyezik-e a régivel
    if (oldpassword == newpassword) {
        return res.status(400).json({ error: 'The new password equals with olda password!' })
    }

    //TODO: newpassword strength check with regular expression

    // megnézzük hogy a megadott régi jelszó stimmel-e?
    pool.query('SELECT * FROM users WHERE ID=?', [uid], (error, results) => {
        if (error) {
            return res.status(500).json({ error: 'Database query error' });
        }

        // ha nincs ilyen id-jű user
        if (results.length == 0) {
            return res.status(400).json({ error: 'This users doesn\'t exsist!'});
        }

        const oldpasswordHash = sha1(oldpassword);

        // ha nem stimmel a megadott régi jelszó
        if (results[0].password != oldpasswordHash) {
            return res.status(400).json({ error: 'The olda password is not correct!' });
        }

        //update password
        pool.query('UPDATE users SET password=SHA1(?) WHERE ID=?', [newpassword, uid], (error, results) => {
            if (error) {
                return res.status(500).json({ error: 'Database query error' });
            }

            return res.status(200).json({ message: 'The password was modified successfully!'});
        })
    })
});

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