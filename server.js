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
app.get('/users/:uid', (req, res) => {
    const uid = req.params.uid;
 
    if (!uid) {
        return res.status(400).json({ error: 'Missing user identifier' })
    }
 
    pool.query('SELECT * FROM users WHERE ID=?', [uid], (error, results) => {
        if (error) {
            return res.status(500).json({ error: 'Database query error' })
        }
 
        if (results.length == 0) {
            return res.status(400).json({ error: 'User with this ID doesn\'t exits!' });
        }
 
        let user = {
            "name": results[0].name,
            "email": results[0].email,
            "role": results[0].role,
            "created_at": results[0].created_at
        }
 
        return res.status(200).json({ results: user });
 
    });
});

// update profile
app.patch('/users/:uid', (req, res) => {
    const uid = req.params.uid;
    const { username, email, luid } = req.body;
 
    if (!uid || !username || !email || !luid) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
 
    if (uid != luid) {
        return res.status(400).json({ error: 'You are not authorized to update this profile!' });
    }
 
    pool.query('SELECT * FROM users WHERE ID=?', [uid], (error, results) => {
        if (error) {
            return res.status(500).json({ error: 'Database query error.' });
        }
        if (results.length == 0) {
            return res.status(400).json({ error: 'User with this ID doesn\'t exist!' });
        }
 
        if ((username == results[0].name) && (email == results[0].email)) {
            return res.status(200).json({ error: 'No changes detected!' });
        }
 
        pool.query('SELECT * FROM USERS WHERE EMAIL=? AND ID<>?', [email, uid], (error, results2) => {
            if (error) {
                return res.status(500).json({ error: 'Database query error.' });
            }
            if (results2.length > 0) {
                return res.status(400).json({ error: 'Email is already in use!' });
            }
 
            pool.query('UPDATE users SET name =?, email=? updated_at=CURRENT_TIMESTAMP WHERE ID=?', [username, email, uid], (error, results3) => {
                if (error) {
                    return res.status(500).json({ error: 'Database query error.' });
                }
                return res.status(200).json({ message: 'Profile updated successfully!' });
            });
        });
    });
});
 

// delete profile
app.delete('/users/:uid', (req, res) => {
    const uid = req.params.uid;
    const loggedUserID = req.body.luid;
 
    if (!uid) {
        return res.status(400).json({ error: 'Missing user identifier' });
    }
 
    if (uid != loggedUserID) {
        return res.status(400).json({ error: 'You don\'t have permission to delete this user!' });
    }
 
    pool.query('DELETE FROM users WHERE ID=?', [uid], (error, results) => {
        if (error) {
            return res.status(500).json({ error: 'Database query error' });
        }
 
        if (results.affectedRows == 1) {
            return res.status(200).json({ error: 'User deleted successfully!' })
        }
 
        return res.status(200).json({ message: 'No deletion occured!' });
 
    });
});

// STEPS ENDPOINTS ----------------------------

// create step
app.post('/steps/:uid', (req, res) => {
    const uid = req.params.uid;
    const { luid, date, step_count } = req.body;
    var todaysDate = new Date();
   
 
    if (!uid || !luid || !date || step_count == null) {
        return res.status(400).json({ error: 'Missing fields in.' });
    }
    if (uid != luid) {
        return res.status(400).json({ error: 'You don\'t have permission to add steps for this user!' });
    }
    if (step_count <= 0) {
        return res.status(400).json({ error: 'Step count cannot be negative or negative.' });
    }
    if (new Date(date) > todaysDate){
      return res.status(400).json({error: 'The date can not be in the future or can not be in negative.'})
    }
 
    pool.query('SELECT * FROM users WHERE ID=?', [uid], (error, results) => {
        if (error) {
            return res.status(500).json({ error: 'Database query error.' });
        }
        if (results.length == 0) {
            return res.status(400).json({ error: 'User with this ID doesn\'t exist!' });
        }
 
        pool.query('SELECT * FROM steps WHERE user_id=? AND date=?', [uid, date], (error, results2) => {
            if (error) {
                return res.status(500).json({ error: 'Database query error.' });
            }
            if (results2.length > 0) {
                return res.status(400).json({ error: 'A step entry already exists for this date. Use update.' });
            }
 
            pool.query('INSERT INTO steps (user_id, step_count, date) VALUES (?, ?, ?)', [uid, step_count, date], (error, results3) => {
                    if (error) {
                        return res.status(500).json({ error: 'Database query error.' });
                    }
                    return res.status(200).json({ message: 'Step entry added successfully!'});
                }
            );
        });
    });
});

// get steps (user) // table view, calendar view, char view
app.post('/steps/:uid', (req, res) => {
    const uid = req.params.uid;
    const luid = req.body.luid;
 
    if (!uid) {
        return res.status(400).json({ error: 'Missing user identifier' })
    }
 
    pool.query('SELECT * FROM steps WHERE user_id=?', [uid], (error, results) => {
        if (error) {
            return res.status(500).json({ error: 'Database query error' })
        }
 
        if (results.length == 0) {
            return res.status(400).json({ error: 'User with this ID doesn\'t exits!' });
        }
 
        let step = {
            "user_id": results[0].user_id,
            "step_count": results[0].step_count,
            "created_at": results[0].created_at,
            "updated_at": results[0].updated_at
        }
 
        return res.status(200).json({ results: step });
 
    });
});

// update step
app.patch('/users/:uid/steps/:stepID', (req, res) => {
    const uid = req.params.uid;
    const stepID = req.params.stepID;
    const { luid, step_count } = req.body;
 
    if (!uid || !stepID || !luid || step_count == null) {
        return res.status(400).json({ error: 'Missing fields.' });
    }
    if (uid != luid) {
        return res.status(400).json({ error: 'You don\'t have permission to update this step entry!' });
    }
    if (step_count <= 0) {
        return res.status(400).json({ error: 'Step count cannot be negative or null.' });
    }
 
    pool.query('SELECT * FROM steps WHERE ID=?', [stepID], (error, results) => {
        if (error) {
            return res.status(500).json({ error: 'Database query error.' });
        }
        if (results.length == 0) {
            return res.status(400).json({ error: 'Step entry with this ID doesn\'t exist!' });
        }
        if (results[0].user_id != uid) {
            return res.status(400).json({ error: 'This step entry doesn\'t belong to this user!' });
        }
 
        pool.query('UPDATE steps SET step_count=?, updated_at=CURRENT_TIMESTAMP WHERE ID=?', [step_count, stepID], (error, results2) => {
                if (error) {
                    return res.status(500).json({ error: 'Database query error.' });
                }
                return res.status(200).json({ message: 'Step entry updated successfully!' });
            }
        );
    });
});

// delete step
app.delete('/users/:uid/steps/:stepID', (req, res) => {
  const uid = req.params.uid;
  const luid = req.body.luid;
  const stepID = req.params.stepID;
 
  if(!uid || !luid){
    return res.status(400).json({error: 'Missing user identifier.'});
  }
  if (uid!=luid){
    return res.status(400).json({error: 'You don\'t have permission to delete this user!'});
  }
  pool.query('DELETE FROM steps WHERE ID=?', [stepID], (error, results) => {
    if (error){
      return res.status(500).json({error: 'Database query error.'})
    }
    if (results.affectedRows == 1){
            return res.status(200).json({message: 'Steps data deleted successfully!'});
        }
        return res.status(200).json({error: 'No deletion occurred.'});
  })
})

//ADMIN ENDPOINTS

// get all users
app.patch('/admin/:uid/status', (req, res) => {
    const { uid } = req.body;
 
    if (!uid) {
        return res.status(400).json({ error: 'Missing user identifier' });
    }
    pool.query('SELECT * FROM users WHERE ID=?', [uid], (error, results) => {
        if (error) {
            return res.status(500).json({ error: 'Database query error.' });
        }
        if (results.length == 0) {
            return res.status(400).json({ error: 'User with this ID doesn\'t exist!' });
        }
 
        if (results[0].role != 'admin') {
            return res.status(400).json({ error: 'Only admins can change user statuses!' });
        }
        pool.query('SELECT * FROM users WHERE ID=?', [uid], (error, results) => {
            if (error) {
                return res.status(500).json({ error: 'Database query error.' });
            }
            if (results.length == 0) {
                return res.status(400).json({ error: 'User with this ID doesn\'t exist!' });
            }
 
            pool.query('UPDATE users SET is_active= not is_active WHERE ID=?', [uid], (error, results2) => {
                if (error) {
                    return res.status(500).json({ error: 'Database query error.' });
                }
                return res.status(200).json({ message: 'User status changed successfully!' });
            });
        });
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