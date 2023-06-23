const express = require('express')
const app = express()
const session = require('express-session');
const bcrypt = require('bcrypt');


const port = 3000


app.use(express.urlencoded({ extended: true }));

app.set('view engine', "ejs");

const mysql = require('mysql');

const connect = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "auth_exo_node",
});

app.get('/', (req, res) => {
    res.redirect('/login')
})

connect.connect(function (err) {
    if (err) throw err;
    console.log("Connexion établie");
})

app.use(
    session({
        secret: 'secret',
        resave: true,
        saveUninitialized: true,
    })
);

const requireLogin = (req, res, next) => {
    if (!req.session.userId) {
        res.redirect('/login');
    } else {
        next();
    }
};

app.get('/', requireLogin, (req, res) => {
    const isAdmin = req.session.isAdmin;
    const username = req.session.username;
    res.render('home', { isAdmin, username });
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', (req, res) => {
    const { username, password, role } = req.body;

    // Vérifier si l'utilisateur existe déjà
    const checkUserQuery = 'SELECT COUNT(*) AS count FROM users WHERE username = ?';
    connect.query(checkUserQuery, [username], (err, results) => {
        if (err) throw err;

        const count = results[0].count;

        if (count > 0) {
            return res.redirect('/register?error=user_exists');
        }

        // Hacher le mot de passe
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) throw err;

            // Insérer l'utilisateur dans la base de données
            const insertUserQuery = 'INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)';
            connect.query(insertUserQuery, [username, hashedPassword, role], (err, results) => {
                if (err) throw err;

                res.redirect('/login');
            });
        });
    });
});

app.get('/dashboard', (req, res) => {
    const isAdmin = req.session.isAdmin;
    const userId = req.session.userId;

    // Récupérer les détails de l'utilisateur depuis la base de données
    const getUserQuery = 'SELECT id, username, role FROM users WHERE id = ?';
    connect.query(getUserQuery, [userId], (err, userResult) => {
        if (err) throw err;

        // Vérifier si des résultats ont été renvoyés et s'ils ont les propriétés attendues
        if (userResult && userResult.length > 0 && userResult[0].username) {
            const user = userResult[0];
            res.render('dashboard', { isAdmin, user });
        } else {
            res.send('Aucun utilisateur trouvé');
        }
    });
});


app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const getUserQuery = 'SELECT id, username, password, email, role FROM users WHERE username = ?'
    connect.query(getUserQuery, [username], (err, results) => {
        if (err) throw err;

        if (results.length === 1) {
            const user = results[0];

            //verif le mdp

            bcrypt.compare(password, user.password, (err, isMatch) => {
                if (isMatch) {
                    req.session.userId = user.id;
                    req.session.username = user.username;
                    req.session.isAdmin = user.role === 'admin';
                    res.redirect('/dashboard');
                } else {
                    res.redirect('/login');
                }
            })
        }
    })
});

app.get('/login', (req, res) => {
    res.render('login');
});


app.listen(port, () => {
    console.log("Le serveur tourne sur la page http://127.0.0.1:3000");
})