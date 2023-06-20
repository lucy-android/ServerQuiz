require('dotenv').config()


const express = require("express")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const constants = require("./constants");
const mysql = require('mysql2');

const app = express()
app.use(express.json())

const users = []
let refreshTokens = []

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'NEWPASSWORD',
    database: 'first',
});


app.post('/register', async (req, res) => {
    try {
        /*
           At first I need to check whether a user with such login already exists.
        */

        let existLoginSql = `SELECT * FROM users WHERE login=\"${req.body.login}\"`;

        connection.query(existLoginSql, (err, result) => {
            if (err) throw err;
            console.log(result);

            if (result.length != 0) {
                console.log("User with such login already exists!");
                res.status(400).send("User with such login already exists!")
            }
        });

        /*
          if we arrive here, it means that the user has unique login
        */

        // here we hash the password provided for registration
        const hashedPassword = await bcrypt.hash(req.body.password, 10)

        // create a new user

        const user = { firstname: req.body.firstname, lastname: req.body.lastname, login: req.body.login, password: hashedPassword }

        // and now we execute an sql statement to insert the new user into the users table
        let insertSql = `INSERT INTO users (firstname, lastname, login, hashedPassword) 
           VALUES ("${user.firstname}", "${user.lastname}", "${user.login}", "${user.password}")`;

        connection.query(insertSql, (err, result) => {
            if (err) throw err;
            console.log(result);
            res.status(201).json({ firstname: user.firstname, lastname: user.lastname, login: user.login }).send()
        });
    } catch {
        res.status(500).send()
    }
})

app.post('/login', async (req, res) => {
    // check whether a user with such login exists

    let findUserSQLstatement = `SELECT * FROM users WHERE login=\"${req.body.login}\"`;

    connection.query(findUserSQLstatement, async (err, result) => {
        if (err) throw err;
        console.log(`query result for users with login ${req.body.login}: ` + result);

        if (result.length == 0) {
            console.log("User with such login does not exist!");
            res.status(401).send(constants.NOT_ALLOWED)
        }

        try {

            /* 
               After the user has been found, get his or her password, and then compare the
               hashed password from the database response to the password passed in the query.
               If the comparison is successful, return tokens.
            */

            const entry = result[0];
            const login = entry.login;
            const hashedPassword = entry.hashedPassword;

            const comparisonResult = await bcrypt.compare(req.body.password, hashedPassword);

            if (comparisonResult) {
                const user = { login: login }
                const accessToken = generateAccessToken(user)

                const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)

                let updateSQLStatement = `UPDATE users SET refreshtoken=\"${refreshToken}\" WHERE login=\"${user.login}\"`;

                connection.query(updateSQLStatement, async (err, result) => {
                    if (err) throw err;
                    console.log(result);
                    res.status(200).send({ accessToken: accessToken, refreshToken: refreshToken })
                })
            } else {
                res.status(401).send(constants.NOT_ALLOWED)
            }
        } catch {
            res.status(500).send()
        }

    });
})

app.post('/refreshtoken', (req, res) => {
    const refreshToken = req.body.token
    if (refreshToken == null) return res.sendStatus(401)
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403)
    jwt.verify(refreshToken.toString(), process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)
        const accessToken = generateAccessToken({ name: user.name })
        res.json({ accessToken: accessToken })
    })
})

app.post('/logout', (req, res) => {
    const refreshToken = req.body.token

    if (refreshToken == null) {
        return res.sendStatus(401)
    }
    let index = refreshTokens.indexOf(refreshToken);

    if (index !== -1) {
        refreshTokens.splice(index, 1);
        return res.status(200).send({ message: constants.LOGGED_OUT });
    }

    return res.status(401).send({ message: constants.BAD_USER });

})


app.get('/quotes', (req, res) => {

    connection.connect(function (err) {
        if (err) throw err;
        console.log("Connected!");
    });

    var sql = "SELECT * FROM quote";

    connection.query(sql, (err, result) => {
        if (err) throw err;
        console.log(result);
        return res.status(200).send(result);
    });
})

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' })
}


app.listen(3000) 