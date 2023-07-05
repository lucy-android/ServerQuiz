require('dotenv').config()


const express = require("express")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const constants = require("./constants");
const mysql = require('mysql2');
const promise = require('mysql2/promise')

const app = express()
app.use(express.json())


const connection = mysql.createConnection({
    host: process.env.HOST_NAME,
    user: process.env.USER_NAME,
    password: process.env.PASSWORD,
    database: process.env.DATABASE_NAME,
}).promise();


app.post('/register', async (req, res) => {

    const [rows] = await connection.query(constants.EXIST_LOGIN_SQL, [req.body.login]);

    console.log(rows);

    if (rows.length !== 0) {
        console.log(constants.USER_EXISTS);

        return res
            .status(constants.HTTP_STATUS_BAD_REQUEST)
            .send(constants.USER_EXISTS);
    }

    const hashedPassword = await bcrypt.hash(req.body.password, constants.SALT_ROUNDS);

    const user = {
        firstname: req.body.firstname,
        lastname: req.body.lastname,
        login: req.body.login,
        password: hashedPassword
    };

    const result = await connection.query(constants.INSERT_SQL, [user.firstname, user.lastname, user.login, user.password]);

    if (result) {
        return res
            .status(constants.HTTP_STATUS_CREATED)
            .json({ firstname: user.firstname, lastname: user.lastname, login: user.login })
            .send();
    }
});

app.post('/login', async (req, res) => {

    let findUserSQLstatement = constants.EXIST_LOGIN_SQL;

    const [rows] = await connection.query(findUserSQLstatement, [req.body.login]);
    if (rows.length == 0) {
        console.log(constants.USER_NOT_EXISTS);
        return res.status(constants.HTTP_STATUS_UNAUTHORIZED).send(constants.NOT_ALLOWED);
    }
    const entry = rows[0];
    const login = entry.login;
    const hashedPassword = entry.hashedPassword;

    const comparisonResult = await bcrypt.compare(req.body.password, hashedPassword);

    if (comparisonResult) {
        const user = { login: login }
        const accessToken = generateAccessToken(user)

        const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)

        let updateSQLStatement = constants.UPDATE_REFRESH_SQL;

        const result = await connection.query(updateSQLStatement, [refreshToken, user.login]);
        console.log(result);
        return res
            .status(constants.HTTP_STATUS_OK)
            .send({ accessToken: accessToken, refreshToken: refreshToken })
    } else {
        res.status(constants.HTTP_STATUS_UNAUTHORIZED).send(constants.NOT_ALLOWED)
    }
});


app.post('/refreshtoken', (req, res) => {
    const refreshToken = req.body.token
    if (refreshToken == null) return res.sendStatus(constants.HTTP_STATUS_UNAUTHORIZED)
    let checkSQLStatement = `SELECT refreshtoken FROM allUsers WHERE refreshtoken=\"${refreshToken}\"`;

    connection.query(checkSQLStatement, async (err, result) => {
        if (err) throw err;
        console.log(result);
        if (result.length == 0) {
            return res.sendStatus(403);
        }

        jwt.verify(refreshToken.toString(), process.env.REFRESH_TOKEN_SECRET, (err, user) => {
            if (err) return res.sendStatus(403)
            const accessToken = generateAccessToken({ login: user.login })
            res.status(constants.HTTP_STATUS_OK).json({ accessToken: accessToken })
        })
    })
})

app.post('/logout', (req, res) => {
    const refreshToken = req.body.token

    if (refreshToken == null) {
        return res.sendStatus(constants.HTTP_STATUS_UNAUTHORIZED)
    }
    jwt.verify(refreshToken.toString(), process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)
        // update database entry with such login
        if (user) {
            let updateSQLStatement = `UPDATE allUsers SET refreshtoken=\"null\" WHERE login=\"${user.login}\"`;

            connection.query(updateSQLStatement, async (err, result) => {
                if (err) throw err;
                console.log(result);
                return res.status(constants.HTTP_STATUS_OK).send({ message: constants.LOGGED_OUT });
            })
        } else {
            return res.status(constants.HTTP_STATUS_UNAUTHORIZED).send({ message: constants.BAD_USER });
        }
    })
})


app.get('/quotes', (req, res) => {

    const accessToken = req.body.token

    if (accessToken == null) {
        return res.sendStatus(constants.HTTP_STATUS_UNAUTHORIZED)
    }

    // verify the accessToken

    // check whether the database contains an entry with refreshtoken not equal to null

    jwt.verify(accessToken.toString(), process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)

        if (user) {
            var sql = "SELECT * FROM quote";
            connection.query(sql, (err, result) => {
                if (err) throw err;
                console.log(result);
                return res.status(constants.HTTP_STATUS_OK).send(result);
            });
        } else {
            return res.status(constants.HTTP_STATUS_UNAUTHORIZED).send({ message: constants.BAD_USER });
        }
    })
})

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' })
}


app.listen(3000) 