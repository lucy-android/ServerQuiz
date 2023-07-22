require('dotenv').config()

const express = require("express")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const constants = require("./constants")
const mysql = require('mysql2')

const app = express()
app.use(express.json())


const connection = mysql.createConnection({
    host: process.env.HOST_NAME,
    user: process.env.USER_NAME,
    password: process.env.PASSWORD,
    database: process.env.DATABASE_NAME,
}).promise()


app.post(constants.REGISTER, async (req, res) => {

    const [rows] = await connection.query(constants.EXIST_LOGIN_SQL, [req.body.login])

    if (rows.length !== 0) return res
        .status(constants.HTTP_STATUS_BAD_REQUEST)
        .send(constants.USER_EXISTS)

    const hashedPassword = await bcrypt.hash(req.body.password, constants.SALT_ROUNDS)

    const user = {
        firstname: req.body.firstname,
        lastname: req.body.lastname,
        login: req.body.login,
        password: hashedPassword
    }

    const result = await connection.query(constants.INSERT_SQL,
        [user.firstname, user.lastname, user.login, user.password])

    if (result) return res
        .status(constants.HTTP_STATUS_CREATED)
        .json({ firstname: user.firstname, lastname: user.lastname, login: user.login })
        .send()

    return res.status(constants.INTERNAL_SERVER_ERROR)

})

app.post(constants.LOGIN, async (req, res) => {

    const [rows] = await connection.query(constants.EXIST_LOGIN_SQL, [req.body.login])

    if (rows.length == 0) return res
        .status(constants.HTTP_STATUS_UNAUTHORIZED)
        .send(constants.NOT_ALLOWED)

    const entry = rows[0]
    const login = entry.login
    const hashedPassword = entry.hashedPassword

    const comparisonResult = await bcrypt.compare(req.body.password, hashedPassword)

    if (comparisonResult) {
        const user = { login: login }
        const accessToken = generateAccessToken(user)

        const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)

        await connection.query(constants.UPDATE_REFRESH_SQL, [refreshToken, user.login])
        return res
            .status(constants.HTTP_STATUS_OK)
            .send({ accessToken: accessToken, refreshToken: refreshToken })
    } else {
        return res.status(constants.HTTP_STATUS_UNAUTHORIZED).send(constants.NOT_ALLOWED)
    }
})


app.post(constants.REFRESHTOKEN, async (req, res) => {
    const refreshToken = req.body.token
    if (refreshToken == null) return res.sendStatus(constants.HTTP_STATUS_UNAUTHORIZED)

    const [rows] = await connection.query(constants.SELECT_REFRESH_SQL, [refreshToken])

    if (rows.length == 0) return res.sendStatus(constants.FORBIDDEN)

    try {
        const user = jwt.verify(refreshToken.toString(), process.env.REFRESH_TOKEN_SECRET)
        const accessToken = generateAccessToken({ login: user.login })
        return res.status(constants.HTTP_STATUS_OK).json({ accessToken: accessToken })
    } catch (error) {
        return res.sendStatus(constants.FORBIDDEN)
    }
})

app.post(constants.LOGOUT, async (req, res) => {
    const refreshToken = req.body.token

    if (refreshToken == null) return res.sendStatus(constants.HTTP_STATUS_UNAUTHORIZED)

    try {
        const user = jwt.verify(refreshToken.toString(), process.env.REFRESH_TOKEN_SECRET)
        if (!user) return res.sendStatus(constants.FORBIDDEN)
        await connection.query(constants.LOGOUT_USER, [user.login])
        return res.status(constants.HTTP_STATUS_OK).send({ message: constants.LOGGED_OUT })
    } catch (error) {
        return res.sendStatus(constants.FORBIDDEN)
    }
})


app.get(constants.QUOTES, async (req, res) => {

    const accessToken = req.body.token

    if (accessToken == null) return res.sendStatus(constants.HTTP_STATUS_UNAUTHORIZED)

    try {
        const user = jwt.verify(accessToken.toString(), process.env.ACCESS_TOKEN_SECRET)
        if (!user) return res.sendStatus(constants.FORBIDDEN)
        const result = await connection.query(constants.GET_ALL_QUOTES)
        return res.status(constants.HTTP_STATUS_OK).send(result[0])
    } catch (error) {
        return res.sendStatus(constants.FORBIDDEN)
    }
})

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: constants.EXPIRES_IN })
}


app.listen(process.env.PORT_NUMBER) 