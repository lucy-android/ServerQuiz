require('dotenv').config()

const express = require("express")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")

const app = express()
app.use(express.json())

const users = []
let refreshTokens = []

app.post('/register', async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10)
        const user = { name: req.body.name, password: hashedPassword }
        if (users.find(user => user.name === req.body.name)) {
            res.status(400).json({ message: "Already exists" }).send()
        } else {
            users.push(user)
            res.status(201).json({ name: user.name, hashedPassword }).send()
        }
    } catch {
        res.status(500).send()
    }

})

app.post('/login', async (req, res) => {
    const user = users.find(user => user.name === req.body.name)
    if (user == null) {
        return res.status(400).send('Cannot find user')
    }

    try {
        const accessToken = generateAccessToken(user)
        const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
        refreshTokens.push(refreshToken)
        if (await bcrypt.compare(req.body.password, user.password)) {
            res.status(200).send({ accessToken: accessToken, refreshToken: refreshToken })
        } else {
            res.status(401).send('Not allowed')
        }
    } catch {
        res.status(500).send()
    }
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

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' })
}


app.listen(3000) 