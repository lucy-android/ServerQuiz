require('dotenv').config()

const express = require("express")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const constants = require("./constants")
const routes = require("./routes")


const app = express()

app.use(express.json())
app.use(routes)
app.listen(process.env.PORT_NUMBER) 