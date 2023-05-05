const express = require("express")
const app = express()
const bcrypt = require("bcrypt")

app.use(express.json())

const users = []

app.post('/register',async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10)
        const user = {name: req.body.name, password: hashedPassword}
        if (users.find(user => user.name === req.body.name)) {
            res.status(400).json( {message: "Already exists"} ).send()
        } else {
            users.push(user)
            res.status(201).json( {name: user.name, hashedPassword} ).send()
        }
    } catch {
        res.status(500).send()
    }

})

app.post('/login', async (req, res) => {
    const user = users.find(user => user.name === req.body.name)
    if(user ==null){
        return res.status(400).send('Cannot find user')
    }
    try {
        if(await bcrypt.compare(req.body.password, user.password)){
            res.status(200).send('success')
        } else {
            res.status(401).send('Not allowed')
        }


    }catch {
        res.status(500).send()

    }
})


app.listen(3000)




app.post('/register', async (req, res) => {

    try {
        // first, I check if the user with such name already exists.
        if (users.find(user => user.name === req.body.name)) {
            res.status(400).json("You cannot register a user with a name that already exists").send()
        } else {
            // equivalent to creating a database entry
            const hashedPassword = await bcrypt.hash(req.body.password, 10)
            const requestName = req.body.name
            users.push({ name: requestName, hashedPassword: hashedPassword })
            res.status(201).json({ message: `Hello, ${requestName}, you are successfully registered!`, hashedPassword: hashedPassword }).send()
        }
    } catch {
        res.status(500).send()
    }
})