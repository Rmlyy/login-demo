const express = require('express')
const cookieParser = require('cookie-parser')
const bcrypt = require('bcrypt')
const crypto = require('crypto')
const fs = require('fs')
const app = express()
const config = require('./config.json')

app.set('view engine', 'ejs')
app.use(cookieParser())
app.use(express.urlencoded({ extended: false }))

if (!config.credentials.password.startsWith('$2b$10')) {
  bcrypt.hash(config.credentials.password, 10).then(function (hash) {
    config.credentials.password = hash
    fs.writeFileSync('./config.json', JSON.stringify(config, null, "\t"))
  })
}

function isLoggedIn(req) {
  if (!req.cookies.session) return false
  return true
}

app.get('/', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/login')
  res.render('index')
})

app.get('/login', (req, res) => {
  if (isLoggedIn(req)) return res.redirect('/')
  res.render('login', { msg: null })
})

app.get('/logout', (req, res) => {
  if (isLoggedIn(req)) {
    res.clearCookie('session')
    res.redirect('/login')
  }
})

app.post('/login', (req, res) => {
  const user = req.body.user
  const password = req.body.password

  if (user != config.credentials.user) return res.status(401).render('login', {
    msg: 'Invalid username or password.'
  })

  bcrypt.compare(password, config.credentials.password).then(function (result) {
    if (!result) return res.status(401).render('login', {
      msg: 'Invalid username or password.'
    })
    res.cookie('session', crypto.randomBytes(20).toString('hex'))
    res.redirect('/')
  })
})

app.listen(config.port, () => {
  console.log(`Listening on ${config.port}`)
})