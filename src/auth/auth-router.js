const express = require('express')
const authRouter = express.Router()
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('../config');
const jsonBodyParser = express.json()

function createJwt(subject, payload) {
  return jwt.sign(payload, config.JWT_SECRET, {
         subject,
         algorithm: 'HS256',
       })
}

authRouter
  .post('/login', jsonBodyParser, (req, res, next) => {
    const { user_name, password } = req.body;
    const loginUser = { user_name, password };
    
    for(const [key, value] of Object.entries(loginUser))
      if(value == null)
        return res.status(400).json({
          error: `Missing ${key} in request body`
    })
  
    req.app.get('db')('thingful_users')
        .where({user_name: loginUser.user_name})
        .first()
        .then(dbUser => {
          if(!dbUser) 
            return res.status(400).json({
              error: 'Incorrect user_name or password'
            })
            return bcrypt.compare(loginUser.password, dbUser.password)
            .then(compareMatch => {
              if(!compareMatch)
                return res.status(400).json({
                  error: 'Incorrect user_name or password'
                })
                const sub = dbUser.user_name
                const payload = { user_id: dbUser.id }
                res.send({
                  authToken: createJwt(sub, payload),
                })
            })
        })
        .catch(next) 
  })

module.exports = authRouter