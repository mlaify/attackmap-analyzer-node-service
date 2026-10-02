const express = require('express');
const { expressjwt } = require('express-jwt');
const usersRouter = require('./routes/users');

const app = express();
app.use(express.json());

// Registered before the guard: nothing says either way.
app.post('/contact', submitContact);

app.use(
  expressjwt({ secret: process.env.JWT_SECRET, algorithms: ['HS256'] }).unless({ path: ['/login', '/signup'] })
);

// Explicitly excluded from the JWT guard by `.unless`.
app.post('/login', login);
app.post('/signup', signup);

app.put('/settings', updateSettings);
app.use('/api/users', usersRouter);

module.exports = app;
