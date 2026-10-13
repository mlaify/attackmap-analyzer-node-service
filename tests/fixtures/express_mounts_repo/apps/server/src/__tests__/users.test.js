// Test code mounts the router elsewhere; that must not add a path.
const express = require('express');
const users = require('../routes/users');

const app = express();
app.use('/test-users', users);
