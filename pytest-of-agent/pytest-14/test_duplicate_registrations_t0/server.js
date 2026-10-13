const express = require('express');
const app = express();
app.get('/x', h);
app.get('/x', requireAuth, h);
app.post('/y', requireAuth, h);
app.post('/y', requireAuth, h2);
