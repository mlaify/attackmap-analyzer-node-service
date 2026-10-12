const express = require('express');

const router = express.Router();

router.get('/:id', (req, res) => res.json({ id: req.params.id }));
router.post('/', (req, res) => res.status(201).end());

module.exports = router;
