const { Router } = require('express');

const router = Router();

router.delete('/users/:id', (req, res) => res.sendStatus(204));

module.exports = router;
