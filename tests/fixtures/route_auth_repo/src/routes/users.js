const express = require('express');

const router = express.Router();

router.delete('/:id', requireAdmin, deleteUser);
router.post('/', createUser);

module.exports = router;
