// Never mounted: keeps its file-local path, auth unknown.
const router = require('express').Router();

router.patch('/orphan/:id', (req, res) => res.sendStatus(204));

module.exports = router;
