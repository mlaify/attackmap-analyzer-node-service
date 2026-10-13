import { Router } from 'express';

const router = Router();

router.get('/daily', (_req, res) => res.json([]));

export default router;
