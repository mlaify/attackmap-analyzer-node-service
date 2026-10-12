import { Router } from 'express';

export const ordersRouter = Router();

ordersRouter.post('/orders', (_req, res) => res.sendStatus(201));
