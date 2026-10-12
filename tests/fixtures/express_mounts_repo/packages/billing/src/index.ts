import { Router } from 'express';

export const billingRouter = Router();

billingRouter.get('/invoices/:id', (_req, res) => res.json({}));
