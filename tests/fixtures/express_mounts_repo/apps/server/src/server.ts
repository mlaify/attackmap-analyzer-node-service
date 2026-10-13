import express from 'express';
import { ordersRouter } from './routes/v2';
import reports from '@/routes/reports';
import { billingRouter } from '@acme/billing';
import { authenticate } from './middleware/session';

const server = express();

server.use('/v2', authenticate, ordersRouter);
server.use('/reports', reports);
server.use('/billing', authenticate, billingRouter);

export default server;
