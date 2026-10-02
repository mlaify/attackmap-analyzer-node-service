import type { Router } from "express";
import jwt from "jsonwebtoken";

export function registerUserRoutes(users: Router, secret: string): void {
  users.get("/users", (_req, res) => res.json([]));
  users.delete("/users/:id", (req, res) => {
    jwt.verify(String(req.headers.authorization), secret);
    res.status(204).end();
  });
}
