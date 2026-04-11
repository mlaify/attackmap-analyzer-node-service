import express from "express";
import axios from "axios";
import { Pool } from "pg";
import Redis from "ioredis";
import jwt from "jsonwebtoken";

const app = express();
const pool = new Pool({ connectionString: process.env.PG_URL });
const cache = new Redis(process.env.REDIS_URL || "redis://localhost:6379");

app.get("/xrpc/ping", async (req, res) => {
  const auth = req.headers["authorization"];
  if (!auth || !String(auth).startsWith("Bearer ")) {
    return res.status(401).json({ error: "missing auth" });
  }

  await axios.post("https://worker.internal.local/rebuild");
  await axios.get(process.env.FEEDGEN_URL as string);

  const token = jwt.sign({ role: "system" }, process.env.JWT_SIGNING_KEY as string);
  await cache.set("last-token", token);
  await pool.query("select 1");
  return res.json({ ok: true });
});

app.listen(3000);
