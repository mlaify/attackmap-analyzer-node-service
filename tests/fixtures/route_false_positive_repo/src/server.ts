import express from "express";
import axios from "axios";
import got from "got";

const app = express();
const cache = new Map<string, string>();
const store = { post: (_k: string) => undefined };
const billing = axios.create({ baseURL: process.env.BILLING_URL });

app.get("/api/users/:id", async (req, res) => {
  // Request/collection getters are not routes.
  const header = req.get("Authorization");
  const session = cache.get("session");
  const searchParams = new URLSearchParams(req.url);
  const page = searchParams.get("page");
  // A non-router object with an HTTP-verb-named method.
  store.post("/x");

  // Outbound client calls are external calls, not inbound routes.
  const health = await axios.get("/internal/health");
  await got.post("https://audit.internal.example/events");
  await billing.put(`/invoices/${req.params.id}`);

  // Ordinary helpers named verify/sign are not crypto.
  const ok = verify(header);
  const label = sign(session);
  return res.json({ header, session, page, health, ok, label });
});

function verify(value: unknown): boolean {
  return Boolean(value);
}

function sign(value: unknown): string {
  return String(value);
}

app.listen(3000);
