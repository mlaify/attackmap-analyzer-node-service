import express from "express";

const app = express();
const v1 = express.Router();
const orgs = express.Router();
const orgUsers = express.Router();

// Prefix mounts — nested three levels deep.
app.use("/api", v1);
v1.use("/v1", orgs);
orgs.use("/orgs/:orgId", orgUsers);

app.get("/health", (_req, res) => res.json({ ok: true }));

// Deeply-nested route under a prefix chain.
orgUsers.get("/members", (_req, res) => res.json([]));
orgUsers.post("/invite", (_req, res) => res.status(201).end());

// Chained .route().get().post() shape.
v1
  .route("/status")
  .get((_req, res) => res.json({ up: true }))
  .post((_req, res) => res.status(202).end());

app.listen(3001);
