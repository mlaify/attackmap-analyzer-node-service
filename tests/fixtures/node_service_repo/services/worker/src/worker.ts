import express from "express";

const app = express();

app.post("/internal/rebuild", async (_req, res) => {
  return res.json({ queued: true });
});

app.listen(3030);
