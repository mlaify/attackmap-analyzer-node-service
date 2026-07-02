import { Worker, Queue } from "bullmq";

new Queue("email-outbox");

new Worker("image-processing", async (job) => {
  return job.data;
});
