import { Kafka } from "kafkajs";

const kafka = new Kafka({ brokers: [process.env.KAFKA_BROKERS as string] });
const consumer = kafka.consumer({ groupId: "orders-worker" });

async function run() {
  await consumer.subscribe({ topic: "orders-created", fromBeginning: false });
  await consumer.subscribe({ topics: ["payments-events"] });
}
run();
