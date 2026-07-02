import { PrismaClient } from "@prisma/client";

const db = new PrismaClient();

export async function GET() {
  return new Response(JSON.stringify(await db.order.findMany()));
}

export async function DELETE() {
  return new Response(null, { status: 204 });
}
