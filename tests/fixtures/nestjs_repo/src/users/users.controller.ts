import { Controller, Get, Post, Delete, UseGuards, All } from "@nestjs/common";
import axios from "axios";
import { PrismaClient } from "@prisma/client";

const db = new PrismaClient();

@Controller("users")
@UseGuards()
export class UsersController {
  @Get()
  async list() {
    return db.user.findMany();
  }

  @Get(":id")
  async findOne() {
    return { ok: true };
  }

  @Post()
  async create() {
    await axios.post("https://audit.internal/create", {});
    return { ok: true };
  }

  @Delete(":id")
  async remove() {
    const key = process.env.ADMIN_API_KEY;
    return { deleted: true, key: !!key };
  }

  @All("proxy")
  async proxy() {
    return { proxied: true };
  }
}
