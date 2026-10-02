import { Controller, Post, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from './jwt-auth.guard';
import { Public } from './public.decorator';

@Controller('posts')
@UseGuards(JwtAuthGuard)
export class PostsController {
  @Post()
  create() {}

  // Opts out of the controller's guard (JwtAuthGuard honours @Public()).
  @Public()
  @Post('preview')
  preview() {}
}
