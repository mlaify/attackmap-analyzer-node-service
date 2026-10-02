import { Controller, Delete, Post, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Controller('billing')
export class BillingController {
  // Passport's AuthGuard doesn't read @Public() metadata.
  @Public()
  @UseGuards(AuthGuard('jwt'))
  @Delete('cards')
  removeCard() {}

  @Post('quote')
  quote() {}
}
