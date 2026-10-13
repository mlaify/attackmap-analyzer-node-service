import { Controller, Delete, Get, Post, UseGuards } from '@nestjs/common';

@Controller({ path: 'accounts', version: '1' })
@UseGuards(AuthGuard)
export class AccountsController {
  @Get()
  list() {}

  // Opts out of the controller's guard.
  @Public()
  @Post('signup')
  signup() {}

  // A role guard counts next to its metadata...
  @Roles('admin')
  @UseGuards(RolesGuard)
  @Delete(':id')
  remove() {}
}

@Controller('lookups')
export class LookupsController {
  // ...and not without it: RolesGuard lets requests without @Roles through.
  @UseGuards(RolesGuard)
  @Get()
  lookup() {}

  // An optional guard admits anonymous callers.
  @UseGuards(OptionalJwtAuthGuard)
  @Post()
  create() {}
}
