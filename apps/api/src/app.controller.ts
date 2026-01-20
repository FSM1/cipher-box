import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AppService } from './app.service';

@ApiTags('Root')
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  @ApiOperation({ summary: 'Get API info' })
  @ApiResponse({ status: 200, description: 'Returns API version info' })
  getRoot(): string {
    return this.appService.getInfo();
  }
}
