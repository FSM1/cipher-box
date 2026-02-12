import { Controller, Get, Header } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { JwtIssuerService } from '../services/jwt-issuer.service';

@ApiTags('Identity')
@Controller('auth')
export class IdentityController {
  constructor(private jwtIssuerService: JwtIssuerService) {}

  @Get('.well-known/jwks.json')
  @Header('Cache-Control', 'public, max-age=3600')
  @ApiOperation({ summary: 'JWKS endpoint for CipherBox identity provider' })
  @ApiResponse({
    status: 200,
    description: 'JWKS containing RS256 public key for JWT verification',
  })
  getJwks(): { keys: object[] } {
    return this.jwtIssuerService.getJwksData();
  }
}
