"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthController = void 0;
const common_1 = require("@nestjs/common");
const swagger_1 = require("@nestjs/swagger");
const auth_service_1 = require("./auth.service");
const login_dto_1 = require("./dto/login.dto");
const token_dto_1 = require("./dto/token.dto");
const link_method_dto_1 = require("./dto/link-method.dto");
const jwt_auth_guard_1 = require("./guards/jwt-auth.guard");
// Cookie configuration
const REFRESH_TOKEN_COOKIE_OPTIONS = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    path: '/auth', // Only sent to auth endpoints
};
let AuthController = class AuthController {
    authService;
    constructor(authService) {
        this.authService = authService;
    }
    async login(loginDto, req, res) {
        const result = await this.authService.login(loginDto);
        const isDesktop = req.headers['x-client-type'] === 'desktop';
        if (isDesktop) {
            // Desktop clients: return refreshToken in response body (no cookie)
            return {
                accessToken: result.accessToken,
                refreshToken: result.refreshToken,
                isNewUser: result.isNewUser,
            };
        }
        // Web clients: set refresh token in HTTP-only cookie
        res.cookie('refresh_token', result.refreshToken, REFRESH_TOKEN_COOKIE_OPTIONS);
        return {
            accessToken: result.accessToken,
            isNewUser: result.isNewUser,
        };
    }
    async refresh(req, body, res) {
        const isDesktop = req.headers['x-client-type'] === 'desktop';
        let refreshToken;
        if (isDesktop) {
            // Desktop clients: read refresh token from request body
            refreshToken = body?.refreshToken;
        }
        else {
            // Web clients: read refresh token from cookie
            refreshToken = req.cookies?.['refresh_token'];
        }
        if (!refreshToken) {
            throw new common_1.UnauthorizedException('No refresh token');
        }
        const result = await this.authService.refreshByToken(refreshToken);
        if (isDesktop) {
            // Desktop clients: return new refreshToken in response body (no cookie)
            return {
                accessToken: result.accessToken,
                refreshToken: result.refreshToken,
            };
        }
        // Web clients: set new refresh token in HTTP-only cookie (rotation)
        res.cookie('refresh_token', result.refreshToken, REFRESH_TOKEN_COOKIE_OPTIONS);
        return {
            accessToken: result.accessToken,
        };
    }
    async logout(req, res) {
        const isDesktop = req.headers['x-client-type'] === 'desktop';
        if (!isDesktop) {
            // Web clients: clear the refresh token cookie
            res.clearCookie('refresh_token', { path: '/auth' });
        }
        return this.authService.logout(req.user.id);
    }
    async getMethods(req) {
        return this.authService.getLinkedMethods(req.user.id);
    }
    async linkMethod(req, linkDto) {
        return this.authService.linkMethod(req.user.id, linkDto);
    }
    async unlinkMethod(req, unlinkDto) {
        await this.authService.unlinkMethod(req.user.id, unlinkDto.methodId);
        return { success: true };
    }
};
exports.AuthController = AuthController;
__decorate([
    (0, common_1.Post)('login'),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    (0, swagger_1.ApiOperation)({ summary: 'Authenticate user with Web3Auth ID token' }),
    (0, swagger_1.ApiResponse)({
        status: 200,
        description: 'Successfully authenticated',
        type: login_dto_1.LoginResponseDto,
    }),
    (0, swagger_1.ApiResponse)({ status: 401, description: 'Invalid Web3Auth token' }),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Req)()),
    __param(2, (0, common_1.Res)({ passthrough: true })),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [login_dto_1.LoginDto, Object, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "login", null);
__decorate([
    (0, common_1.Post)('refresh'),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    (0, swagger_1.ApiOperation)({ summary: 'Refresh access token using HTTP-only refresh token cookie' }),
    (0, swagger_1.ApiResponse)({
        status: 200,
        description: 'Tokens refreshed successfully',
        type: token_dto_1.TokenResponseDto,
    }),
    (0, swagger_1.ApiResponse)({ status: 401, description: 'Invalid or expired refresh token' }),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Res)({ passthrough: true })),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, token_dto_1.DesktopRefreshDto, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "refresh", null);
__decorate([
    (0, common_1.Post)('logout'),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiOperation)({ summary: 'Logout user and invalidate all refresh tokens' }),
    (0, swagger_1.ApiResponse)({
        status: 200,
        description: 'Successfully logged out',
        type: token_dto_1.LogoutResponseDto,
    }),
    (0, swagger_1.ApiResponse)({ status: 401, description: 'Unauthorized' }),
    __param(0, (0, common_1.Request)()),
    __param(1, (0, common_1.Res)({ passthrough: true })),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "logout", null);
__decorate([
    (0, common_1.Get)('methods'),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiOperation)({ summary: 'Get all linked auth methods for the current user' }),
    (0, swagger_1.ApiResponse)({
        status: 200,
        description: 'List of linked auth methods',
        type: [link_method_dto_1.AuthMethodResponseDto],
    }),
    (0, swagger_1.ApiResponse)({ status: 401, description: 'Unauthorized' }),
    __param(0, (0, common_1.Request)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "getMethods", null);
__decorate([
    (0, common_1.Post)('link'),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiOperation)({ summary: 'Link a new auth method to the current user account' }),
    (0, swagger_1.ApiResponse)({
        status: 200,
        description: 'Auth method linked successfully, returns updated list of methods',
        type: [link_method_dto_1.AuthMethodResponseDto],
    }),
    (0, swagger_1.ApiResponse)({ status: 400, description: 'Auth method already linked or publicKey mismatch' }),
    (0, swagger_1.ApiResponse)({ status: 401, description: 'Unauthorized' }),
    __param(0, (0, common_1.Request)()),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, link_method_dto_1.LinkMethodDto]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "linkMethod", null);
__decorate([
    (0, common_1.Post)('unlink'),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard),
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiOperation)({ summary: 'Unlink an auth method from the current user account' }),
    (0, swagger_1.ApiResponse)({
        status: 200,
        description: 'Auth method unlinked successfully',
        type: link_method_dto_1.UnlinkMethodResponseDto,
    }),
    (0, swagger_1.ApiResponse)({ status: 400, description: 'Cannot unlink last auth method or method not found' }),
    (0, swagger_1.ApiResponse)({ status: 401, description: 'Unauthorized' }),
    __param(0, (0, common_1.Request)()),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, link_method_dto_1.UnlinkMethodDto]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "unlinkMethod", null);
exports.AuthController = AuthController = __decorate([
    (0, swagger_1.ApiTags)('Auth'),
    (0, common_1.Controller)('auth'),
    __metadata("design:paramtypes", [auth_service_1.AuthService])
], AuthController);
//# sourceMappingURL=auth.controller.js.map