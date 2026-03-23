"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const core_1 = require("@nestjs/core");
const swagger_1 = require("@nestjs/swagger");
const common_1 = require("@nestjs/common");
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const app_module_1 = require("./app.module");
async function bootstrap() {
    const isDev = process.env.NODE_ENV === 'development' || !process.env.NODE_ENV;
    // In staging/production, omit debug and verbose log levels for concise output
    const app = await core_1.NestFactory.create(app_module_1.AppModule, {
        logger: isDev ? ['log', 'error', 'warn', 'debug', 'verbose'] : ['log', 'error', 'warn'],
    });
    const logger = new common_1.Logger('Bootstrap');
    // [SECURITY: CRITICAL-01] Enable global validation pipe
    // Without this, all DTO validation decorators (@IsString, @Matches, etc.) are ignored
    app.useGlobalPipes(new common_1.ValidationPipe({
        whitelist: true, // Strip properties not in DTO
        forbidNonWhitelisted: true, // Reject unexpected properties
        transform: true, // Auto-transform types
    }));
    app.use((0, cookie_parser_1.default)());
    // CORS_ALLOWED_ORIGINS supports wildcards (e.g. https://cipher-box-pr-*.onrender.com)
    // Falls back to WEB_APP_URL for backwards compatibility
    const rawOrigins = process.env.CORS_ALLOWED_ORIGINS || process.env.WEB_APP_URL;
    const originEntries = rawOrigins
        ? rawOrigins.split(',').map((s) => s.trim())
        : ['http://localhost:5173', 'http://localhost:4173'];
    const exactOrigins = originEntries.filter((o) => !o.includes('*'));
    const wildcardPatterns = originEntries
        .filter((o) => o.includes('*'))
        .map((o) => new RegExp(`^${o.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`));
    app.enableCors({
        origin: (origin, callback) => {
            if (!origin)
                return callback(null, true);
            if (exactOrigins.includes(origin))
                return callback(null, true);
            if (wildcardPatterns.some((re) => re.test(origin)))
                return callback(null, true);
            callback(new Error(`Origin ${origin} not allowed by CORS`));
        },
        credentials: true,
    });
    const config = new swagger_1.DocumentBuilder()
        .setTitle('CipherBox API')
        .setDescription('Zero-knowledge encrypted cloud storage API')
        .setVersion('0.1.0')
        .addBearerAuth()
        .build();
    const document = swagger_1.SwaggerModule.createDocument(app, config);
    swagger_1.SwaggerModule.setup('api-docs', app, document, {
        jsonDocumentUrl: 'api-docs/json',
    });
    const port = process.env.PORT || 3000;
    await app.listen(port);
    logger.log(`CipherBox API running on http://localhost:${port}`);
    logger.log(`Swagger UI: http://localhost:${port}/api-docs`);
}
bootstrap();
//# sourceMappingURL=main.js.map