import type { Provider } from '@nestjs/common';
import { AuthMetricsInterceptor } from '../auth/auth-metrics.interceptor';
import { AcceleratorToken } from '../auth/entities/accelerator-token.entity';
import { AuthMethod } from '../auth/entities/auth-method.entity';
import { IdentitySubject } from '../auth/entities/identity-subject.entity';
import { RefreshToken } from '../auth/entities/refresh-token.entity';
import { User } from '../auth/entities/user.entity';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { AcceleratorTokenService } from '../auth/services/accelerator-token.service';
import { AuthService } from '../auth/services/auth.service';
import { ChallengeService } from '../auth/services/challenge.service';
import { EmailOtpService } from '../auth/services/email-otp.service';
import { IdentityService } from '../auth/services/identity.service';
import { IdentityTokenService } from '../auth/services/identity-token.service';
import { MailProvider } from '../auth/services/mail.provider';
import { SiweService } from '../auth/services/siwe.service';
import { TestAuthService } from '../auth/services/test-auth.service';
import { TokenService } from '../auth/services/token.service';

/** The tables `AuthService` reads and writes. */
export const AUTH_SERVICE_ENTITIES = [
  User,
  AuthMethod,
  RefreshToken,
  AcceleratorToken,
  IdentitySubject,
];

const refusingMail = {
  sendVerificationCode: () => Promise.reject(new Error('no email in this suite')),
};

/**
 * `AuthService`, what it injects, and what `AuthController` adds around it. The
 * suite still provides `Clock`, `Entropy` and `ConfigService`.
 */
export function authServiceProviders(
  mail: Pick<MailProvider, 'sendVerificationCode'> = refusingMail
): Provider[] {
  return [
    AuthMetricsInterceptor,
    AuthService,
    TestAuthService,
    TokenService,
    AcceleratorTokenService,
    ChallengeService,
    IdentityService,
    IdentityTokenService,
    SiweService,
    JwtAuthGuard,
    EmailOtpService,
    { provide: MailProvider, useValue: mail },
  ];
}
