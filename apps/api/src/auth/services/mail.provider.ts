import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

const SENDGRID_ENDPOINT = 'https://api.sendgrid.com/v3/mail/send';
const SEND_TIMEOUT_MS = 10_000;

/**
 * Email delivery, as a seam rather than a vendor. CipherBox owns passwordless
 * email again (ADR 0008 D1), so the provider is configuration — and its
 * absence is a boot failure, not a first-send surprise.
 */
@Injectable()
export abstract class MailProvider {
  abstract sendVerificationCode(to: string, code: string): Promise<void>;
}

/** SendGrid's v3 REST API over plain `fetch`; the SDK adds nothing here. */
export class SendGridMailProvider extends MailProvider {
  constructor(
    private readonly apiKey: string,
    private readonly from: string
  ) {
    super();
  }

  async sendVerificationCode(to: string, code: string): Promise<void> {
    const response = await fetch(SENDGRID_ENDPOINT, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${this.apiKey}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        personalizations: [{ to: [{ email: to }] }],
        from: { email: this.from },
        subject: 'Your CipherBox verification code',
        content: [
          {
            type: 'text/plain',
            value:
              `Your CipherBox verification code is: ${code}\n\n` +
              'It expires in a few minutes. If you did not request it, ignore this email.',
          },
        ],
      }),
      signal: AbortSignal.timeout(SEND_TIMEOUT_MS),
    });
    if (!response.ok) {
      // Status only: the body echoes the request, and the request carries the code.
      throw new Error(`SendGrid rejected the message with status ${response.status}`);
    }
  }
}

/** Undeployed profiles only — the code goes to the log because nothing else can carry it. */
export class LoggingMailProvider extends MailProvider {
  private readonly logger = new Logger(LoggingMailProvider.name);

  sendVerificationCode(to: string, code: string): Promise<void> {
    this.logger.warn(`Verification code for ${to}: ${code}`);
    return Promise.resolve();
  }
}

/**
 * Selects the configured provider, refusing to boot a deployed profile that
 * has none. Allowlisted the same way `buildJwtOptions` allowlists its fallback:
 * only `development` and `test` may run without real delivery.
 */
export function buildMailProvider(configService: ConfigService): MailProvider {
  const nodeEnv = configService.get<string>('NODE_ENV') ?? 'development';
  const deployed = nodeEnv !== 'development' && nodeEnv !== 'test';
  const provider = configService.get<string>('MAIL_PROVIDER')?.trim();

  if (!provider) {
    if (deployed) {
      throw new Error(
        `MAIL_PROVIDER is required when NODE_ENV is '${nodeEnv}' (set it to 'sendgrid')`
      );
    }
    return new LoggingMailProvider();
  }

  if (provider === 'log') {
    if (deployed) {
      throw new Error(
        `MAIL_PROVIDER='log' delivers no mail and is refused when NODE_ENV is '${nodeEnv}'`
      );
    }
    return new LoggingMailProvider();
  }

  if (provider === 'sendgrid') {
    const apiKey = configService.get<string>('SENDGRID_API_KEY')?.trim();
    const from = configService.get<string>('MAIL_FROM_ADDRESS')?.trim();
    if (!apiKey || !from) {
      throw new Error(
        "MAIL_PROVIDER='sendgrid' requires SENDGRID_API_KEY and MAIL_FROM_ADDRESS to be set"
      );
    }
    return new SendGridMailProvider(apiKey, from);
  }

  throw new Error(`Unknown MAIL_PROVIDER '${provider}' — expected 'sendgrid' or 'log'`);
}
