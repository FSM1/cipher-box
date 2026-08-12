import { ArgumentMetadata, BadRequestException, ValidationPipe } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import { EmailCodeRequestDto, EmailCodeVerifyRequestDto } from './identity.dto';

/**
 * Driven through the pipe rather than the class: the trim runs inside
 * `plainToInstance`, so a test constructing a DTO by hand never sees it — and
 * neither does one calling `EmailOtpService` directly.
 */
const pipe = new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true });

const body = (metatype: ArgumentMetadata['metatype']): ArgumentMetadata => ({
  type: 'body',
  metatype,
});

describe('EmailCodeRequestDto', () => {
  it('trims an address before validating it, so a typed space is not a 400', async () => {
    await expect(
      pipe.transform({ email: '  MEMBER@Example.COM  ' }, body(EmailCodeRequestDto))
    ).resolves.toEqual({ email: 'MEMBER@Example.COM' });
  });

  it('still refuses an address that is malformed once trimmed', async () => {
    await expect(
      pipe.transform({ email: '  not-an-address  ' }, body(EmailCodeRequestDto))
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('refuses a non-string payload rather than throwing inside the transform', async () => {
    for (const email of [42, null, undefined, { toString: () => 'a@b.com' }, ['a@b.com']]) {
      await expect(pipe.transform({ email }, body(EmailCodeRequestDto))).rejects.toBeInstanceOf(
        BadRequestException
      );
    }
  });

  // The pipe is configured to refuse, not silently strip: a caller sending a
  // field this DTO never declared is told so rather than having it swallowed.
  it('refuses a payload carrying an undeclared property', async () => {
    await expect(
      pipe.transform({ email: 'member@example.com', role: 'admin' }, body(EmailCodeRequestDto))
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(
      pipe.transform(
        { email: 'member@example.com', code: '123456', attempts: 0 },
        body(EmailCodeVerifyRequestDto)
      )
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('applies the same trim on the verify request', async () => {
    await expect(
      pipe.transform(
        { email: '  member@example.com  ', code: '123456' },
        body(EmailCodeVerifyRequestDto)
      )
    ).resolves.toEqual({ email: 'member@example.com', code: '123456' });
  });
});
