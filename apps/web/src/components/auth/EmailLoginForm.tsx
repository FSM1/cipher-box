import { useCallback, useEffect, useRef, useState } from 'react';
import { authApi } from '../../lib/api/auth';

interface EmailLoginFormProps {
  onLogin: (email: string, otp: string) => Promise<void>;
  disabled?: boolean;
}

type FormStep = 'email' | 'otp';

const OTP_LENGTH = 6;
const RESEND_COOLDOWN_SECONDS = 60;

/**
 * Email + OTP two-step login form.
 * Step 1: Email input + [SEND OTP] button
 * Step 2: OTP input (6 digits) + [VERIFY] button + [RESEND] link
 *
 * Calls the CipherBox identity provider to send OTP,
 * then calls onLogin(email, otp) for Core Kit auth.
 */
export function EmailLoginForm({ onLogin, disabled }: EmailLoginFormProps) {
  const [step, setStep] = useState<FormStep>('email');
  const [email, setEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resendCooldown, setResendCooldown] = useState(0);

  const otpInputRef = useRef<HTMLInputElement>(null);
  const cooldownTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Auto-focus OTP input when transitioning to step 2
  useEffect(() => {
    if (step !== 'otp') return;

    // Small delay for DOM update
    const timer = setTimeout(() => {
      otpInputRef.current?.focus();
    }, 50);
    return () => clearTimeout(timer);
  }, [step]);

  // Cleanup cooldown timer on unmount
  useEffect(() => {
    return () => {
      if (cooldownTimerRef.current) {
        clearInterval(cooldownTimerRef.current);
      }
    };
  }, []);

  const startResendCooldown = useCallback(() => {
    setResendCooldown(RESEND_COOLDOWN_SECONDS);

    if (cooldownTimerRef.current) {
      clearInterval(cooldownTimerRef.current);
    }

    cooldownTimerRef.current = setInterval(() => {
      setResendCooldown((prev) => {
        if (prev <= 1) {
          if (cooldownTimerRef.current) {
            clearInterval(cooldownTimerRef.current);
            cooldownTimerRef.current = null;
          }
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
  }, []);

  const handleSendOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || disabled || loading) return;

    setLoading(true);
    setError(null);

    try {
      await authApi.identityEmailSendOtp(email.trim().toLowerCase());
      setStep('otp');
      startResendCooldown();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to send verification code';
      // Check for rate limit error
      if ((err as { response?: { status?: number } })?.response?.status === 429) {
        setError('Too many attempts. Please wait before trying again.');
      } else {
        setError(message);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (otp.length !== OTP_LENGTH || disabled || loading) return;

    setLoading(true);
    setError(null);

    try {
      await onLogin(email.trim().toLowerCase(), otp);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Verification failed';
      // Check for invalid OTP response
      if ((err as { response?: { status?: number } })?.response?.status === 401) {
        setError('Invalid code. Please check and try again.');
      } else {
        setError(message);
      }
      // Clear OTP on error so user can re-enter
      setOtp('');
      otpInputRef.current?.focus();
    } finally {
      setLoading(false);
    }
  };

  const handleResend = async () => {
    if (resendCooldown > 0 || loading) return;

    setLoading(true);
    setError(null);

    try {
      await authApi.identityEmailSendOtp(email.trim().toLowerCase());
      startResendCooldown();
      setOtp('');
      otpInputRef.current?.focus();
    } catch {
      setError('Failed to resend code. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleBackToEmail = () => {
    setStep('email');
    setOtp('');
    setError(null);
  };

  const handleOtpChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value.replace(/\D/g, '').slice(0, OTP_LENGTH);
    setOtp(value);
  };

  const loadingText = step === 'email' ? 'sending code...' : 'verifying code...';

  return (
    <div className="email-login-form">
      {step === 'email' ? (
        <form onSubmit={handleSendOtp} className="email-login-step">
          <label htmlFor="login-email" className="sr-only">
            Email address
          </label>
          <input
            id="login-email"
            type="email"
            className="email-login-input"
            placeholder="enter email address"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            disabled={disabled || loading}
            required
            autoComplete="email"
            aria-describedby={error ? 'email-login-error' : undefined}
          />
          <button
            type="submit"
            className={['email-login-submit', loading ? 'email-login-submit--loading' : '']
              .filter(Boolean)
              .join(' ')}
            disabled={disabled || loading || !email.trim()}
            aria-busy={loading}
          >
            {loading ? loadingText : '[SEND OTP]'}
          </button>
        </form>
      ) : (
        <form onSubmit={handleVerifyOtp} className="email-login-step">
          <div className="otp-header">
            <button
              type="button"
              className="otp-back-btn"
              onClick={handleBackToEmail}
              disabled={loading}
              aria-label="Go back to email input"
            >
              {'<-'}
            </button>
            <span className="otp-email-display">{email}</span>
          </div>
          <label htmlFor="login-otp" className="sr-only">
            Verification code
          </label>
          <input
            id="login-otp"
            ref={otpInputRef}
            type="text"
            inputMode="numeric"
            pattern="[0-9]*"
            className="otp-input"
            placeholder="enter 6-digit code"
            value={otp}
            onChange={handleOtpChange}
            disabled={disabled || loading}
            required
            maxLength={OTP_LENGTH}
            autoComplete="one-time-code"
            aria-describedby={error ? 'email-login-error' : undefined}
          />
          <button
            type="submit"
            className={['email-login-submit', loading ? 'email-login-submit--loading' : '']
              .filter(Boolean)
              .join(' ')}
            disabled={disabled || loading || otp.length !== OTP_LENGTH}
            aria-busy={loading}
          >
            {loading ? loadingText : '[VERIFY]'}
          </button>
          <button
            type="button"
            className="otp-resend-btn"
            onClick={handleResend}
            disabled={resendCooldown > 0 || loading}
            aria-label={
              resendCooldown > 0
                ? `Resend code available in ${resendCooldown} seconds`
                : 'Resend verification code'
            }
          >
            {resendCooldown > 0 ? `[resend in ${resendCooldown}s]` : '[resend code]'}
          </button>
        </form>
      )}

      {error && (
        <div id="email-login-error" className="login-error" role="alert" aria-live="polite">
          {error}
        </div>
      )}
    </div>
  );
}
