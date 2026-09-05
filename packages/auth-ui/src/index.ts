/**
 * The auth surfaces both hosts render (ADR 0008 D3). `@cipherbox/login` owns
 * the sequencing; this package owns what the member sees and types, so a
 * surface has one implementation whichever host mounts it. Everything here
 * takes its host in through props: no store, no router, no engine handle.
 *
 * Styling is the host's. These components carry class names and nothing else,
 * because the frame around them — the web app's terminal theme, the shell
 * window's own palette — belongs to the host, not to the surface.
 */

export { EmailLoginForm, type EmailLoginFormProps } from './EmailLoginForm';
export { LoginError } from './LoginError';
export { RecoveryPhraseForm, type RecoveryPhraseFormProps } from './RecoveryPhraseForm';
