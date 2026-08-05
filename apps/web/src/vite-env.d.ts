/// <reference types="vite/client" />

/** The app's build-time environment contract; every key is optional and defaulted. */
interface ImportMetaEnv {
  readonly VITE_API_URL?: string;
  /** Comma-separated `/routing/v1` origins: someguy plus a public endpoint. */
  readonly VITE_ROUTING_ENDPOINTS?: string;
  /** Base URL of the token-authed read accelerator; unset leaves reads dormant. */
  readonly VITE_READ_ACCELERATOR_URL?: string;
  /** Comma-separated public trustless-gateway origins, tried after the accelerator. */
  readonly VITE_PUBLIC_GATEWAYS?: string;
  /** `local` | `ci` | `staging` | `production` — picks the Web3Auth network. */
  readonly VITE_ENVIRONMENT?: string;
  /** `true` builds the e2e introspection hook in; any other value leaves it out. */
  readonly VITE_E2E_HOOK?: string;
  readonly VITE_WEB3AUTH_CLIENT_ID?: string;
  /** The Web3Auth verifier the Core Kit login flows authenticate against. */
  readonly VITE_WEB3AUTH_VERIFIER?: string;
}
