/// <reference types="vite/client" />

/** The app's build-time environment contract; every key is optional and defaulted. */
interface ImportMetaEnv {
  readonly VITE_API_URL?: string;
  /** Comma-separated `/routing/v1` origins: someguy plus a public endpoint. */
  readonly VITE_ROUTING_ENDPOINTS?: string;
}
