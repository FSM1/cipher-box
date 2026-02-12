/**
 * Utility module for handling optional ox imports
 * This allows the library to work without ox being installed
 */
export declare function getOxModule(): Promise<any>;
export declare function hasOxModule(): boolean;
export declare function getOxExports(): Promise<{
    Base64: any;
    Hex: any;
    PublicKey: any;
    Signature: any;
    WebAuthnP256: any;
}>;
//# sourceMappingURL=ox.d.ts.map