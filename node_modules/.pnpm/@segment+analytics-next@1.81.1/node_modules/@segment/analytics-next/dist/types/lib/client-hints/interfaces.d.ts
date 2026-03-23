export interface NavigatorUABrandVersion {
    readonly brand: string;
    readonly version: string;
}
export interface UADataValues {
    readonly brands?: NavigatorUABrandVersion[];
    readonly mobile?: boolean;
    readonly platform?: string;
    readonly architecture?: string;
    readonly bitness?: string;
    readonly model?: string;
    readonly platformVersion?: string;
    /** @deprecated in favour of fullVersionList */
    readonly uaFullVersion?: string;
    readonly fullVersionList?: NavigatorUABrandVersion[];
    readonly wow64?: boolean;
}
export interface UALowEntropyJSON {
    readonly brands: NavigatorUABrandVersion[];
    readonly mobile: boolean;
    readonly platform: string;
}
export interface NavigatorUAData extends UALowEntropyJSON {
    getHighEntropyValues(hints: HighEntropyHint[]): Promise<UADataValues>;
    toJSON(): UALowEntropyJSON;
}
export type HighEntropyHint = 'architecture' | 'bitness' | 'model' | 'platformVersion' | 'uaFullVersion' | 'fullVersionList' | 'wow64';
//# sourceMappingURL=interfaces.d.ts.map