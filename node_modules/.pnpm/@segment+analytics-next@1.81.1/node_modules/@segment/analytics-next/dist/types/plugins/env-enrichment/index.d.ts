import type { Context } from '../../core/context';
import type { Plugin } from '../../core/plugin';
import { Campaign, PluginType } from '@segment/analytics-core';
import { Analytics } from '../../core/analytics';
export declare function utm(query: string): Campaign;
export declare function ampId(): string | undefined;
declare class EnvironmentEnrichmentPlugin implements Plugin {
    private instance;
    private userAgentData;
    name: string;
    type: PluginType;
    version: string;
    isLoaded: () => boolean;
    load: (_ctx: Context, instance: Analytics) => Promise<void>;
    private enrich;
    track: (ctx: Context) => Context;
    identify: (ctx: Context) => Context;
    page: (ctx: Context) => Context;
    group: (ctx: Context) => Context;
    alias: (ctx: Context) => Context;
    screen: (ctx: Context) => Context;
}
export declare const envEnrichment: EnvironmentEnrichmentPlugin;
export {};
//# sourceMappingURL=index.d.ts.map