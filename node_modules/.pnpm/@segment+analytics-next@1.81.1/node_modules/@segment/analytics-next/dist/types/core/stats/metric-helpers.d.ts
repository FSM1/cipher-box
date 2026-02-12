import { Context } from '../context';
export interface RecordIntegrationMetricProps {
    integrationName: string;
    methodName: string;
    didError?: boolean;
    type: 'classic' | 'action';
}
export declare function recordIntegrationMetric(ctx: Context, { methodName, integrationName, type, didError, }: RecordIntegrationMetricProps): void;
//# sourceMappingURL=metric-helpers.d.ts.map