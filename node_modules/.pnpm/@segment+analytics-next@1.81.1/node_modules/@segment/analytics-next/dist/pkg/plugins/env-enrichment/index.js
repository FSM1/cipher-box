import { __assign, __awaiter, __generator } from "tslib";
import jar from 'js-cookie';
import { version } from '../../generated/version';
import { getVersionType } from '../../lib/version-type';
import { tld } from '../../core/user/tld';
import { gracefulDecodeURIComponent } from '../../core/query-string/gracefulDecodeURIComponent';
import { CookieStorage, UniversalStorage } from '../../core/storage';
import { clientHints } from '../../lib/client-hints';
var cookieOptions;
function getCookieOptions() {
    if (cookieOptions) {
        return cookieOptions;
    }
    var domain = tld(window.location.href);
    cookieOptions = {
        expires: 31536000000,
        secure: false,
        path: '/',
    };
    if (domain) {
        cookieOptions.domain = domain;
    }
    return cookieOptions;
}
function ads(query) {
    var queryIds = {
        btid: 'dataxu',
        urid: 'millennial-media',
    };
    if (query.startsWith('?')) {
        query = query.substring(1);
    }
    query = query.replace(/\?/g, '&');
    var parts = query.split('&');
    for (var _i = 0, parts_1 = parts; _i < parts_1.length; _i++) {
        var part = parts_1[_i];
        var _a = part.split('='), k = _a[0], v = _a[1];
        if (queryIds[k]) {
            return {
                id: v,
                type: queryIds[k],
            };
        }
    }
}
export function utm(query) {
    if (query.startsWith('?')) {
        query = query.substring(1);
    }
    query = query.replace(/\?/g, '&');
    return query.split('&').reduce(function (acc, str) {
        var _a = str.split('='), k = _a[0], _b = _a[1], v = _b === void 0 ? '' : _b;
        if (k.includes('utm_') && k.length > 4) {
            var utmParam = k.slice(4);
            if (utmParam === 'campaign') {
                utmParam = 'name';
            }
            acc[utmParam] = gracefulDecodeURIComponent(v);
        }
        return acc;
    }, {});
}
export function ampId() {
    var ampId = jar.get('_ga');
    if (ampId && ampId.startsWith('amp')) {
        return ampId;
    }
}
function referrerId(query, ctx, disablePersistance) {
    var _a;
    var storage = new UniversalStorage(disablePersistance ? [] : [new CookieStorage(getCookieOptions())]);
    var stored = storage.get('s:context.referrer');
    var ad = (_a = ads(query)) !== null && _a !== void 0 ? _a : stored;
    if (!ad) {
        return;
    }
    if (ctx) {
        ctx.referrer = __assign(__assign({}, ctx.referrer), ad);
    }
    storage.set('s:context.referrer', ad);
}
/**
 *
 * @param obj e.g. { foo: 'b', bar: 'd', baz: ['123', '456']}
 * @returns e.g. 'foo=b&bar=d&baz=123&baz=456'
 */
var objectToQueryString = function (obj) {
    try {
        var searchParams_1 = new URLSearchParams();
        Object.entries(obj).forEach(function (_a) {
            var k = _a[0], v = _a[1];
            if (Array.isArray(v)) {
                v.forEach(function (value) { return searchParams_1.append(k, value); });
            }
            else {
                searchParams_1.append(k, v);
            }
        });
        return searchParams_1.toString();
    }
    catch (_a) {
        return '';
    }
};
var EnvironmentEnrichmentPlugin = /** @class */ (function () {
    function EnvironmentEnrichmentPlugin() {
        var _this = this;
        this.name = 'Page Enrichment';
        this.type = 'before';
        this.version = '0.1.0';
        this.isLoaded = function () { return true; };
        this.load = function (_ctx, instance) { return __awaiter(_this, void 0, void 0, function () {
            var _a, _1;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        this.instance = instance;
                        _b.label = 1;
                    case 1:
                        _b.trys.push([1, 3, , 4]);
                        _a = this;
                        return [4 /*yield*/, clientHints(this.instance.options.highEntropyValuesClientHints)];
                    case 2:
                        _a.userAgentData = _b.sent();
                        return [3 /*break*/, 4];
                    case 3:
                        _1 = _b.sent();
                        return [3 /*break*/, 4];
                    case 4: return [2 /*return*/, Promise.resolve()];
                }
            });
        }); };
        this.enrich = function (ctx) {
            var _a, _b;
            // Note: Types are off - context should never be undefined here, since it is set as part of event creation.
            var evtCtx = ctx.event.context;
            var search = evtCtx.page.search || '';
            var query = typeof search === 'object' ? objectToQueryString(search) : search;
            evtCtx.userAgent = navigator.userAgent;
            evtCtx.userAgentData = _this.userAgentData;
            // @ts-ignore
            var locale = navigator.userLanguage || navigator.language;
            if (typeof evtCtx.locale === 'undefined' && typeof locale !== 'undefined') {
                evtCtx.locale = locale;
            }
            (_a = evtCtx.library) !== null && _a !== void 0 ? _a : (evtCtx.library = {
                name: 'analytics.js',
                version: "".concat(getVersionType() === 'web' ? 'next' : 'npm:next', "-").concat(version),
            });
            if (query && !evtCtx.campaign) {
                evtCtx.campaign = utm(query);
            }
            var amp = ampId();
            if (amp) {
                evtCtx.amp = { id: amp };
            }
            referrerId(query, evtCtx, (_b = _this.instance.options.disableClientPersistence) !== null && _b !== void 0 ? _b : false);
            try {
                evtCtx.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
            }
            catch (_) {
                // If browser doesn't have support leave timezone undefined
            }
            return ctx;
        };
        this.track = this.enrich;
        this.identify = this.enrich;
        this.page = this.enrich;
        this.group = this.enrich;
        this.alias = this.enrich;
        this.screen = this.enrich;
    }
    return EnvironmentEnrichmentPlugin;
}());
export var envEnrichment = new EnvironmentEnrichmentPlugin();
//# sourceMappingURL=index.js.map