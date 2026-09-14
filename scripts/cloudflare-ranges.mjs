/**
 * Cloudflare's published edge ranges, hand-mirrored from cloudflare.com/ips.
 *
 * Trusting these ranges is what makes an IP-keyed rate limit key on a member
 * rather than on a whole edge POP (blueprint/deploy.md). The Lint gate pins
 * `docker/Caddyfile` to this set, and the nightly Cloudflare Range Watch pins
 * this set to Cloudflare's live list, so a snapshot cannot go stale in silence.
 */
export const CLOUDFLARE_RANGES = [
  '173.245.48.0/20',
  '103.21.244.0/22',
  '103.22.200.0/22',
  '103.31.4.0/22',
  '141.101.64.0/18',
  '108.162.192.0/18',
  '190.93.240.0/20',
  '188.114.96.0/20',
  '197.234.240.0/22',
  '198.41.128.0/17',
  '162.158.0.0/15',
  '104.16.0.0/13',
  '104.24.0.0/14',
  '172.64.0.0/13',
  '131.0.72.0/22',
  '2400:cb00::/32',
  '2606:4700::/32',
  '2803:f800::/32',
  '2405:b500::/32',
  '2405:8100::/32',
  '2a06:98c0::/29',
  '2c0f:f248::/32',
];
