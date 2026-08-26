# Stock Caddy ships no rate limiter, and the front's `/routing/v1` PUT publish
# leg is deliberately token-free (blueprint/api.md, Egress) — a body cap is all
# it can bound without one.
FROM caddy:2.11.4-builder-alpine AS build

RUN xcaddy build v2.11.4 --with github.com/mholt/caddy-ratelimit@v0.1.0

FROM caddy:2.11.4-alpine

COPY --from=build /usr/bin/caddy /usr/bin/caddy
