# Stock Caddy ships no rate limiter, and the front's `/routing/v1` PUT publish
# leg is deliberately token-free (blueprint/api.md, Egress) — a body cap is all
# it can bound without one.
#
# Both stages are digest-pinned: this binary terminates TLS and enforces every
# egress obligation, and the same tags feed the Lint gate. The builder bakes the
# Caddy version, so `xcaddy build` takes it from there rather than repeating it
# here, where a bump could miss one of two places and mismatch the runtime base.
FROM caddy:2.11.4-builder-alpine@sha256:7bac9be4072f7c4db2ccc7350750e0705004bf02da2ac7d96b1469ca4f28bb7c AS build

# Pinned to a commit rather than v0.1.0, the newest tag: `ipv6_prefix` landed
# after it, and masking the key to a /64 outside the module means pattern-matching
# a text address, which cannot reach the network half of a compressed one.
RUN xcaddy build --with github.com/mholt/caddy-ratelimit@5625512f24f6f59d6f64fb3aafe5eecff0b286db

FROM caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648

COPY --from=build /usr/bin/caddy /usr/bin/caddy
