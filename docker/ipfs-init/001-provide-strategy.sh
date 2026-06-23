#!/bin/sh
# CipherBox Kubo init: announce only pin roots to the DHT, not every block.
#
# Reduces background provide/reprovide CPU on the shared Kubo node. With the
# default "all" strategy the staging node scheduled ~76k CIDs for DHT
# announcement, consuming a large share of Kubo's CPU at idle; "roots" cuts that
# to the pin-root count (~18k) with no loss of retrievability (every pinned root
# is still announced; only unpinned intermediate blocks are dropped).
#
# Kubo 0.40 renamed Reprovider.Strategy -> Provide.Strategy. This file is sourced
# by the Kubo entrypoint on every boot (before the daemon starts), so the setting
# is idempotent and survives container recreation and fresh repos.
ipfs config Provide.Strategy roots || echo "ipfs-init: failed to set Provide.Strategy roots (continuing)"
