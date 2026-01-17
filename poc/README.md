# CipherBox Console PoC Harness

Single-user, online test harness that exercises CipherBox file system flows directly on IPFS/IPNS (no Web3Auth, no backend). Each run initializes a new vault, executes a full flow, verifies correctness via IPNS/IPFS, then unpins all created CIDs during teardown.

## Requirements

- Node.js 20+
- Local IPFS daemon (Kubo) with the HTTP API enabled
- Optional: Pinata API keys for remote pin/unpin

## Setup

1. Copy the env template:
   - `cp .env.example .env`
2. Set `ECDSA_PRIVATE_KEY` to a 32-byte hex string (no `0x`).
3. Ensure your IPFS API is reachable at `IPFS_API_URL`.

## Run

- `npm install`
- `npm start`

## What the harness does

- Initializes a new vault (root folder key + root IPNS key)
- Creates folders
- Uploads a file, downloads and verifies content
- Modifies, renames, moves, and deletes a file
- Publishes all metadata to IPFS and IPNS
- Measures IPNS propagation delay per publish
- Teardown: unpins all file and metadata CIDs, removes IPNS keys

## Notes

- IPNS resolution is eventually consistent; the harness polls until the expected CID appears.
- Unpinning removes pins from configured services but does not guarantee deletion from the public IPFS network.
