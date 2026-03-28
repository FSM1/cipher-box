# CipherBox Feature Matrix

**Last updated:** 2026-03-28

## Platform Feature Matrix

| Feature                         | Web | Desktop | API | SDK | E2E Tests          |
| ------------------------------- | --- | ------- | --- | --- | ------------------ |
| **Authentication**              |     |         |     |     |                    |
| Google OAuth                    | Y   | Y       | Y   | -   | full-workflow      |
| Email OTP                       | Y   | Y       | Y   | -   | full-workflow      |
| Wallet login (SIWE)             | Y   | Y       | Y   | -   | wallet-login       |
| Test-only login                 | -   | Y       | Y   | -   | all suites         |
| Token refresh                   | Y   | Y       | Y   | -   | full-workflow      |
| Logout + token revocation       | Y   | Y       | Y   | -   | full-workflow      |
| Account deletion                | Y   | -       | Y   | -   | sharing-workflow   |
| **MFA & Device Management**     |     |         |     |     |                    |
| MFA enrollment                  | Y   | Y       | Y   | -   | mfa-flows          |
| Recovery phrase (BIP39)         | Y   | Y       | -   | -   | mfa-flows          |
| Device approval flow            | Y   | Y       | Y   | -   | mfa-flows          |
| Authorized devices list         | Y   | -       | Y   | -   | mfa-flows          |
| Link/unlink auth methods        | Y   | -       | Y   | -   | -                  |
| **File Operations**             |     |         |     |     |                    |
| Upload (single file)            | Y   | Y       | Y   | Y   | full-workflow      |
| Upload (drag-and-drop)          | Y   | -       | -   | -   | full-workflow      |
| Download (single)               | Y   | Y       | Y   | Y   | full-workflow      |
| Download (batch zip)            | Y   | -       | -   | -   | -                  |
| Rename                          | Y   | Y       | -   | Y   | full-workflow      |
| Delete (to bin)                 | Y   | Y       | -   | Y   | recycle-bin        |
| Move (between folders)          | Y   | Y       | -   | Y   | full-workflow      |
| Replace (re-upload)             | Y   | -       | -   | -   | full-workflow      |
| Text file editing               | Y   | -       | -   | -   | full-workflow      |
| File details panel              | Y   | -       | -   | -   | full-workflow      |
| Storage quota display           | Y   | -       | Y   | -   | full-workflow      |
| **File Versioning**             |     |         |     |     |                    |
| Version history                 | Y   | -       | -   | Y   | full-workflow      |
| Version restore                 | Y   | -       | -   | Y   | full-workflow      |
| **Folder Operations**           |     |         |     |     |                    |
| Create folder                   | Y   | Y       | -   | Y   | full-workflow      |
| Navigate (breadcrumbs)          | Y   | Y       | -   | Y   | full-workflow      |
| Rename folder                   | Y   | Y       | -   | Y   | full-workflow      |
| Delete folder (to bin)          | Y   | Y       | -   | Y   | recycle-bin        |
| Move folder                     | Y   | Y       | -   | Y   | full-workflow      |
| Nested subfolders               | Y   | Y       | -   | Y   | full-workflow      |
| **Sharing (Direct)**            |     |         |     |     |                    |
| Share file (read-only)          | Y   | -       | Y   | Y   | sharing-workflow   |
| Share folder (read-only)        | Y   | -       | Y   | Y   | sharing-workflow   |
| Share file (read-write)         | Y   | -       | Y   | Y   | writable-shares    |
| Share folder (read-write)       | Y   | -       | Y   | Y   | writable-shares    |
| Multi-recipient sharing         | Y   | -       | Y   | Y   | sharing-workflow   |
| Permission upgrade/downgrade    | Y   | -       | Y   | -   | writable-shares    |
| Share revocation                | Y   | -       | Y   | Y   | sharing-workflow   |
| Hide received share             | Y   | -       | Y   | -   | sharing-workflow   |
| Lazy key rotation               | Y   | -       | Y   | -   | sharing-workflow   |
| Write ops in shared folder      | Y   | -       | Y   | Y   | writable-shares    |
| **Sharing (Invite Links)**      |     |         |     |     |                    |
| Generate invite link            | Y   | -       | Y   | -   | invite-link        |
| Claim invite link               | Y   | -       | Y   | -   | invite-link        |
| Invite landing page             | Y   | -       | Y   | -   | invite-link        |
| Revoke invite link              | Y   | -       | Y   | -   | invite-link        |
| **Recycle Bin**                 |     |         |     |     |                    |
| Soft delete                     | Y   | -       | -   | Y   | recycle-bin        |
| View deleted items              | Y   | -       | -   | Y   | recycle-bin        |
| Restore from bin                | Y   | -       | -   | Y   | recycle-bin        |
| Permanent delete                | Y   | -       | -   | Y   | recycle-bin        |
| Empty bin                       | Y   | -       | -   | Y   | recycle-bin        |
| **Search**                      |     |         |     |     |                    |
| Fuzzy file name search          | Y   | -       | -   | -   | search-workflow    |
| Cmd/Ctrl+K shortcut             | Y   | -       | -   | -   | search-workflow    |
| Keyboard navigation             | Y   | -       | -   | -   | search-workflow    |
| **Media Preview**               |     |         |     |     |                    |
| Image preview                   | Y   | -       | -   | -   | full-workflow      |
| PDF viewer                      | Y   | -       | -   | -   | -                  |
| Video player (streaming)        | Y   | -       | -   | -   | -                  |
| Audio player                    | Y   | -       | -   | -   | -                  |
| **Sync**                        |     |         |     |     |                    |
| IPNS polling (30s)              | Y   | Y       | -   | Y   | conflict-detection |
| Conflict detection (409)        | Y   | Y       | Y   | Y   | conflict-detection |
| Device registry sync            | Y   | Y       | -   | -   | -                  |
| **Desktop-Specific**            |     |         |     |     |                    |
| FUSE mount (~\/CipherBox)       | -   | Y       | -   | -   | desktop-e2e        |
| Transparent file access         | -   | Y       | -   | -   | desktop-e2e        |
| System tray integration         | -   | Y       | -   | -   | desktop-e2e        |
| OS keychain storage             | -   | Y       | -   | -   | -                  |
| Auto-updater                    | -   | Y       | -   | -   | -                  |
| Dev-key mode (headless)         | -   | Y       | -   | -   | desktop-e2e        |
| **Infrastructure**              |     |         |     |     |                    |
| TEE IPNS republishing           | -   | -       | Y   | -   | -                  |
| BYO IPFS node support           | -   | -       | Y   | -   | sdk-e2e            |
| Pin migration (provider switch) | -   | -       | Y   | -   | -                  |
| Prometheus metrics              | -   | -       | Y   | -   | -                  |
| Vault recovery tool             | Y   | -       | -   | -   | recovery           |
| Performance baselines           | -   | -       | Y   | -   | journey-timing     |

## E2E Test Suites

| Suite              | File                           | Coverage                                                                                            |
| ------------------ | ------------------------------ | --------------------------------------------------------------------------------------------------- |
| Full Workflow      | `full-workflow.spec.ts`        | Login, vault init, folders, files, edit, rename, move, delete, versioning, media preview            |
| Sharing            | `sharing-workflow.spec.ts`     | Direct shares, multi-recipient, revocation, key rotation, hide                                      |
| Writable Shares    | `writable-shares.spec.ts`      | Write permission, recipient uploads/mkdir/rename/delete, permission upgrade/downgrade, file editing |
| Invite Links       | `invite-link-workflow.spec.ts` | Create invite, claim, revoke, landing page                                                          |
| Recycle Bin        | `recycle-bin.spec.ts`          | Soft delete, restore, permanent delete, empty bin                                                   |
| Search             | `search-workflow.spec.ts`      | Search palette, fuzzy matching, keyboard/click navigation                                           |
| MFA Flows          | `mfa-flows.spec.ts`            | MFA enrollment, device approval, recovery phrase                                                    |
| Wallet Login       | `wallet-login.spec.ts`         | EIP-6963 mock wallet, SIWE flow                                                                     |
| Recovery           | `recovery.spec.ts`             | Vault recovery tool via IPFS-direct v2 blob path                                                    |
| Conflict Detection | `conflict-detection.spec.ts`   | Multi-device conflicts, auto-resync                                                                 |
| Journey Timing     | `journey-timing.spec.ts`       | Performance benchmarks for critical paths                                                           |
| Load Test          | `load-test.spec.ts`            | Concurrent operations stress testing                                                                |

## Features Without E2E Coverage

- PDF viewer, video player, audio player (manual testing only)
- Batch download (zip)
- Link/unlink auth methods
- Device registry sync
- OS keychain storage
- Auto-updater
- TEE republishing
- Pin migration

<!-- Feature matrix: 2026-03-28 -->
