# Verification: account switching

The client unit suite and Chromium browser seam test cover preservation of
owner-local staging bytes across account switches. The browser test uses real
IndexedDB and OPFS and reads the preserved bytes through the staging seam.

Puppeteer MCP is unavailable in this environment. The following product flow
still needs manual verification with two accounts and an invite recipient:

1. Sign in as account A, mint an invite link, and sign out.
2. Sign in as account B on the same browser, then sign out.
3. Have the recipient claim A's link. Sign back in as A.
4. Check that the link and pending claim remain available and conversion succeeds.
5. Check that an explicit “forget this device” still erases only the chosen account.

## Deleting a granted folder

The engine simulation suite covers the owner's delete of read- and write-granted
scope roots with bin retention enabled and disabled. The command refuses with
`UnsupportedTarget` / `delete-target-is-a-scope-root` before publishing or queuing.

Puppeteer MCP is unavailable. The T3 browser preview was attempted at
`http://localhost:5173`, but returned a browser error page. With the local stack
running and the updated WASM built, verify:

1. As owner, share a folder with read access, then attempt to delete it.
2. Check that the refusal is visible, the folder remains, and the bin stays empty.
3. Repeat for write access and with bin retention set to zero.
4. Let several sync ticks run; check that no trust violation or dead letter appears.
