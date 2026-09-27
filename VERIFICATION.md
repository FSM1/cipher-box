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
