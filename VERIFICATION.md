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

## Session restore failures

The web unit suite covers a refused secret export, a provider HTTP refusal, and
an account conflict across the protected-route redirect, including multiple auth
consumers. The staging harness unit suite covers successful restoration, visible
refusals, a silent return to sign-in, timeout, and report redaction.

Puppeteer MCP was unavailable. The collaborative browser verified the actual
sign-in UI with injected Core Kit and engine fixtures: the restore refusal and
account-conflict explanation were visible, and a subsequent email sign-in cleared
the refusal and reached the vault fixture.

The deployed build still needs this check after release:

1. Sign in to staging, then use browser request blocking to block the staging
   API's `/auth/challenge` request.
2. Reload `/files`. Once restoration fails, verify that sign-in displays the
   refusal instead of silently losing the session.
3. Remove the request block and sign in again. Verify that the old refusal clears
   and the vault opens.
4. Run staging `link-first`. A refused return from offline should report the
   restore refusal, or a return to sign-in without an error, instead of waiting
   three minutes for a missing file browser.
