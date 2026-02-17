# Session Context

**Session ID:** 39dea4ee-5f57-4587-8c44-40db1cc1144c

**Commit Message:** There is some weird effect on the logout menu - it often closes between

## Prompt

there is some weird effect on the logout menu - it often closes between mouse-over on the trigger and the cursor being on the menu item.

## Summary

The dropdown is positioned with `top: calc(100% + 4px)` (same visual gap as before), and the `::before` pseudo-element spans the 4px gap invisibly, keeping the mouse within `.user-menu` during the transition. Want to test it before I commit?

## Key Actions

- - **Grep**: logout|user-menu|UserMenu|account-menu|ProfileMenu
- - **Read**: /Users/michael/Code/cipher-box/apps/web/src/components/layout/UserMenu.tsx
- - **Grep**: user-menu
- - **Grep**: user-menu
- - **Read**: /Users/michael/Code/cipher-box/apps/web/src/styles/layout.css
- - **Edit**: /Users/michael/Code/cipher-box/apps/web/src/styles/layout.css
- - **Edit**: /Users/michael/Code/cipher-box/apps/web/src/styles/layout.css
