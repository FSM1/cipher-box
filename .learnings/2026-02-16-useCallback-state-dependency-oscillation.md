# useCallback State Dependency Oscillation Causes Infinite Render Loop

**Date:** 2026-02-16

## Original Prompt

> Debugging browser tab crash during login flow. Chrome DevTools showed 12,962 failed GET requests to `/device-approval/pending` with `ERR_INSUFFICIENT_RESOURCES`.

## What I Learned

- **State in `useCallback` deps + effect cleanup that resets that state = infinite render loop.** The pattern:
  ```
  const [flag, setFlag] = useState(false);
  const fn = useCallback(() => { setFlag(true); ... }, [flag]);  // identity changes when flag changes
  // In consumer:
  useEffect(() => { fn(); return () => { setFlag(false); }; }, [fn]);  // cleanup resets flag
  ```
  This oscillates: effect fires -> flag=true -> fn new identity -> cleanup resets flag=false -> fn new identity -> effect fires -> repeat forever.

- **The symptom was misleading.** It looked like CoreKit `loginWithJWT` was crashing the browser (WASM/TSS), but it was actually a runaway polling loop in a completely unrelated component (`DeviceApprovalModal`) starving the browser of network resources. The tab freeze happened to coincide with login because that's when auth state changes triggered the modal's polling effect.

- **`ERR_INSUFFICIENT_RESOURCES` is the giveaway.** This Chrome error means the browser's network socket pool is exhausted. Normal polling (even aggressive) doesn't hit this. Seeing it means requests are firing synchronously in a tight loop, not on an interval.

- **Fix: use `useRef` instead of `useState` for guards that don't need to trigger re-renders.** A ref-based guard (`isPollingRef.current`) works identically for the polling logic but doesn't change callback identities or trigger render cycles.

## What Would Have Helped

- Opening Chrome DevTools Network tab earlier instead of assuming the freeze was WASM-related
- Checking for `ERR_INSUFFICIENT_RESOURCES` or rapid-fire requests as a first diagnostic step when a tab becomes unresponsive
- Recognizing that "browser tab crashes after X" doesn't mean X caused the crash — check what else activates when X runs

## Key Files

- `apps/web/src/hooks/useDeviceApproval.ts` — the polling hook with the bug
- `apps/web/src/components/mfa/DeviceApprovalModal.tsx` — the consumer whose useEffect + cleanup created the oscillation
- `apps/web/src/api/custom-instance.ts` — the fetch wrapper (line 24 appeared in all console errors)
