# Phase 7: Multi-Device Sync - Research

**Researched:** 2026-01-22
**Domain:** Multi-device sync via IPNS polling, React state management, offline detection
**Confidence:** HIGH

## Summary

Multi-device sync via IPNS polling is a well-established pattern in distributed applications. The standard approach combines interval-based polling with browser APIs for visibility and network detection, state management via Zustand, and stale-while-revalidate caching patterns.

**Key findings:**

- IPNS resolution via delegated routing API is already implemented in backend (delegated-ipfs.dev)
- React polling patterns use custom hooks with useEffect/useRef cleanup and Page Visibility API integration
- Zustand state management works seamlessly with polling patterns and already used in codebase
- Browser offline detection uses navigator.onLine with online/offline event listeners
- Last-write-wins conflict resolution uses timestamp comparison (simple, deterministic)
- Optimistic UI updates require manual rollback on error (no automatic rollback in React)

**Primary recommendation:** Implement polling with custom useInterval hook, integrate Page Visibility API to pause when backgrounded, use Zustand for sync state, and implement stale-while-revalidate pattern for IPNS resolution caching.

## Standard Stack

The established libraries/tools for this domain:

### Core

| Library               | Version | Purpose                | Why Standard                                                                      |
| --------------------- | ------- | ---------------------- | --------------------------------------------------------------------------------- |
| Zustand               | 5.0.10  | Sync state management  | Already in use; lightweight, works with concurrent mode via useSyncExternalStore  |
| @tanstack/react-query | 5.62.0  | Server state & caching | Already in use; handles deduplication, stale-while-revalidate, cache invalidation |
| React 18              | 18.3.1  | UI framework           | Already in use; concurrent mode supports interruptible rendering                  |

### Supporting

| Library                 | Version        | Purpose                   | When to Use                                     |
| ----------------------- | -------------- | ------------------------- | ----------------------------------------------- |
| Page Visibility API     | Browser native | Detect tab backgrounding  | Pause polling when tab inactive to save battery |
| navigator.onLine        | Browser native | Offline detection         | Block operations and auto-resume on reconnect   |
| window.addEventListener | Browser native | Network/visibility events | React to online/offline/visibilitychange events |

### Alternatives Considered

| Instead of     | Could Use     | Tradeoff                                                              |
| -------------- | ------------- | --------------------------------------------------------------------- |
| Custom polling | WebSockets    | WebSockets more complex, overkill for 30s latency, IPNS is poll-only  |
| Zustand        | Redux Toolkit | Redux heavier (10% adoption in 2026 vs Zustand 40%), more boilerplate |
| Manual caching | SWR library   | SWR adds dependency; React Query already provides pattern             |

**Installation:**
All core dependencies already installed. No additional packages needed.

## Architecture Patterns

### Recommended Project Structure

```
apps/web/src/
├── hooks/
│   ├── useInterval.ts          # Custom interval hook with cleanup
│   ├── useVisibility.ts        # Page Visibility API wrapper
│   ├── useOnlineStatus.ts      # Network status detection
│   └── useSyncPolling.ts       # Main sync polling orchestrator
├── services/
│   ├── ipns.service.ts         # IPNS resolution (add resolve function)
│   └── sync.service.ts         # Sync logic (compare CIDs, update state)
├── stores/
│   ├── sync.store.ts           # Sync state (lastSync, isSyncing, errors)
│   └── folder.store.ts         # Existing - update with sync data
└── components/
    └── SyncIndicator.tsx       # Header sync icon
```

### Pattern 1: Custom useInterval Hook

**What:** Reusable interval hook with proper cleanup and ref-based callback
**When to use:** All polling operations
**Example:**

```typescript
// Source: https://blog.openreplay.com/polling-in-react-using-the-useinterval-custom-hook/
function useInterval(callback: () => void, delay: number | null) {
  const savedCallback = useRef<(() => void) | null>(null);

  // Remember the latest callback (without re-establishing interval)
  useEffect(() => {
    savedCallback.current = callback;
  }, [callback]);

  // Set up the interval
  useEffect(() => {
    if (delay === null) return; // Pause polling by passing null

    const id = setInterval(() => {
      savedCallback.current?.();
    }, delay);

    return () => clearInterval(id); // Cleanup on unmount
  }, [delay]);
}
```

### Pattern 2: Page Visibility Integration

**What:** Pause polling when tab is backgrounded
**When to use:** All background polling to save battery
**Example:**

```typescript
// Source: https://usehooks.com/usevisibilitychange
function useVisibilityChange() {
  const [isVisible, setIsVisible] = useState(!document.hidden);

  useEffect(() => {
    const handleVisibilityChange = () => {
      setIsVisible(!document.hidden);
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, []);

  return isVisible;
}

// Usage in polling hook
const isVisible = useVisibilityChange();
const pollDelay = isVisible ? 30000 : null; // null pauses polling
useInterval(pollCallback, pollDelay);
```

### Pattern 3: Offline Detection

**What:** navigator.onLine with event listeners
**When to use:** Block operations when offline, auto-resume when online
**Example:**

```typescript
// Source: https://developer.mozilla.org/en-US/docs/Web/API/Navigator/Online_and_offline_events
function useOnlineStatus() {
  const [isOnline, setIsOnline] = useState(navigator.onLine);

  useEffect(() => {
    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  return isOnline;
}
```

### Pattern 4: Stale-While-Revalidate Caching

**What:** Serve cached IPNS resolution immediately while fetching fresh data
**When to use:** Initial folder load to show last-known state quickly
**Example:**

```typescript
// Source: https://tanstack.com/query/latest/docs/framework/react/guides/optimistic-updates
// Use React Query for IPNS resolution caching
const { data: resolvedCid, isStale } = useQuery({
  queryKey: ['ipns', ipnsName],
  queryFn: () => resolveIpnsRecord(ipnsName),
  staleTime: 30000, // Consider fresh for 30s
  gcTime: 60000, // Keep in cache for 60s
});

// Show cached data immediately with "Syncing..." indicator if stale
```

### Pattern 5: Zustand Sync State

**What:** Central sync state store for polling status
**When to use:** Track sync state across components
**Example:**

```typescript
type SyncState = {
  isSyncing: boolean;
  lastSyncTime: Date | null;
  syncError: string | null;

  startSync: () => void;
  syncSuccess: (timestamp: Date) => void;
  syncFailure: (error: string) => void;
};

export const useSyncStore = create<SyncState>((set) => ({
  isSyncing: false,
  lastSyncTime: null,
  syncError: null,

  startSync: () => set({ isSyncing: true, syncError: null }),
  syncSuccess: (timestamp) =>
    set({
      isSyncing: false,
      lastSyncTime: timestamp,
    }),
  syncFailure: (error) =>
    set({
      isSyncing: false,
      syncError: error,
    }),
}));
```

### Anti-Patterns to Avoid

- **Direct setInterval in component:** Memory leaks on unmount - always use cleanup
- **Polling without visibility check:** Wastes battery when tab backgrounded
- **Assuming navigator.onLine is reliable:** It only detects network interface status, not actual connectivity
- **Hardcoded intervals:** Use state/props for dynamic control (pause, resume)
- **Triggering full reload on every poll:** Use CID comparison to detect changes first
- **Automatic re-polling after local changes:** Wait for next interval (per user decision)

## Don't Hand-Roll

Problems that look simple but have existing solutions:

| Problem                | Don't Build              | Use Instead                   | Why                                                                  |
| ---------------------- | ------------------------ | ----------------------------- | -------------------------------------------------------------------- |
| Polling with cleanup   | Custom setInterval logic | useInterval hook pattern      | Cleanup, ref updates, pause/resume built-in                          |
| Request deduplication  | Manual request tracking  | React Query                   | Handles concurrent identical requests automatically                  |
| Cache invalidation     | Manual cache tracking    | React Query invalidateQueries | Timestamp-based staleness, automatic refetch                         |
| Stale-while-revalidate | Custom cache logic       | React Query staleTime         | Battle-tested, handles race conditions                               |
| Offline queueing       | Custom request queue     | Manual with online event      | Complex edge cases (partial failures, retry logic) - defer to future |

**Key insight:** Polling patterns have many edge cases (unmount during request, concurrent updates, stale callbacks). Use established patterns and hooks rather than reinventing.

## Common Pitfalls

### Pitfall 1: setInterval Callback Captures Stale State

**What goes wrong:** setInterval callback captures state at creation time, doesn't see updates
**Why it happens:** JavaScript closure captures variables at creation, not reference
**How to avoid:** Use useRef to store latest callback, update ref on every render
**Warning signs:** Callback using old prop/state values, infinite loops with dependency arrays

### Pitfall 2: Memory Leak from Uncleaned Intervals

**What goes wrong:** Interval continues running after component unmounts
**Why it happens:** Forgot to return cleanup function from useEffect
**How to avoid:** Always return `() => clearInterval(id)` from useEffect
**Warning signs:** Console errors about setting state on unmounted component

### Pitfall 3: navigator.onLine False Positives

**What goes wrong:** navigator.onLine shows true but actual network requests fail
**Why it happens:** navigator.onLine only detects if network interface is connected, not internet reachability
**How to avoid:** Don't fully trust it; use it as hint, handle network errors gracefully
**Warning signs:** "Online" indicator but requests timing out

### Pitfall 4: Race Conditions in Concurrent Polls

**What goes wrong:** Second poll completes before first, older data overwrites newer
**Why it happens:** Network timing variability
**How to avoid:** Compare sequence numbers/timestamps, abort outdated requests
**Warning signs:** Folder state flickering between old and new

### Pitfall 5: Polling During Tab Backgrounding Drains Battery

**What goes wrong:** Continuous polling when user isn't viewing the app wastes resources
**Why it happens:** Browser throttles timers in background but doesn't stop them
**How to avoid:** Use Page Visibility API to pause polling (set delay to null)
**Warning signs:** High CPU usage when tab backgrounded, battery complaints

### Pitfall 6: Optimistic Update Without Rollback

**What goes wrong:** UI shows success but server fails, leaving inconsistent state
**Why it happens:** Assumed operation would succeed, no error handling
**How to avoid:** Store previous state, rollback on error, or use React Query's onError
**Warning signs:** UI out of sync with server after errors

## Code Examples

Verified patterns from official sources:

### IPNS Resolution via Delegated Routing

```typescript
// Source: https://specs.ipfs.tech/ipips/ipip-0379/ (Delegated IPNS HTTP API)
// Backend already implements PUT /routing/v1/ipns/{ipnsName}
// Need to implement GET for resolution

async function resolveIpnsRecord(ipnsName: string): Promise<{
  cid: string;
  sequenceNumber: bigint;
} | null> {
  // Use backend relay to delegated-ipfs.dev
  const response = await fetch(`/api/ipns/resolve?name=${ipnsName}`);
  if (!response.ok) return null;

  const data = await response.json();
  return {
    cid: data.cid,
    sequenceNumber: BigInt(data.sequenceNumber),
  };
}
```

### Sync Polling Orchestrator

```typescript
// Combines all patterns: interval, visibility, online status
function useSyncPolling() {
  const isVisible = useVisibilityChange();
  const isOnline = useOnlineStatus();
  const { startSync, syncSuccess, syncFailure } = useSyncStore();
  const { rootIpnsName } = useVaultStore();
  const { folders, setFolder } = useFolderStore();

  const pollSync = useCallback(async () => {
    if (!rootIpnsName || !isOnline) return;

    startSync();
    try {
      // 1. Resolve IPNS to current CID
      const resolved = await resolveIpnsRecord(rootIpnsName);
      if (!resolved) throw new Error('Resolution failed');

      // 2. Compare with cached CID
      const rootFolder = folders['root'];
      const cachedCid = rootFolder?.latestCid;

      if (resolved.cid !== cachedCid) {
        // 3. Changes detected - fetch and decrypt new metadata
        await refreshFolderMetadata(rootIpnsName, resolved.cid);
      }

      syncSuccess(new Date());
    } catch (error) {
      syncFailure(error.message);
    }
  }, [rootIpnsName, isOnline, folders]);

  // Poll every 30s when visible and online
  const pollDelay = isVisible && isOnline ? 30000 : null;
  useInterval(pollSync, pollDelay);

  // Poll immediately when coming online
  const prevOnline = useRef(isOnline);
  useEffect(() => {
    if (isOnline && !prevOnline.current) {
      pollSync(); // Reconnected - sync immediately
    }
    prevOnline.current = isOnline;
  }, [isOnline, pollSync]);
}
```

### Last-Write-Wins Conflict Resolution

```typescript
// Source: https://docs.couchbase.com/sync-gateway/current/conflict-resolution.html
// Compare IPNS sequence numbers (higher sequence wins)
function resolveConflict(localSequence: bigint, remoteSequence: bigint): 'local' | 'remote' {
  return remoteSequence > localSequence ? 'remote' : 'local';
}

// Apply remote changes if remote sequence is higher
if (resolveConflict(localSeq, remoteSeq) === 'remote') {
  // Overwrite local state with remote
  setFolder({
    ...folder,
    children: remoteChildren,
    sequenceNumber: remoteSequence,
  });
}
```

### Optimistic UI with Manual Rollback

```typescript
// Source: https://tanstack.com/query/latest/docs/framework/react/guides/optimistic-updates
const deleteMutation = useMutation({
  mutationFn: deleteFile,
  onMutate: async (fileId) => {
    // Cancel outgoing refetches
    await queryClient.cancelQueries({ queryKey: ['folder', folderId] });

    // Snapshot previous value for rollback
    const previous = useFolderStore.getState().folders[folderId];

    // Optimistically update UI
    updateFolderChildren(
      folderId,
      previous.children.filter((c) => c.id !== fileId)
    );

    return { previous }; // Context for rollback
  },
  onError: (err, fileId, context) => {
    // Rollback on error
    if (context?.previous) {
      setFolder(context.previous);
    }
  },
  onSettled: () => {
    // Refetch to ensure sync
    queryClient.invalidateQueries({ queryKey: ['folder', folderId] });
  },
});
```

## State of the Art

| Old Approach                | Current Approach                           | When Changed                  | Impact                             |
| --------------------------- | ------------------------------------------ | ----------------------------- | ---------------------------------- |
| setInterval directly        | useInterval custom hook                    | React Hooks (2019)            | Proper cleanup, no memory leaks    |
| Manual visibility detection | Page Visibility API                        | Stable in all browsers (2021) | Battery savings, standardized      |
| navigator.onLine only       | navigator.onLine + event listeners         | Modern browsers               | Reactive updates, not just polling |
| Redux for all state         | Zustand for client, React Query for server | 2023-2024                     | Lighter bundle, better DX          |
| Fetch with manual caching   | React Query stale-while-revalidate         | TanStack Query v5 (2023)      | Automatic cache management         |
| Long polling                | WebSockets/SSE                             | Modern realtime               | Not applicable - IPNS is poll-only |

**Deprecated/outdated:**

- **setInterval in class components:** React 18+ uses hooks, class components deprecated
- **componentWillUnmount for cleanup:** Use useEffect cleanup function
- **SWR library for this use case:** React Query already in project, avoid duplicate functionality

## Open Questions

Things that couldn't be fully resolved:

1. **IPNS resolution latency actual performance**
   - What we know: Specs mention <2s for uncached, <200ms for cached (from TECHNICAL_ARCHITECTURE.md)
   - What's unclear: Real-world latency via delegated-ipfs.dev in 2026
   - Recommendation: Measure in integration tests, may need backend caching layer if too slow
   - Research flag: "IPNS resolution latency (~30s) may need deeper investigation during Phase 7" already noted in STATE.md

2. **Backend IPNS resolution endpoint exists?**
   - What we know: Backend has `POST /ipns/publish` but no `GET /ipns/resolve` endpoint found
   - What's unclear: Whether resolution endpoint needs to be added or exists elsewhere
   - Recommendation: Add `GET /ipns/resolve?name={ipnsName}` endpoint to relay to delegated-ipfs.dev

3. **Polling behavior when tab regains focus**
   - What we know: User decision leaves this to Claude's discretion
   - Options: (a) Poll immediately on focus regain, (b) Wait for next interval
   - Recommendation: Poll immediately on focus regain - provides fresh data when user returns

4. **Offline UI treatment**
   - What we know: User decision leaves this to Claude's discretion
   - Options: (a) Toast notification, (b) Persistent banner, (c) Blocking overlay
   - Recommendation: Persistent subtle banner at top - non-intrusive but always visible

## Sources

### Primary (HIGH confidence)

- [Delegated IPNS HTTP API Specification](https://specs.ipfs.tech/ipips/ipip-0379/) - IPNS resolution protocol
- [Page Visibility API - MDN](https://developer.mozilla.org/en-US/docs/Web/API/Page_Visibility_API) - Browser visibility detection
- [Navigator onLine - MDN](https://developer.mozilla.org/en-US/docs/Web/API/Navigator/Online_and_offline_events) - Offline detection
- [TanStack Query Optimistic Updates](https://tanstack.com/query/latest/docs/framework/react/guides/optimistic-updates) - React Query patterns
- Codebase files: `apps/web/src/stores/vault.store.ts`, `apps/api/src/ipns/ipns.service.ts`

### Secondary (MEDIUM confidence)

- [Polling in React using useInterval](https://blog.openreplay.com/polling-in-react-using-the-useinterval-custom-hook/) - Custom hook pattern
- [useVisibilityChange Hook](https://usehooks.com/usevisibilitychange) - Page visibility hook
- [Zustand + React Query Pattern](https://medium.com/@freeyeon96/zustand-react-query-new-state-management-7aad6090af56) - State management combination
- [Last-Write-Wins Conflict Resolution - Couchbase](https://docs.couchbase.com/sync-gateway/current/conflict-resolution.html) - LWW patterns
- [Stale-While-Revalidate Guide](https://www.toptal.com/react/stale-while-revalidate) - Caching strategy

### Tertiary (LOW confidence - verify during implementation)

- [State Management in 2026](https://www.nucamp.co/blog/state-management-in-2026-redux-context-api-and-modern-patterns) - Market trends
- [Chrome Timer Throttling](https://developer.chrome.com/blog/timer-throttling-in-chrome-88) - Background behavior

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH - All libraries already in codebase, verified versions
- Architecture patterns: HIGH - Patterns from MDN, React docs, established libraries
- IPNS resolution: MEDIUM - Backend endpoint needs verification/implementation
- Pitfalls: HIGH - Well-documented in React ecosystem
- Performance: MEDIUM - Real-world IPNS latency needs measurement

**Research date:** 2026-01-22
**Valid until:** 2026-02-22 (30 days - stable browser APIs and React patterns)
