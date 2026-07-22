// Gate-5 DataCacheHandler measurement harness.
//
// The mounted gate5fs exposes a control plane through xattrs on the mount
// root: setxattr("g5.cmd", "<verb> ...") mutates server-side state or fires
// -[FSVolume setCacheStateForItem:...]; getxattr("g5.log") drains the
// module's event log. This probe drives the coherence experiments that
// answer the FUSE-T gate-1 question for the FSKit backend:
//
//   1. Does the kernel (LiveFS/lifs) cache file data after a read, so a
//      server-side mutation is NOT visible on the next read?
//   2. Does setCacheStateForItem land an invalidation on that cached data,
//      and how fast (the gate-1 "cached data never revalidates" failure)?
//   3. What is the steady-state read-path cost once cached?
//
// Usage: g5probe <mountRoot> <dataFile> [coherencySweepMax]

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/xattr.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <time.h>
#include <errno.h>

static uint64_t now_ns(void) {
    return clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW);
}

static int cmd(const char *root, const char *c) {
    if (setxattr(root, "g5.cmd", c, strlen(c), 0, 0) != 0) {
        fprintf(stderr, "  cmd '%s' failed: %s\n", c, strerror(errno));
        return -1;
    }
    return 0;
}

static void drain_log(const char *root, const char *tag) {
    static char buf[65536];
    ssize_t n = getxattr(root, "g5.log", buf, sizeof(buf) - 1, 0, 0);
    if (n <= 0) return;
    buf[n] = 0;
    printf("  --- module log (%s) ---\n", tag);
    for (char *line = strtok(buf, "\n"); line; line = strtok(NULL, "\n"))
        printf("    %s\n", line);
}

// Read the whole file fresh (own fd) and return the first byte + a checksum.
static unsigned char read_first(const char *path, long *sum, size_t *len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return 0; }
    static unsigned char b[1 << 20];
    ssize_t total = 0, r;
    long s = 0;
    unsigned char first = 0;
    while ((r = read(fd, b, sizeof(b))) > 0) {
        if (total == 0 && r > 0) first = b[0];
        for (ssize_t i = 0; i < r; i++) s += b[i];
        total += r;
    }
    close(fd);
    if (sum) *sum = s;
    if (len) *len = (size_t)total;
    return first;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <mountRoot> <dataFile> [sweepMax]\n", argv[0]);
        return 2;
    }
    const char *root = argv[1];
    const char *file = argv[2];
    int sweepMax = argc > 3 ? atoi(argv[3]) : 4;
    const char *base = strrchr(file, '/');
    base = base ? base + 1 : file;

    printf("== Gate-5 DataCacheHandler coherence probe ==\n");
    printf("mount=%s file=%s\n\n", root, file);

    // Baseline: seed the file to all 'A' at 64 KiB, read it (populates cache).
    char buf[128];
    snprintf(buf, sizeof(buf), "fill %s A 65536", base);
    if (cmd(root, buf)) return 1;

    long sum;
    size_t len;
    unsigned char first = read_first(file, &sum, &len);
    printf("[baseline] first=0x%02x len=%zu sum=%ld\n", first, len, sum);

    // --- Experiment 1: does pread cache? (buffer-cache path) ---
    printf("\n[exp1] pread held-open fd vs server mutate, NO invalidation\n");
    int fd = open(file, O_RDONLY);
    unsigned char held[65536];
    pread(fd, held, sizeof(held), 0);
    snprintf(buf, sizeof(buf), "mutate %s B", base);
    cmd(root, buf);  // server-side: backing bytes now all 'B', no FS write
    unsigned char after[65536];
    pread(fd, after, sizeof(after), 0);
    printf("  re-read after mutate (no inval): 0x%02x -> %s\n",
           after[0], after[0] == 'A' ? "STALE (kernel cached)" : "fresh (readFromFile re-hit)");
    close(fd);

    // --- Experiment 2: mmap page cache + coherency-grant sweep ---
    // mmap forces the unified page cache. For each grantedCoherency the
    // module hands back in dch.open, test whether a mapped page holds stale
    // data after a server-side mutation (i.e. the kernel is caching under
    // that grant), then whether setCacheStateForItem invalidates it.
    printf("\n[exp2] mmap page-cache staleness vs granted coherency\n");
    printf("  %-6s %-16s %-22s\n", "grant", "holds-cache?", "setCacheState invalidates?");
    for (int grant = 0; grant <= sweepMax; grant++) {
        snprintf(buf, sizeof(buf), "grant %d", grant);
        cmd(root, buf);
        snprintf(buf, sizeof(buf), "fill %s A 65536", base);
        cmd(root, buf);

        int mfd = open(file, O_RDONLY);
        unsigned char *m = mmap(NULL, 65536, PROT_READ, MAP_SHARED, mfd, 0);
        if (m == MAP_FAILED) { printf("  %-6d mmap failed: %s\n", grant, strerror(errno)); close(mfd); continue; }
        volatile unsigned char seed = m[0];  // fault the page in -> cached
        (void)seed;

        // Server-side mutate to 'D', NO invalidation. Re-touch mapped page.
        snprintf(buf, sizeof(buf), "mutate %s D", base);
        cmd(root, buf);
        // Give any async coherence a moment, then sample.
        usleep(20000);
        int holds = (m[0] == 'A');

        // Now fire setCacheStateForItem and see if the mapped page refreshes.
        int invalidated = 0;
        double lat_ms = 0;
        if (holds) {
            snprintf(buf, sizeof(buf), "setcache %s 0 0 0", base);
            uint64_t t0 = now_ns();
            cmd(root, buf);
            for (int i = 0; i < 5000; i++) {
                if (m[0] == 'D') { lat_ms = (now_ns() - t0) / 1e6; invalidated = 1; break; }
                usleep(100);
            }
        }
        munmap((void *)m, 65536);
        close(mfd);

        if (!holds)
            printf("  %-6d %-16s %-22s\n", grant, "no (coherent)", "n/a (never stale)");
        else if (invalidated)
            printf("  %-6d %-16s YES  %.3f ms\n", grant, "STALE", lat_ms);
        else
            printf("  %-6d %-16s NO  (stale >500ms)\n", grant, "STALE");
    }

    // --- Experiment 2b: setCacheStateForItem return-value sweep ---
    // Independent of caching, record which (mode,type,action) triples the
    // 27 API accepts vs rejects, from the module-logged return object.
    printf("\n[exp2b] setCacheStateForItem accepted arg triples (see module log)\n");
    cmd(root, "grant 0");
    for (int type = 0; type <= sweepMax; type++)
        for (int action = 0; action <= sweepMax; action++) {
            snprintf(buf, sizeof(buf), "setcache %s 0 %d %d", base, type, action);
            cmd(root, buf);
        }

    // --- Experiment 3: steady-state cached read cost ---
    printf("\n[exp3] steady-state read latency (cached, held-open fd)\n");
    fd = open(file, O_RDONLY);
    unsigned char one[4096];
    pread(fd, one, sizeof(one), 0);  // warm
    uint64_t mn = ~0ull, mx = 0, tot = 0;
    const int N = 1000;
    for (int i = 0; i < N; i++) {
        uint64_t t0 = now_ns();
        pread(fd, one, sizeof(one), 0);
        uint64_t d = now_ns() - t0;
        if (d < mn) mn = d;
        if (d > mx) mx = d;
        tot += d;
    }
    close(fd);
    printf("  n=%d  min=%.3fus  mean=%.3fus  max=%.3fus\n",
           N, mn / 1e3, (tot / (double)N) / 1e3, mx / 1e3);

    drain_log(root, "final");
    return 0;
}
