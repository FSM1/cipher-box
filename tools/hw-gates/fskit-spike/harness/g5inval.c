// Careful, single-triple invalidation trial for gate 5.
// Repeats N independent trials of: fill A -> mmap+fault -> confirm cached ->
// server-mutate to D (no inval) -> confirm still stale -> setCacheStateForItem
// (mode,type,action) -> poll mapped page for the flip to D. Reports the
// cached-rate, invalidation-landed-rate, and latency distribution so a flaky
// vs reliable primitive is distinguishable.
//
// Usage: g5inval <mountRoot> <dataFile> <mode> <type> <action> <trials>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/xattr.h>
#include <sys/mman.h>
#include <time.h>

static uint64_t now_ns(void) { return clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW); }
static int cmd(const char *root, const char *c) { return setxattr(root, "g5.cmd", c, strlen(c), 0, 0); }

int main(int argc, char **argv) {
    if (argc < 7) { fprintf(stderr, "usage: %s root file mode type action trials\n", argv[0]); return 2; }
    const char *root = argv[1], *file = argv[2];
    int mode = atoi(argv[3]), type = atoi(argv[4]), action = atoi(argv[5]), trials = atoi(argv[6]);
    const char *base = strrchr(file, '/'); base = base ? base + 1 : file;
    char buf[128];

    int cached = 0, landed = 0;
    double lat[4096]; int nl = 0;
    char *dir = strdup(file); char *sl = strrchr(dir, '/'); if (sl) *sl = 0;
    (void)base;

    printf("== gate-5 invalidation trial: setCacheStateForItem(mode=%d type=%d action=%d), %d trials ==\n",
           mode, type, action, trials);
    // Fresh file (fresh vnode) per trial so item coherency state never carries over.
    for (int t = 0; t < trials; t++) {
        char name[64], path[256];
        snprintf(name, sizeof(name), "t%d_%d.bin", (int)getpid(), t);
        snprintf(path, sizeof(path), "%s/%s", dir, name);
        snprintf(buf, sizeof(buf), "create %s 65536 A", name); cmd(root, buf);

        int fd = open(path, O_RDONLY);
        unsigned char *m = mmap(NULL, 65536, PROT_READ, MAP_SHARED, fd, 0);
        if (m == MAP_FAILED) { close(fd); continue; }
        volatile unsigned char s = m[0]; (void)s;         // fault -> cache
        usleep(2000);
        snprintf(buf, sizeof(buf), "mutate %s D", name); cmd(root, buf);  // server change, no inval
        usleep(10000);
        if (m[0] != 'A') { munmap((void*)m, 65536); close(fd); continue; }  // not cached this trial
        cached++;

        snprintf(buf, sizeof(buf), "setcache %s %d %d %d", name, mode, type, action);
        uint64_t t0 = now_ns();
        cmd(root, buf);
        int flip = 0;
        for (int i = 0; i < 3000; i++) { if (m[0] == 'D') { flip = 1; break; } usleep(100); }
        if (flip) { landed++; lat[nl++] = (now_ns() - t0) / 1e6; }
        munmap((void*)m, 65536); close(fd);
        snprintf(buf, sizeof(buf), "remove %s", name); cmd(root, buf);
    }
    printf("cached (page held stale): %d/%d\n", cached, trials);
    printf("invalidation landed:      %d/%d cached\n", landed, cached);
    if (nl) {
        // simple sort for percentiles
        for (int i = 0; i < nl; i++) for (int j = i+1; j < nl; j++) if (lat[j] < lat[i]) { double tmp=lat[i]; lat[i]=lat[j]; lat[j]=tmp; }
        double sum = 0; for (int i = 0; i < nl; i++) sum += lat[i];
        printf("latency ms: min=%.3f p50=%.3f p95=%.3f max=%.3f mean=%.3f\n",
               lat[0], lat[nl/2], lat[(int)(nl*0.95)], lat[nl-1], sum/nl);
    }
    return 0;
}
