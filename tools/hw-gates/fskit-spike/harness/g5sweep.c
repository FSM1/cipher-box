// Focused brute-force of the setCacheStateForItem coherency triple.
// Each iteration re-establishes a stale mmap'd page (fill A -> fault ->
// server-mutate to D, no inval), fires setCacheStateForItem(mode,type,
// action), and checks whether the mapped page flips to 'D'. A hit means
// that triple is the kernel-page invalidation directive.
//
// Usage: g5sweep <mountRoot> <dataFile> <maxMode> <maxType> <maxAction>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/xattr.h>
#include <sys/mman.h>
#include <time.h>

static int cmd(const char *root, const char *c) {
    return setxattr(root, "g5.cmd", c, strlen(c), 0, 0);
}

int main(int argc, char **argv) {
    if (argc < 6) { fprintf(stderr, "usage: %s root file maxMode maxType maxAction\n", argv[0]); return 2; }
    const char *root = argv[1], *file = argv[2];
    int maxMode = atoi(argv[3]), maxType = atoi(argv[4]), maxAction = atoi(argv[5]);
    const char *base = strrchr(file, '/'); base = base ? base + 1 : file;
    char buf[128];
    int hits = 0;

    printf("== setCacheStateForItem invalidation brute-force ==\n");
    for (int mode = 0; mode <= maxMode; mode++)
    for (int type = 0; type <= maxType; type++)
    for (int action = 0; action <= maxAction; action++) {
        // Re-establish stale cached page.
        snprintf(buf, sizeof(buf), "fill %s A 65536", base); cmd(root, buf);
        int fd = open(file, O_RDONLY);
        unsigned char *m = mmap(NULL, 65536, PROT_READ, MAP_SHARED, fd, 0);
        if (m == MAP_FAILED) { close(fd); continue; }
        volatile unsigned char s = m[0]; (void)s;   // fault in
        snprintf(buf, sizeof(buf), "mutate %s D", base); cmd(root, buf);
        usleep(5000);
        if (m[0] != 'A') { munmap((void*)m, 65536); close(fd); continue; }  // wasn't cached

        // Fire the candidate invalidation.
        snprintf(buf, sizeof(buf), "setcache %s %d %d %d", base, mode, type, action);
        cmd(root, buf);
        int flipped = 0;
        for (int i = 0; i < 2000; i++) { if (m[0] == 'D') { flipped = 1; break; } usleep(100); }
        if (flipped) { printf("  HIT mode=%d type=%d action=%d -> page invalidated\n", mode, type, action); hits++; }
        munmap((void*)m, 65536); close(fd);
    }
    printf("total hits: %d\n", hits);
    return 0;
}
