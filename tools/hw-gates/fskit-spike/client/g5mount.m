// Entitled FSKit control client for the gate-5 spike:
//   g5mount list
//   g5mount enable|disable <bundleID>
//   g5mount mount <backingDir> <mountPath> [optkind]   (optkind: nil|dict|task)
//   g5mount mountnopath <backingDir> [optkind]
//
// mountSingleVolumeForResource:... is macOS-27-only; declared here from
// runtime introspection (see RESULTS.md gate 5). The completion handler's
// exact arity is undocumented; the handler below decodes defensively.

#import <Foundation/Foundation.h>
#import <FSKit/FSKit.h>
#import <objc/runtime.h>

@interface FSClient (Gate5MacOS27)
// v56@0:8@16@24@32@40@?48
- (void)mountSingleVolumeForResource:(FSResource *)resource
                            bundleID:(NSString *)bundleID
                           mountPath:(id)mountPath
                             options:(id)options
                   completionHandler:(void (^)(id arg1, id arg2))handler;
// v48@0:8@16@24@32@?40
- (void)mountSingleVolumeForResource:(FSResource *)resource
                            bundleID:(NSString *)bundleID
                             options:(id)options
                   completionHandler:(void (^)(id arg1, id arg2))handler;
// v36@0:8@16B24@?28
- (void)setEnabledStateForIdentifier:(NSString *)identifier
                            newState:(BOOL)newState
                        replyHandler:(void (^)(id reply))reply;
@end

static void describeArg(const char *label, id a) {
    if (!a) { printf("  %s: nil\n", label); return; }
    printf("  %s: <%s> %s\n", label, class_getName(object_getClass(a)),
           [[a description] UTF8String]);
}

static id optionsOfKind(const char *kind) {
    if (!kind || !strcmp(kind, "nil")) return nil;
    if (!strcmp(kind, "dict")) return @{};
    if (!strcmp(kind, "task")) {
        // FSTaskOptions has no public initializer in the 26.5 SDK; try alloc/init.
        return [[NSClassFromString(@"FSTaskOptions") alloc] init];
    }
    fprintf(stderr, "unknown optkind %s\n", kind);
    exit(2);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: g5mount list|enable|disable|mount|mountnopath ...\n"); return 2; }
    NSString *cmd = @(argv[1]);
    FSClient *client = FSClient.sharedInstance;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block int rc = 0;

    if ([cmd isEqualToString:@"list"]) {
        [client fetchInstalledExtensionsWithCompletionHandler:^(NSArray *ids, NSError *err) {
            if (err) { printf("error: %s\n", err.description.UTF8String); rc = 1; }
            for (id m in ids) printf("%s\n", [[m description] UTF8String]);
            dispatch_semaphore_signal(sem);
        }];
    } else if ([cmd isEqualToString:@"enable"] || [cmd isEqualToString:@"disable"]) {
        if (argc < 3) { fprintf(stderr, "need bundleID\n"); return 2; }
        [client setEnabledStateForIdentifier:@(argv[2])
                                    newState:[cmd isEqualToString:@"enable"]
                                replyHandler:^(id reply) {
            describeArg("reply", reply);
            dispatch_semaphore_signal(sem);
        }];
    } else if ([cmd isEqualToString:@"mount"]) {
        if (argc < 4) { fprintf(stderr, "need backingDir mountPath\n"); return 2; }
        FSPathURLResource *res =
            [[FSPathURLResource alloc] initWithURL:[NSURL fileURLWithPath:@(argv[2])]
                                          writable:YES];
        printf("mounting gate5fs (resource %s) at %s...\n", argv[2], argv[3]);
        [client mountSingleVolumeForResource:res
                                    bundleID:@"cc.cipherbox.gate5host.fsmodule"
                                   mountPath:@(argv[3])
                                     options:optionsOfKind(argc > 4 ? argv[4] : "nil")
                           completionHandler:^(id a1, id a2) {
            // One-arg convention: a1 is the NSError (or nil). Two-arg: a1 is a
            // path-ish value and a2 the NSError. Only trust a2 when a1 is
            // clearly not an error.
            describeArg("arg1", a1);
            describeArg("arg2", a2);
            if ([a1 isKindOfClass:NSError.class] || [a2 isKindOfClass:NSError.class]) rc = 1;
            dispatch_semaphore_signal(sem);
        }];
    } else if ([cmd isEqualToString:@"mountnopath"]) {
        if (argc < 3) { fprintf(stderr, "need backingDir\n"); return 2; }
        FSPathURLResource *res =
            [[FSPathURLResource alloc] initWithURL:[NSURL fileURLWithPath:@(argv[2])]
                                          writable:YES];
        [client mountSingleVolumeForResource:res
                                    bundleID:@"cc.cipherbox.gate5host.fsmodule"
                                     options:optionsOfKind(argc > 3 ? argv[3] : "nil")
                           completionHandler:^(id a1, id a2) {
            describeArg("arg1", a1);
            describeArg("arg2", a2);
            if ([a1 isKindOfClass:NSError.class] || [a2 isKindOfClass:NSError.class]) rc = 1;
            dispatch_semaphore_signal(sem);
        }];
    } else {
        fprintf(stderr, "unknown command\n");
        return 2;
    }

    if (dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC))) {
        fprintf(stderr, "timed out waiting for fskitd reply\n");
        return 3;
    }
    return rc;
}
