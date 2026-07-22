// Gate-5 FSKit spike module: an in-memory unary file system whose only job
// is to expose the macOS 27 DataCacheHandler surface to a measurement
// harness. Control plane: setxattr("g5.cmd") issues server-side mutations
// and setCacheStateForItem probes; getxattr("g5.log") drains the event log.

#import "Gate5FS.h"
#import <os/log.h>
#import <sys/xattr.h>

static os_log_t g5log(void) {
    static os_log_t l;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ l = os_log_create("cc.cipherbox.gate5", "fs"); });
    return l;
}

static uint64_t g5now(void) { return clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW); }

static NSError *posixErr(int code) { return fs_errorForPOSIXError(code); }

#pragma mark - Item

@interface G5Item : FSItem
@property (nonatomic, copy) NSString *itemName;
@property (nonatomic) BOOL isDir;
@property (nonatomic) uint64_t itemID;
@property (nonatomic) uint32_t mode;
@property (nonatomic) NSMutableData *bytes;
@property (nonatomic) struct timespec mtime;
@property (nonatomic) struct timespec ctime;
@property (nonatomic) struct timespec btime;
@property (nonatomic) NSMutableDictionary<NSString *, NSData *> *xattrs;
@end

@implementation G5Item
- (instancetype)initWithName:(NSString *)name dir:(BOOL)dir itemID:(uint64_t)itemID {
    if ((self = [super init])) {
        _itemName = [name copy];
        _isDir = dir;
        _itemID = itemID;
        _mode = dir ? 0777 : 0666;
        _bytes = [NSMutableData data];
        _xattrs = [NSMutableDictionary dictionary];
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        _mtime = _ctime = _btime = now;
    }
    return self;
}
- (void)touchModified {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    self.mtime = now;
    self.ctime = now;
}
@end

#pragma mark - Volume

@interface Gate5Volume ()
@property (nonatomic) dispatch_queue_t q;
@property (nonatomic) G5Item *root;
@property (nonatomic) NSMutableDictionary<NSString *, G5Item *> *children;
@property (nonatomic) uint64_t nextID;
@property (nonatomic) uint32_t generation;
@property (nonatomic) long grantValue;
@property (nonatomic) NSMutableArray<NSString *> *events;
@end

@implementation Gate5Volume

- (instancetype)init {
    FSVolumeIdentifier *vid = [[FSVolumeIdentifier alloc] initWithUUID:[NSUUID UUID]];
    if ((self = [super initWithVolumeID:vid
                             volumeName:[[FSFileName alloc] initWithString:@"gate5vol"]])) {
        _q = dispatch_queue_create("cc.cipherbox.gate5.volume", DISPATCH_QUEUE_SERIAL);
        _children = [NSMutableDictionary dictionary];
        _nextID = 16;
        _generation = 1;
        _grantValue = 0;
        _events = [NSMutableArray array];
    }
    return self;
}

- (void)ev:(NSString *)fmt, ... NS_FORMAT_FUNCTION(1, 2) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *line = [NSString stringWithFormat:@"%llu %@", g5now(), msg];
    os_log(g5log(), "%{public}@", line);
    dispatch_async(self.q, ^{
        [self.events addObject:line];
        if (self.events.count > 4096) [self.events removeObjectsInRange:NSMakeRange(0, 1024)];
    });
}

- (NSString *)nameOf:(FSItem *)item {
    return [item isKindOfClass:G5Item.class] ? ((G5Item *)item).itemName : @"?";
}

- (G5Item *)makeFileNamed:(NSString *)name size:(NSUInteger)size fill:(char)c {
    G5Item *it = [[G5Item alloc] initWithName:name dir:NO itemID:self.nextID++];
    it.bytes = [NSMutableData dataWithLength:size];
    memset(it.bytes.mutableBytes, c, size);
    self.children[name] = it;
    self.generation++;
    return it;
}

#pragma mark FSVolumeOperations

- (FSVolumeSupportedCapabilities *)supportedVolumeCapabilities {
    FSVolumeSupportedCapabilities *caps = [[FSVolumeSupportedCapabilities alloc] init];
    caps.supportsHiddenFiles = YES;
    caps.supports2TBFiles = YES;
    caps.supports64BitObjectIDs = YES;
    caps.caseFormat = FSVolumeCaseFormatSensitive;
    return caps;
}

- (FSStatFSResult *)volumeStatistics {
    FSStatFSResult *st = [[FSStatFSResult alloc] initWithFileSystemTypeName:@"gate5fs"];
    st.blockSize = 4096;
    st.ioSize = 65536;
    st.totalBytes = 512ull << 20;
    st.freeBytes = 256ull << 20;
    st.availableBytes = 256ull << 20;
    st.usedBytes = 256ull << 20;
    st.totalFiles = 4096;
    st.freeFiles = 4000;
    return st;
}

- (NSInteger)maximumLinkCount { return 32; }
- (NSInteger)maximumNameLength { return 255; }
- (BOOL)restrictsOwnershipChanges { return NO; }
- (BOOL)truncatesLongNames { return NO; }
- (NSInteger)maximumXattrSize { return 1 << 20; }
- (uint64_t)maximumFileSize { return 1ull << 40; }

- (void)activateWithOptions:(FSTaskOptions *)options
               replyHandler:(void (^)(FSItem *_Nullable, NSError *_Nullable))reply {
    [self ev:@"activate"];
    dispatch_sync(self.q, ^{
        if (!self.root) {
            self.root = [[G5Item alloc] initWithName:@"/" dir:YES itemID:2 /*FSItemIDRootDirectory*/];
            [self makeFileNamed:@"data.bin" size:64 * 1024 fill:'A'];
        }
    });
    reply(self.root, nil);
}

- (void)deactivateWithOptions:(FSDeactivateOptions)options
                 replyHandler:(void (^)(NSError *_Nullable))reply {
    [self ev:@"deactivate"];
    reply(nil);
}

- (void)mountWithOptions:(FSTaskOptions *)options
            replyHandler:(void (^)(NSError *_Nullable))reply {
    [self ev:@"mount"];
    reply(nil);
}

- (void)unmountWithReplyHandler:(void (^)(void))reply {
    [self ev:@"unmount"];
    reply();
}

- (void)synchronizeWithFlags:(FSSyncFlags)flags
                replyHandler:(void (^)(NSError *_Nullable))reply {
    reply(nil);
}

- (FSItemAttributes *)attributesFor:(G5Item *)it {
    FSItemAttributes *a = [[FSItemAttributes alloc] init];
    a.type = it.isDir ? FSItemTypeDirectory : FSItemTypeFile;
    a.mode = it.mode | (it.isDir ? S_IFDIR : S_IFREG);
    a.uid = getuid();
    a.gid = getgid();
    a.linkCount = it.isDir ? 2 : 1;
    a.flags = 0;
    a.size = it.isDir ? 4096 : it.bytes.length;
    a.allocSize = (a.size + 4095) & ~4095ull;
    a.fileID = it.itemID;
    a.parentID = it.isDir ? 2 : 2;
    a.modifyTime = it.mtime;
    a.changeTime = it.ctime;
    a.accessTime = it.mtime;
    a.birthTime = it.btime;
    a.addedTime = it.btime;
    return a;
}

- (void)getAttributes:(FSItemGetAttributesRequest *)desired
               ofItem:(FSItem *)item
         replyHandler:(void (^)(FSItemAttributes *_Nullable, NSError *_Nullable))reply {
    __block FSItemAttributes *a;
    dispatch_sync(self.q, ^{ a = [self attributesFor:(G5Item *)item]; });
    [self ev:@"getattr %@ wanted=0x%lx", [self nameOf:item], (long)desired.wantedAttributes];
    reply(a, nil);
}

- (void)setAttributes:(FSItemSetAttributesRequest *)req
               onItem:(FSItem *)item
         replyHandler:(void (^)(FSItemAttributes *_Nullable, NSError *_Nullable))reply {
    G5Item *it = (G5Item *)item;
    __block FSItemAttributes *a;
    dispatch_sync(self.q, ^{
        FSItemAttribute consumed = 0;
        if ([req isValid:FSItemAttributeSize] && !it.isDir) {
            it.bytes.length = (NSUInteger)req.size;
            [it touchModified];
            consumed |= FSItemAttributeSize;
        }
        if ([req isValid:FSItemAttributeMode]) { it.mode = req.mode & 07777; consumed |= FSItemAttributeMode; }
        if ([req isValid:FSItemAttributeModifyTime]) { it.mtime = req.modifyTime; consumed |= FSItemAttributeModifyTime; }
        if ([req isValid:FSItemAttributeAccessTime]) { consumed |= FSItemAttributeAccessTime; }
        if ([req isValid:FSItemAttributeUID]) { consumed |= FSItemAttributeUID; }
        if ([req isValid:FSItemAttributeGID]) { consumed |= FSItemAttributeGID; }
        req.consumedAttributes = consumed;
        a = [self attributesFor:it];
    });
    [self ev:@"setattr %@", [self nameOf:item]];
    reply(a, nil);
}

- (void)lookupItemNamed:(FSFileName *)name
            inDirectory:(FSItem *)directory
           replyHandler:(void (^)(FSItem *_Nullable, FSFileName *_Nullable, NSError *_Nullable))reply {
    __block G5Item *found;
    dispatch_sync(self.q, ^{ found = self.children[name.string ?: @""]; });
    [self ev:@"lookup %@ -> %@", name.string, found ? @"hit" : @"ENOENT"];
    if (found) reply(found, [[FSFileName alloc] initWithString:found.itemName], nil);
    else reply(nil, nil, posixErr(ENOENT));
}

- (void)reclaimItem:(FSItem *)item replyHandler:(void (^)(NSError *_Nullable))reply {
    [self ev:@"reclaim %@", [self nameOf:item]];
    reply(nil);
}

- (void)readSymbolicLink:(FSItem *)item
            replyHandler:(void (^)(FSFileName *_Nullable, NSError *_Nullable))reply {
    reply(nil, posixErr(EINVAL));
}

- (void)createItemNamed:(FSFileName *)name
                   type:(FSItemType)type
            inDirectory:(FSItem *)directory
             attributes:(FSItemSetAttributesRequest *)newAttributes
           replyHandler:(void (^)(FSItem *_Nullable, FSFileName *_Nullable, NSError *_Nullable))reply {
    NSString *n = name.string ?: @"";
    __block G5Item *it;
    __block BOOL exists = NO;
    dispatch_sync(self.q, ^{
        if (self.children[n]) { exists = YES; return; }
        if (type == FSItemTypeDirectory) {
            it = [[G5Item alloc] initWithName:n dir:YES itemID:self.nextID++];
            self.children[n] = it;
            self.generation++;
        } else {
            it = [self makeFileNamed:n size:0 fill:0];
        }
        if ([newAttributes isValid:FSItemAttributeMode]) it.mode = newAttributes.mode & 07777;
    });
    [self ev:@"create %@ type=%ld%@", n, (long)type, exists ? @" EEXIST" : @""];
    if (exists) reply(nil, nil, posixErr(EEXIST));
    else reply(it, [[FSFileName alloc] initWithString:n], nil);
}

- (void)createSymbolicLinkNamed:(FSFileName *)name
                    inDirectory:(FSItem *)directory
                     attributes:(FSItemSetAttributesRequest *)newAttributes
                   linkContents:(FSFileName *)contents
                   replyHandler:(void (^)(FSItem *_Nullable, FSFileName *_Nullable, NSError *_Nullable))reply {
    reply(nil, nil, posixErr(ENOTSUP));
}

- (void)createLinkToItem:(FSItem *)item
                   named:(FSFileName *)name
             inDirectory:(FSItem *)directory
            replyHandler:(void (^)(FSFileName *_Nullable, NSError *_Nullable))reply {
    reply(nil, posixErr(ENOTSUP));
}

- (void)removeItem:(FSItem *)item
             named:(FSFileName *)name
     fromDirectory:(FSItem *)directory
      replyHandler:(void (^)(NSError *_Nullable))reply {
    NSString *n = name.string ?: @"";
    dispatch_sync(self.q, ^{
        [self.children removeObjectForKey:n];
        self.generation++;
    });
    [self ev:@"remove %@", n];
    reply(nil);
}

- (void)renameItem:(FSItem *)item
       inDirectory:(FSItem *)sourceDirectory
             named:(FSFileName *)sourceName
         toNewName:(FSFileName *)destinationName
       inDirectory:(FSItem *)destinationDirectory
          overItem:(FSItem *)overItem
      replyHandler:(void (^)(FSFileName *_Nullable, NSError *_Nullable))reply {
    NSString *src = sourceName.string ?: @"", *dst = destinationName.string ?: @"";
    dispatch_sync(self.q, ^{
        G5Item *it = self.children[src];
        [self.children removeObjectForKey:src];
        it.itemName = dst;
        self.children[dst] = it;
        self.generation++;
    });
    [self ev:@"rename %@ -> %@%@", src, dst, overItem ? @" over" : @""];
    reply([[FSFileName alloc] initWithString:dst], nil);
}

- (void)enumerateDirectory:(FSItem *)directory
          startingAtCookie:(FSDirectoryCookie)cookie
                  verifier:(FSDirectoryVerifier)verifier
       providingAttributes:(FSItemGetAttributesRequest *)attributes
               usingPacker:(FSDirectoryEntryPacker *)packer
              replyHandler:(void (^)(FSDirectoryVerifier, NSError *_Nullable))reply {
    __block NSArray<G5Item *> *items;
    __block uint32_t gen;
    dispatch_sync(self.q, ^{
        items = [self.children.allValues sortedArrayUsingComparator:^(G5Item *a, G5Item *b) {
            return [a.itemName compare:b.itemName];
        }];
        gen = self.generation;
    });
    [self ev:@"enumdir cookie=%llu attrs=%d", (unsigned long long)cookie, attributes != nil];
    // Cookie space: 0 ".", 1 "..", 2+i child i.
    uint64_t idx = (uint64_t)cookie;
    if (attributes == nil) {
        for (; idx < 2; idx++) {
            FSFileName *dot = [[FSFileName alloc] initWithString:idx == 0 ? @"." : @".."];
            if (![packer packEntryWithName:dot
                                  itemType:FSItemTypeDirectory
                                    itemID:2
                                nextCookie:idx + 1
                                attributes:nil]) {
                reply(gen, nil);
                return;
            }
        }
    } else if (idx < 2) {
        idx = 2;
    }
    for (; idx - 2 < items.count; idx++) {
        G5Item *it = items[(NSUInteger)(idx - 2)];
        FSItemAttributes *a = attributes ? [self attributesFor:it] : nil;
        if (![packer packEntryWithName:[[FSFileName alloc] initWithString:it.itemName]
                              itemType:it.isDir ? FSItemTypeDirectory : FSItemTypeFile
                                itemID:it.itemID
                            nextCookie:idx + 1
                            attributes:a]) break;
    }
    reply(gen, nil);
}

#pragma mark FSVolumeOpenCloseOperations

- (void)openItem:(FSItem *)item
       withModes:(FSVolumeOpenModes)modes
    replyHandler:(void (^)(NSError *_Nullable))reply {
    [self ev:@"open %@ modes=0x%lx", [self nameOf:item], (unsigned long)modes];
    reply(nil);
}

- (void)closeItem:(FSItem *)item
     keepingModes:(FSVolumeOpenModes)modes
     replyHandler:(void (^)(NSError *_Nullable))reply {
    [self ev:@"close %@ keep=0x%lx", [self nameOf:item], (unsigned long)modes];
    reply(nil);
}

#pragma mark FSVolumeReadWriteOperations

- (void)readFromFile:(FSItem *)item
              offset:(off_t)offset
              length:(size_t)length
          intoBuffer:(FSMutableFileDataBuffer *)buffer
        replyHandler:(void (^)(size_t, NSError *_Nullable))reply {
    G5Item *it = (G5Item *)item;
    __block size_t n = 0;
    dispatch_sync(self.q, ^{
        if ((uint64_t)offset < it.bytes.length) {
            n = MIN(length, (size_t)(it.bytes.length - (uint64_t)offset));
            n = MIN(n, buffer.length);
            memcpy(buffer.mutableBytes, (const char *)it.bytes.bytes + offset, n);
        }
    });
    [self ev:@"read %@ off=%lld len=%zu -> %zu", [self nameOf:item], (long long)offset, length, n];
    reply(n, nil);
}

- (void)writeContents:(NSData *)contents
               toFile:(FSItem *)item
             atOffset:(off_t)offset
         replyHandler:(void (^)(size_t, NSError *_Nullable))reply {
    G5Item *it = (G5Item *)item;
    dispatch_sync(self.q, ^{
        uint64_t end = (uint64_t)offset + contents.length;
        if (it.bytes.length < end) it.bytes.length = (NSUInteger)end;
        [it.bytes replaceBytesInRange:NSMakeRange((NSUInteger)offset, contents.length)
                            withBytes:contents.bytes];
        [it touchModified];
    });
    [self ev:@"write %@ off=%lld len=%lu", [self nameOf:item], (long long)offset,
             (unsigned long)contents.length];
    reply(contents.length, nil);
}

#pragma mark FSVolumeXattrOperations (control plane)

- (void)getXattrNamed:(FSFileName *)name
               ofItem:(FSItem *)item
         replyHandler:(void (^)(NSData *_Nullable, NSError *_Nullable))reply {
    NSString *n = name.string ?: @"";
    if ([n isEqualToString:@"g5.log"]) {
        __block NSString *joined;
        dispatch_sync(self.q, ^{
            joined = [self.events componentsJoinedByString:@"\n"];
            [self.events removeAllObjects];
        });
        reply([joined dataUsingEncoding:NSUTF8StringEncoding], nil);
        return;
    }
    __block NSData *val;
    dispatch_sync(self.q, ^{ val = ((G5Item *)item).xattrs[n]; });
    if (val) reply(val, nil);
    else reply(nil, posixErr(ENOATTR));
}

- (void)setXattrNamed:(FSFileName *)name
               toData:(NSData *)value
               onItem:(FSItem *)item
               policy:(FSSetXattrPolicy)policy
         replyHandler:(void (^)(NSError *_Nullable))reply {
    NSString *n = name.string ?: @"";
    if ([n isEqualToString:@"g5.cmd"]) {
        NSString *cmd = [[NSString alloc] initWithData:value encoding:NSUTF8StringEncoding];
        reply([self runCommand:[cmd stringByTrimmingCharactersInSet:
                                        NSCharacterSet.whitespaceAndNewlineCharacterSet]]);
        return;
    }
    dispatch_sync(self.q, ^{
        G5Item *it = (G5Item *)item;
        if (value) it.xattrs[n] = value;
        else [it.xattrs removeObjectForKey:n];
    });
    reply(nil);
}

- (void)listXattrsOfItem:(FSItem *)item
            replyHandler:(void (^)(NSArray<FSFileName *> *_Nullable, NSError *_Nullable))reply {
    __block NSArray<NSString *> *names;
    dispatch_sync(self.q, ^{ names = ((G5Item *)item).xattrs.allKeys; });
    NSMutableArray<FSFileName *> *out = [NSMutableArray array];
    for (NSString *n in names) [out addObject:[[FSFileName alloc] initWithString:n]];
    reply(out, nil);
}

// Command grammar (one per setxattr, space-separated):
//   mutate <name> <char>            server-side data overwrite, same size
//   fill <name> <char> <size>       data + size change
//   touch <name>                    mtime bump only
//   create <name> <size> <char>     new entry, server-side
//   remove <name>                   drop entry, server-side
//   grant <long>                    coherency value replied to open/upgrade
//   setcache <name> <mode> <type> <action>   -[FSVolume setCacheStateForItem:...]
- (NSError *)runCommand:(NSString *)cmd {
    NSArray<NSString *> *t = [cmd componentsSeparatedByString:@" "];
    NSString *op = t.firstObject ?: @"";
    __block NSError *err;
    __block G5Item *target;
    G5Item *(^need)(NSString *) = ^(NSString *name) {
        __block G5Item *it;
        dispatch_sync(self.q, ^{ it = self.children[name]; });
        if (!it) err = posixErr(ENOENT);
        return it;
    };
    if ([op isEqualToString:@"mutate"] && t.count == 3) {
        if ((target = need(t[1]))) {
            dispatch_sync(self.q, ^{
                memset(target.bytes.mutableBytes, [t[2] characterAtIndex:0], target.bytes.length);
            });
            [self ev:@"cmd.mutate %@ '%@'", t[1], t[2]];
        }
    } else if ([op isEqualToString:@"fill"] && t.count == 4) {
        if ((target = need(t[1]))) {
            dispatch_sync(self.q, ^{
                target.bytes.length = (NSUInteger)[t[3] longLongValue];
                memset(target.bytes.mutableBytes, [t[2] characterAtIndex:0], target.bytes.length);
                [target touchModified];
            });
            [self ev:@"cmd.fill %@ '%@' %@", t[1], t[2], t[3]];
        }
    } else if ([op isEqualToString:@"touch"] && t.count == 2) {
        if ((target = need(t[1]))) {
            dispatch_sync(self.q, ^{ [target touchModified]; });
            [self ev:@"cmd.touch %@", t[1]];
        }
    } else if ([op isEqualToString:@"create"] && t.count == 4) {
        dispatch_sync(self.q, ^{
            [self makeFileNamed:t[1] size:(NSUInteger)[t[2] longLongValue]
                           fill:(char)[t[3] characterAtIndex:0]];
        });
        [self ev:@"cmd.create %@ %@", t[1], t[2]];
    } else if ([op isEqualToString:@"remove"] && t.count == 2) {
        dispatch_sync(self.q, ^{
            [self.children removeObjectForKey:t[1]];
            self.generation++;
        });
        [self ev:@"cmd.remove %@", t[1]];
    } else if ([op isEqualToString:@"grant"] && t.count == 2) {
        self.grantValue = [t[1] integerValue];
        [self ev:@"cmd.grant %ld", self.grantValue];
    } else if ([op isEqualToString:@"setcache"] && t.count == 5) {
        if ((target = need(t[1]))) {
            uint64_t t0 = g5now();
            id r = [self setCacheStateForItem:target
                                    cacheMode:[t[2] integerValue]
                                coherencyType:[t[3] integerValue]
                              coherencyAction:[t[4] integerValue]];
            [self ev:@"cmd.setcache %@ mode=%@ type=%@ action=%@ took=%lluns -> %@: %@",
                     t[1], t[2], t[3], t[4], g5now() - t0,
                     r ? NSStringFromClass([r class]) : @"nil", r ?: @"ok"];
        }
    } else {
        err = posixErr(EINVAL);
        [self ev:@"cmd.unknown '%@'", cmd];
    }
    return err;
}

#pragma mark FSVolumeDataCacheHandler (macOS 27)

- (BOOL)isDataCacheInhibited {
    [self ev:@"dch.isDataCacheInhibited -> NO"];
    return NO;
}

- (id)grantedResultOf:(NSString *)cls {
    return [(id<Gate5GrantedResult>)[NSClassFromString(cls) alloc]
        initWithGrantedCoherency:self.grantValue];
}

- (void)openItem:(FSItem *)item
           modes:(NSUInteger)modes
       cacheMode:(long)cacheMode
         context:(FSContext *)context
    replyHandler:(void (^)(id _Nullable, NSError *_Nullable))reply {
    [self ev:@"dch.open %@ modes=0x%lx cacheMode=%ld grant=%ld",
             [self nameOf:item], (unsigned long)modes, cacheMode, self.grantValue];
    reply([self grantedResultOf:@"FSOpenItemResult"], nil);
}

- (void)upgradeItem:(FSItem *)item
          cacheMode:(long)cacheMode
            context:(FSContext *)context
       replyHandler:(void (^)(id _Nullable, NSError *_Nullable))reply {
    [self ev:@"dch.upgrade %@ cacheMode=%ld grant=%ld",
             [self nameOf:item], cacheMode, self.grantValue];
    reply([self grantedResultOf:@"FSUpgradeItemResult"], nil);
}

- (void)closeItem:(FSItem *)item
          context:(FSContext *)context
     replyHandler:(void (^)(void))reply {
    [self ev:@"dch.close %@", [self nameOf:item]];
    reply();
}

@end

#pragma mark - File system

@implementation Gate5FS

+ (Gate5FS *)shared {
    static Gate5FS *fs;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ fs = [[Gate5FS alloc] init]; });
    return fs;
}

- (void)didFinishLoading {
    os_log(g5log(), "gate5fs extension loaded (pid %d)", getpid());
}

- (void)probeResource:(FSResource *)resource
         replyHandler:(void (^)(FSProbeResult *_Nullable, NSError *_Nullable))reply {
    os_log(g5log(), "probe %{public}@", resource);
    reply([FSProbeResult usableProbeResultWithName:@"gate5vol"
                                       containerID:[[FSContainerIdentifier alloc]
                                                       initWithUUID:[NSUUID UUID]]],
          nil);
}

- (void)loadResource:(FSResource *)resource
             options:(FSTaskOptions *)options
        replyHandler:(void (^)(FSVolume *_Nullable, NSError *_Nullable))reply {
    os_log(g5log(), "loadResource %{public}@", resource);
    // At load time the container is ready (loaded, no volume active yet);
    // it transitions to active only once a volume mounts.
    self.containerStatus = FSContainerStatus.ready;
    reply([[Gate5Volume alloc] init], nil);
}

- (void)unloadResource:(FSResource *)resource
               options:(FSTaskOptions *)options
          replyHandler:(void (^)(NSError *_Nullable))reply {
    os_log(g5log(), "unloadResource");
    reply(nil);
}

@end
