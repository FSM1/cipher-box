// Gate-5 FSKit spike module (issue #644).
//
// Built against the macOS 26.5 CLT SDK; the macOS 27 additions below are
// declared by hand from live-runtime introspection (selectors, argument
// order, and block signatures recovered via _protocol_getMethodTypeEncoding
// on macOS 27.0 build 26A5388g — see tools/hw-gates/RESULTS.md gate 5).

#import <Foundation/Foundation.h>
#import <FSKit/FSKit.h>

NS_ASSUME_NONNULL_BEGIN

// ---- macOS 27 runtime surface, absent from the 26.5 SDK ----

@class FSContext; // runtime-only class; opaque to this module

// Runtime extended encoding:
//   openItem:    v56@0:8@"FSItem"16Q24q32@"FSContext"40@?<v@?@"FSOpenItemResult"@"NSError">48
//   upgradeItem: v48@0:8@"FSItem"16q24@"FSContext"32@?<v@?@"FSUpgradeItemResult"@"NSError">40
//   closeItem:   v40@0:8@"FSItem"16@"FSContext"24@?<v@?>32
@protocol FSVolumeDataCacheHandler <NSObject>
@optional
- (BOOL)isDataCacheInhibited;
@required
- (void)openItem:(FSItem *)item
           modes:(NSUInteger)modes
       cacheMode:(long)cacheMode
         context:(FSContext *)context
    replyHandler:(void (^)(id _Nullable result, NSError *_Nullable error))reply;
- (void)upgradeItem:(FSItem *)item
          cacheMode:(long)cacheMode
            context:(FSContext *)context
       replyHandler:(void (^)(id _Nullable result, NSError *_Nullable error))reply;
- (void)closeItem:(FSItem *)item
          context:(FSContext *)context
     replyHandler:(void (^)(void))reply;
@end

// -[FSVolume(DataCacheHandler) setCacheStateForItem:...]; exists on the 27
// runtime only, resolved dynamically at the call site.
// Encoding: @48@0:8@16q24q32q40 (returns an object; observed to be NSError).
@interface FSVolume (Gate5MacOS27)
- (nullable id)setCacheStateForItem:(FSItem *)item
                          cacheMode:(long)cacheMode
                      coherencyType:(long)coherencyType
                    coherencyAction:(long)coherencyAction;
@end

// FSOpenItemResult / FSUpgradeItemResult (27-only): instantiated via
// NSClassFromString; both expose initWithGrantedCoherency: (@24@0:8q16).
@protocol Gate5GrantedResult <NSObject>
- (id)initWithGrantedCoherency:(long)coherency;
@end

// ---- spike module ----

@interface Gate5Volume : FSVolume <FSVolumeOperations,
                                   FSVolumeOpenCloseOperations,
                                   FSVolumeReadWriteOperations,
                                   FSVolumeXattrOperations,
                                   FSVolumeDataCacheHandler>
- (instancetype)init;
@end

@interface Gate5FS : FSUnaryFileSystem <FSUnaryFileSystemOperations>
@property (class, readonly) Gate5FS *shared;
@end

NS_ASSUME_NONNULL_END
