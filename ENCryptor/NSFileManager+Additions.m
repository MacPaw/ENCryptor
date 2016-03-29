//
//  NSFileManager+MHAdditions.m
//  Encrypto
//
//  Created by tanlan on 10/8/13.
//  Copyright (c) 2013 MacPaw. All rights reserved.
//  
#import "NSFileManager+Additions.h"
#import "fts.h"
#import <sys/stat.h>

@implementation NSFileManager (MHAdditions)

- (BOOL)en_ftsWalkAtPath:(NSString *)path
                 handler:(void (^)(NSString *currentPath, BOOL isRoot, NSUInteger size, BOOL *cancelled))handler; {
    BOOL isCancelled = NO;
    BOOL ftsSuccessed = YES;

    @autoreleasepool {
        const char *fts_paths[] = {[path fileSystemRepresentation], 0};

        FTS *fts = fts_open((char *const *) fts_paths, FTS_PHYSICAL | FTS_XDEV | FTS_NOCHDIR, NULL);
        FTSENT *entry = NULL;

        BOOL isRoot = YES;

        while ((entry = fts_read(fts)) && !isCancelled) {
            unsigned short ftsInfo = entry->fts_info;

            if (ftsInfo == FTS_DP) {
                isRoot = NO;
                continue;
            }
            else if (ftsInfo == FTS_ERR) {
                ftsSuccessed = NO;
                break;
            }

            if (handler != NULL) {
                handler([NSString stringWithUTF8String:entry->fts_path], isRoot, entry->fts_statp->st_size, &isCancelled);
            }

            isRoot = NO;
        }

        if (fts != NULL) {
            @try {
                fts_close(fts);
            }
            @catch (NSException *exception) {
                NSLog(@"fts_close exception = %@", exception);
            }
        }
    }

    return ftsSuccessed;
}

#pragma mark -

- (NSURL *)en_createUniqueTemporaryDirectory {
    NSURL *tempURL = [self.class en_temporaryDirectoryURL];

    if (tempURL == nil)
        return nil;

    NSURL *URL = [tempURL URLByAppendingPathComponent:[NSUUID UUID].UUIDString];

    if ([self createDirectoryAtURL:URL withIntermediateDirectories:YES
                        attributes:nil
                             error:nil])
        return URL;

    return nil;
}

- (NSURL *)en_rootURLForURLs:(NSArray *)urls {
    NSString *rootPath = [NSString new];
    BOOL foundRootPath = NO;

    if (urls.count) {
        NSString *main = [urls.firstObject path];

        for (NSString *currentComponent in [main pathComponents]) {
            rootPath = [rootPath stringByAppendingPathComponent:currentComponent];

            for (NSURL *currentURL in [urls copy]) {
                if (![currentURL.path hasPrefix:rootPath]) {
                    foundRootPath = YES;
                    break;
                }
            }

            if (foundRootPath) {
                break;
            }
        }
    }

    return [NSURL fileURLWithPath:rootPath];
}

@end

@implementation NSFileManager (SystemPaths)

+ (NSURL *)en_userLibraryURL {
    NSArray *paths = [[NSFileManager defaultManager] URLsForDirectory:NSLibraryDirectory inDomains:NSUserDomainMask];
    if (paths.count == 1) {
        return paths.firstObject;
    }
    else {
        NSLog(@"Error: returned more than one user library path: %@", paths);
        return nil;
    }
}

+ (NSURL *)en_temporaryDirectoryURL {
    return [self.en_userLibraryURL URLByAppendingPathComponent:@"Temp"];
}

@end

@implementation NSFileManager (Rights)

- (BOOL)en_checkSourceReadability:(NSURL *)sourceURL
                       failedFile:(NSString *__autoreleasing *)failedFilePath {
    __block NSString *localFailed = nil;

    [self en_ftsWalkAtPath:sourceURL.path
                   handler:^(NSString *currentPath, BOOL isRoot, NSUInteger size, BOOL *cancelled) {
                       if (![self isReadableFileAtPath:currentPath]) {
                           localFailed = currentPath;
                           if (cancelled != NULL)
                               *cancelled = YES;
                       }
                   }];

    if (localFailed != nil && failedFilePath != NULL) {
        *failedFilePath = localFailed;
    }

    return localFailed == nil;
}

@end
