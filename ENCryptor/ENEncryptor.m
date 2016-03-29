//
//  ENEncryptor.m
//  Encrypto
//
//  Created by tanlan on 05.12.14.
//  Copyright (c) 2014 MacPaw. All rights reserved.
//

#import "ENEncryptor.h"
#import "ENChronometer.h"
#import "ENEncryptedArchive.h"
#import "NSFileManager+Additions.h"
@import Cocoa;

@interface ENEncryptor () <ENEncryptedArchiveDelegate, ENChronometerDelegate>

@property (strong, nonatomic) NSArray *sourceURLs;
@property (strong, nonatomic) NSURL *destinationURL;

@property (strong, nonatomic) ENEncryptedArchive *archive;
@property (strong, nonatomic) ENChronometer *chronometer;

@property (assign, nonatomic) BOOL isCancelled;

@end

static NSString *const ENArchiveGroupFileName = @"Encrypted Archive.crypto";
static NSString *const ENArchiveFileExtention = @"crypto";

@interface NSImage (ENPNGRepresentation)

- (NSData *)en_PNGRepresentation;

@end

@implementation ENEncryptor

- (instancetype)init {
    return nil;
}

- (instancetype)initWithSourceURLs:(NSArray *)sourceURLs {
    if (sourceURLs == nil)
        return nil;

    self = [super init];
    if (self != nil) {
        _sourceURLs = sourceURLs;

        _archive = [ENEncryptedArchive archive];
        _archive.delegate = self;

        _chronometer = [ENChronometer new];
        _chronometer.delegate = self;
    }
    return self;
}

- (void)dealloc {
    [self.archive closeArchive];
}

+ (instancetype)encryptorWithSourceURLs:(NSArray *)sourceURLs {
    return [[self alloc] initWithSourceURLs:sourceURLs];
}

#pragma mark -

- (void)encryptWithPassword:(NSString *)password hint:(NSString *)hint preview:(NSImage *)preview {
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSURL *tempURL = [fileManager en_createUniqueTemporaryDirectory];

    if (tempURL == nil) {
        if ([self.delegate respondsToSelector:@selector(encryptor:didFailWithError:)])
            [self.delegate encryptor:self didFailWithError:[NSError errorWithDomain:[[NSBundle mainBundle] bundleIdentifier]
                                                                               code:ENEncryptedArchiveFileCreationFailed
                                                                           userInfo:nil]];
    }
    else {
        NSString *filename = self.sourceURLs.count > 1 ? ENArchiveGroupFileName :
                [[[self.sourceURLs.firstObject
                        lastPathComponent]
                        stringByDeletingPathExtension]
                        stringByAppendingPathExtension:ENArchiveFileExtention];

        self.destinationURL = [tempURL URLByAppendingPathComponent:filename];
        NSURL *root = [fileManager en_rootURLForURLs:self.sourceURLs];

        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
            __block NSError *error = nil;

            for (NSURL *currentURL in self.sourceURLs.copy) {
                NSString *failedFilePath = nil;

                if (![fileManager en_checkSourceReadability:currentURL
                                                 failedFile:&failedFilePath]) {
                    ENEncryptedArchiveItem *item = [ENEncryptedArchiveItem new];
                    item.path = failedFilePath;
                    error = [NSError errorWithDomain:[[NSBundle mainBundle] bundleIdentifier]
                                                code:ENEncryptedArchiveFileReadingFailed
                                            userInfo:@{kEncryptedArchiveItem : item}];
                    break;
                }


                NSString *currentURLPath = currentURL.path.copy;
                if (currentURLPath.length > root.path.length + 1) {
                    NSString *currentPath = root.path.copy;
                    NSString *subPath = [[currentURLPath substringFromIndex:currentPath.length + 1] stringByDeletingLastPathComponent];
                    for (NSString *currentComponent in subPath.pathComponents) {
                        currentPath = [currentPath stringByAppendingPathComponent:currentComponent];

                        if ([self.archive addItem:currentPath
                                         fromRoot:root.path] == nil) {
                            error = [NSError errorWithDomain:[[NSBundle mainBundle] bundleIdentifier]
                                                        code:ENEncryptedArchiveFileCreationFailed
                                                    userInfo:nil];
                        }
                    }

                    if (error != nil) {
                        break;
                    }
                }

                if (![fileManager en_ftsWalkAtPath:currentURL.path
                                           handler:^(NSString *currentPath, BOOL isRoot, NSUInteger size, BOOL *cancelled) {
                                               if (self.isCancelled) {
                                                   if (cancelled != NULL)
                                                       *cancelled = self.isCancelled;
                                               }
                                               else {
                                                   if ([self.archive addItem:currentPath
                                                                    fromRoot:root.path] == nil) {
                                                       if (cancelled != NULL) {
                                                           *cancelled = YES;
                                                       }

                                                       error = [NSError errorWithDomain:[[NSBundle mainBundle] bundleIdentifier]
                                                                                   code:ENEncryptedArchiveFileCreationFailed
                                                                               userInfo:nil];
                                                   }
                                               }
                                           }]) {
                    break;
                }
            }

            if (error == nil) {
                if (!self.isCancelled) {
                    self.archive.password = password;
                    self.archive.passwordHint = hint;
                    self.archive.preview = preview.en_PNGRepresentation;

                    [self.archive save:self.destinationURL.path];
                }
            }
            else if ([self.delegate respondsToSelector:@selector(encryptor:didFailWithError:)])
                [self.delegate encryptor:self didFailWithError:error];
        });
    }
}

- (void)cancel {
    self.isCancelled = YES;

    if ([self.chronometer isMeasuring])
        [self.chronometer stop];
}

#pragma mark - Encrypted Archive Delegate

- (void)encryptedArchive:(ENEncryptedArchive *)archive startedOperation:(NSDictionary *)info {
    if ([info[kEncryptedArchiveOperation] isEqualToString:kEncryptedArchiveOperationSaving]) {
        [self.chronometer start];

        if ([self.delegate respondsToSelector:@selector(encryptor:didStartWithURLs:)])
            [self.delegate encryptor:self didStartWithURLs:self.sourceURLs];
    }
}

- (void)encryptedArchive:(ENEncryptedArchive *)archive finishedOperation:(NSDictionary *)info {
    if ([info[kEncryptedArchiveOperation] isEqualToString:kEncryptedArchiveOperationSaving]) {
        if ([self.chronometer isMeasuring])
            [self.chronometer stop];

        if ([self.delegate respondsToSelector:@selector(encryptor:didFinishWithResultURL:)])
            [self.delegate encryptor:self didFinishWithResultURL:self.destinationURL];
    }
}

- (void)encryptedArchive:(ENEncryptedArchive *)archive operationProgress:(NSDictionary *)info cancel:(BOOL *)cancel {
    if (cancel != NULL)
        *cancel = self.isCancelled;

    if (!self.isCancelled) {
        double currentProgress = [info[kEncryptedArchiveTotalProgress] doubleValue];

        [self.chronometer updateProgress:currentProgress];

        if ([self.delegate respondsToSelector:@selector(encryptor:didUpdateProgress:)])
            [self.delegate encryptor:self didUpdateProgress:currentProgress];
    }
}

- (void)encryptedArchive:(ENEncryptedArchive *)archive operationError:(NSDictionary *)info {
    if ([info[kEncryptedArchiveOperation] isEqualToString:kEncryptedArchiveOperationSaving]) {
        if ([self.chronometer isMeasuring])
            [self.chronometer stop];

        if (!self.isCancelled && [self.delegate respondsToSelector:@selector(encryptor:didFailWithError:)]) {
            NSError *error = [info valueForKey:kEncryptedArchiveError];
            NSMutableDictionary *userInfo = [NSMutableDictionary dictionaryWithDictionary:error.userInfo];

            if (info[kEncryptedArchiveItem])
                [userInfo addEntriesFromDictionary:@{kEncryptedArchiveItem : info[kEncryptedArchiveItem]}];

            error = [NSError errorWithDomain:error.domain code:error.code userInfo:userInfo];
            [self.delegate encryptor:self didFailWithError:error];
        }
    }
}

#pragma mark - Chronometer Delegate

- (void)chronometer:(ENChronometer *)chronometer didUpdateRemainingTime:(double)remainingTime {
    if ([self.delegate respondsToSelector:@selector(encryptor:didUpdateEstimationTime:)])
        [self.delegate encryptor:self didUpdateEstimationTime:chronometer.remainingTime];
}

@end

@implementation NSImage (ENPNGRepresentation)

- (NSData *)en_PNGRepresentation {
    [self lockFocus];
    NSBitmapImageRep *bitmapRep =
            [[NSBitmapImageRep alloc] initWithFocusedViewRect:NSMakeRect(0, 0, self.size.width, self.size.height)];
    [self unlockFocus];

    return [bitmapRep representationUsingType:NSPNGFileType properties:@{}];
}

@end
