//
//  ENDecryptor.m
//  Encrypto
//
//  Created by tanlan on 08.12.14.
//  Copyright (c) 2014 MacPaw. All rights reserved.
//

#import "ENDecryptor.h"
#import "ENChronometer.h"
#import "ENEncryptedArchive.h"
#import "NSFileManager+Additions.h"

@interface ENDecryptor () <ENEncryptedArchiveDelegate, ENChronometerDelegate>

@property (strong, nonatomic) NSURL *archiveURL;
@property (strong, nonatomic) NSURL *destinationURL;
@property (strong, nonatomic) ENEncryptedArchive *archive;

@property (strong, nonatomic) NSString *hint;
@property (strong, nonatomic) NSString *rootName;

@property (strong, nonatomic) ENChronometer *chronometer;
@property (assign, nonatomic) BOOL isCancelled;

@end

@implementation ENDecryptor

- (instancetype)init {
    return nil;
}

- (instancetype)initWithArchiveURL:(NSURL *)archiveURL {
    if (archiveURL == nil)
        return nil;

    self = [super init];

    if (self != nil) {
        _archiveURL = archiveURL;
        _archive = [[ENEncryptedArchive alloc] init];
        _chronometer = [ENChronometer new];
        _chronometer.delegate = self;
    }

    return self;
}

+ (instancetype)decryptorWithArchiveURL:(NSURL *)archiveURL {
    return [[self alloc] initWithArchiveURL:archiveURL];
}

- (void)dealloc {
    [self.archive closeArchive];
}

#pragma mark -

- (void)decryptWithPassword:(NSString *)password {
    NSURL *tempURL = [[NSFileManager defaultManager] en_createUniqueTemporaryDirectory];

    if (tempURL == nil) {
        if ([self.delegate respondsToSelector:@selector(decryptor:didFailWithError:)])
            [self.delegate decryptor:self didFailWithError:[NSError errorWithDomain:[[NSBundle mainBundle] bundleIdentifier]
                                                                               code:0
                                                                           userInfo:nil]];
    }
    else {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{

            self.archive.password = password;
            [self.archive openArchive:self.archiveURL.path];
            self.hint = self.archive.passwordHint;

            NSArray *rootItems = [self.archive childRecordsAtPath:nil];
            NSURL *extractionURL = tempURL;
            
            if (rootItems.count > 1) {
                extractionURL = [tempURL URLByAppendingPathComponent:self.rootName.stringByDeletingPathExtension];
                
                [[NSFileManager defaultManager] createDirectoryAtURL:extractionURL
                                         withIntermediateDirectories:YES
                                                          attributes:nil
                                                               error:nil];
                
                self.rootName = self.archiveURL.lastPathComponent;
                self.destinationURL = extractionURL;
            }
            else {
                self.rootName = [[rootItems.firstObject path] lastPathComponent];
                self.destinationURL = [tempURL URLByAppendingPathComponent:self.rootName];
            }

            self.archive.delegate = self;

            [self.archive extractAllItems:extractionURL.path];
            [self.archive closeArchive];
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
    if ([info[kEncryptedArchiveOperation] isEqualToString:kEncryptedArchiveOperationExtraction]) {
        [self.chronometer start];

        if ([self.delegate respondsToSelector:@selector(decryptor:didStartWithArchiveURL:)])
            [self.delegate decryptor:self didStartWithArchiveURL:self.archiveURL];
    }
}

- (void)encryptedArchive:(ENEncryptedArchive *)archive finishedOperation:(NSDictionary *)info {
    if ([info[kEncryptedArchiveOperation] isEqualToString:kEncryptedArchiveOperationExtraction]) {
        if ([self.chronometer isMeasuring])
            [self.chronometer stop];

        if ([self.delegate respondsToSelector:@selector(decryptor:didFinishWithResultURL:)])
            [self.delegate decryptor:self didFinishWithResultURL:self.destinationURL];
    }
}

- (void)encryptedArchive:(ENEncryptedArchive *)archive operationProgress:(NSDictionary *)info cancel:(BOOL *)cancel {
    if (cancel != NULL)
        *cancel = self.isCancelled;

    if (!self.isCancelled) {
        double currentProgress = [info[kEncryptedArchiveTotalProgress] doubleValue];

        [self.chronometer updateProgress:currentProgress];

        if ([self.delegate respondsToSelector:@selector(decryptor:didUpdateProgress:)])
            [self.delegate decryptor:self didUpdateProgress:currentProgress];
    }
}

- (void)encryptedArchive:(ENEncryptedArchive *)archive operationError:(NSDictionary *)info {
    if ([info[kEncryptedArchiveOperation] isEqualToString:kEncryptedArchiveOperationExtraction]) {
        if ([self.chronometer isMeasuring])
            [self.chronometer stop];

        if (!self.isCancelled && [self.delegate respondsToSelector:@selector(decryptor:didFailWithError:)]) {
            NSError *error = [info valueForKey:kEncryptedArchiveError];
            NSMutableDictionary *userInfo = [NSMutableDictionary dictionaryWithDictionary:error.userInfo];
            
            if (info[kEncryptedArchiveItem])
                [userInfo addEntriesFromDictionary:@{kEncryptedArchiveItem : info[kEncryptedArchiveItem]}];
            
            error = [NSError errorWithDomain:error.domain code:error.code userInfo:userInfo];

            [self.delegate decryptor:self didFailWithError:error];
        }
    }
}

- (void)encryptedArchive:(ENEncryptedArchive *)archive HMACMismatch:(ENEncryptedArchiveItem *)forItem action:(ENEncryptedArchiveAction *)action {
    if ([self.chronometer isMeasuring])
        [self.chronometer stop];

    if (!self.isCancelled && [self.delegate respondsToSelector:@selector(decryptor:didFailWithError:)]) {
        NSError *error = [NSError errorWithDomain:ENEncryptedArchiveErrorDomain
                                             code:ENEncryptedArchiveErrorDirectoryHMACMismatch
                                         userInfo:nil];

        [self.delegate decryptor:self didFailWithError:error];
    }

    if (action != NULL)
        *action = ENActionCancel;
}

#pragma mark - Chronometer Delegate

- (void)chronometer:(ENChronometer *)chronometer didUpdateRemainingTime:(double)remainingTime {
    if ([self.delegate respondsToSelector:@selector(decryptor:didUpdateEstimationTime:)])
        [self.delegate decryptor:self didUpdateEstimationTime:chronometer.remainingTime];
}

@end
