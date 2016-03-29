//
//  ENArchiveOpener.m
//  Encrypto
//
//  Created by tanlan on 26.01.15.
//  Copyright (c) 2015 MacPaw. All rights reserved.
//

@import Cocoa;
#import "ENArchiveOpener.h"
#import "ENEncryptedArchive.h"

@interface ENArchiveOpener () <ENEncryptedArchiveDelegate>

@property (strong, nonatomic) ENEncryptedArchive *archive;
@property (strong, nonatomic) NSString *archivePath;
@property (strong, nonatomic) dispatch_semaphore_t passCheckingSemaphore;
@property (strong, nonatomic) dispatch_semaphore_t passValidationSemaphore;

@property (assign, nonatomic) BOOL validationResult;

@end

static NSString *const ENFolderUTI = @"public.folder";

@implementation ENArchiveOpener

- (instancetype)initWithArchiveURL:(NSURL *)archiveURL {
    if (archiveURL.path == nil)
        return nil;

    self = [super init];

    if (self != nil) {
        _archivePath = archiveURL.path;

        _archive = [ENEncryptedArchive new];
        [_archive openArchive:_archivePath];

        _hint = _archive.passwordHint;

        [_archive closeArchive];
        _archive = nil;
    }

    return self;
}

+ (instancetype)openerWithArchiveURL:(NSURL *)archiveURL {
    return [[ENArchiveOpener alloc] initWithArchiveURL:archiveURL];
}

- (void)dealloc {
    [self.archive closeArchive];
}

#pragma mark -

- (BOOL)checkPassword:(NSString *)password {
    if (self.archive == nil) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            self.archive = [ENEncryptedArchive new];
            self.archive.delegate = self;
            self.archive.password = password;
            [self.archive openArchive:self.archivePath];
        });
    }
    else {
        self.archive.password = password;
    }

    self.passCheckingSemaphore = dispatch_semaphore_create(0);

    if (self.passValidationSemaphore)
        dispatch_semaphore_signal(self.passValidationSemaphore);

    dispatch_semaphore_wait(self.passCheckingSemaphore, DISPATCH_TIME_FOREVER);

    return self.validationResult;
}

#pragma mark Encrypted Archive delegate

- (void)encryptedArchive:(ENEncryptedArchive *)archive finishedOperation:(NSDictionary *)info {
    if ([info[kEncryptedArchiveOperation] isEqualToString:kEncryptedArchiveOperationOpening]) {
        self.validationResult = YES;

        if (self.archive.preview != nil) {
            _preview = [[NSImage alloc] initWithData:self.archive.preview];
        }
        else {
            NSArray *rootItems = [self.archive childRecordsAtPath:@"/"];

            if (rootItems.count) {
                _preview = [[NSWorkspace sharedWorkspace] iconForFileType:
                        rootItems.count > 1 ? ENFolderUTI : [rootItems.firstObject UTI]];
            }
        }

        _containsApplication = self.archive.includeApplications;

        [self.archive closeArchive];
        self.archive = nil;

        if (self.passCheckingSemaphore)
            dispatch_semaphore_signal(self.passCheckingSemaphore);
    }
}

- (void)encryptedArchive:(ENEncryptedArchive *)archive operationError:(NSDictionary *)info {
    if ([info[kEncryptedArchiveOperation] isEqualToString:kEncryptedArchiveOperationOpening]) {
        NSError *error = info[kEncryptedArchiveError];

        if ([self.delegate respondsToSelector:@selector(archiveOpener:didReportError:)])
            [self.delegate archiveOpener:self didReportError:error];

        self.validationResult = NO;
        self.archive = nil;

        if (self.passCheckingSemaphore)
            dispatch_semaphore_signal(self.passCheckingSemaphore);
    }
}

- (void)encryptedArchivePasswordNeeded:(ENEncryptedArchive *)archive cancel:(BOOL *)cancel {
    self.validationResult = NO;
    self.passValidationSemaphore = dispatch_semaphore_create(0);

    if (self.passCheckingSemaphore)
        dispatch_semaphore_signal(self.passCheckingSemaphore);

    dispatch_semaphore_wait(self.passValidationSemaphore, DISPATCH_TIME_FOREVER);
}

@end