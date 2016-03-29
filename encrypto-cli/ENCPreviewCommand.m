//
//  ENCPreviewCommand.m
//  ENCryptor
//
//  Created by Oleksii Pavlovskyi on 3/22/16.
//  Copyright © 2016 MacPaw. All rights reserved.
//

#import "ENCPreviewCommand.h"
#import "NSURL+Additions.h"
#import "ENCLog.h"
@import ENCryptor;

@interface ENCPreviewCommand () <ENArchiveOpenerDelegate>

@property NSString *inputPath;
@property ENArchiveOpener *archiveOpener;

@end

@implementation ENCPreviewCommand

- (instancetype)initWithArguments:(NSArray<NSString *> *)arguments {
    self = [super initWithArguments:arguments];
    if (self) {
        self.inputPath = arguments.firstObject.stringByStandardizingPath;
    }
    return self;
}

- (void)performWithCompletion:(void (^)(NSInteger returnCode))completion {
    NSURL *resolvedURL = [NSURL enc_resolvedURLWithPath:self.inputPath];
    if (resolvedURL) {
        self.archiveOpener = [ENArchiveOpener openerWithArchiveURL:resolvedURL];
        self.archiveOpener.delegate = self;
        
        ENCNamedLog(@"😉  %@ hint: %@", resolvedURL.lastPathComponent, self.archiveOpener.hint);
        completion(0);
    } else {
        ENCNamedLog(@"🙁  %@: no such file or directory", self.inputPath.lastPathComponent);
        completion(1);
    }
}

#pragma mark - ENArchiveOpenerDelegate

- (void)archiveOpener:(ENArchiveOpener *)opener didReportError:(NSError *)error {
    ENCNamedLog(@"🙁  preview error occured: %@", error.localizedDescription);
}

+ (NSString *)format {
    return @"preview (.+)";
}

+ (NSString *)helpMessage {
    return @"preview <input>";
}

@end
