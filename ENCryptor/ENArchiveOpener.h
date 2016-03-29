//
//  ENArchiveOpener.h
//  Encrypto
//
//  Created by tanlan on 26.01.15.
//  Copyright (c) 2015 MacPaw. All rights reserved.
//

NS_ASSUME_NONNULL_BEGIN

@import Foundation;
@class ENArchiveOpener;

@protocol ENArchiveOpenerDelegate <NSObject>

- (void)archiveOpener:(ENArchiveOpener *)opener didReportError:(NSError *)error;

@end

@interface ENArchiveOpener : NSObject

- (instancetype)initWithArchiveURL:(NSURL *)archiveURL;
+ (instancetype)openerWithArchiveURL:(NSURL *)archiveURL;

@property (strong, readonly, nonatomic) NSString *hint;
@property (strong, readonly, nonatomic) NSImage *preview;
@property (assign, readonly, nonatomic) BOOL containsApplication;

@property (weak, nonatomic, nullable) id <ENArchiveOpenerDelegate> delegate;

- (BOOL)checkPassword:(NSString *)password;

@end

NS_ASSUME_NONNULL_END