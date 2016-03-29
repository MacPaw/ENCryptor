//
//  ENDecryptor.h
//  Encrypto
//
//  Created by tanlan on 08.12.14.
//  Copyright (c) 2014 MacPaw. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@protocol ENDecryptorDelegate;

@interface ENDecryptor : NSObject

- (instancetype)initWithArchiveURL:(NSURL *)archiveURL;
+ (instancetype)decryptorWithArchiveURL:(NSURL *)archiveURL;

@property (nonatomic, weak, nullable) id <ENDecryptorDelegate> delegate;
@property (nonatomic, strong, readonly) NSString *rootName;
@property (nonatomic, strong, readonly) NSString *hint;

- (void)decryptWithPassword:(NSString *)password;
- (void)cancel;

@end

@protocol ENDecryptorDelegate <NSObject>

@optional
- (void)decryptor:(ENDecryptor *)decryptor didStartWithArchiveURL:(NSURL *)archiveURL;
- (void)decryptor:(ENDecryptor *)decryptor didFailWithError:(NSError *)error;
- (void)decryptor:(ENDecryptor *)decryptor didFinishWithResultURL:(NSURL *)resultURL;
- (void)decryptor:(ENDecryptor *)decryptor didUpdateProgress:(float)progress;
- (void)decryptor:(ENDecryptor *)decryptor didUpdateEstimationTime:(NSTimeInterval)estimationTime;

@end

NS_ASSUME_NONNULL_END