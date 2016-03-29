//
//  ENEncryptor.h
//  Encrypto
//
//  Created by tanlan on 05.12.14.
//  Copyright (c) 2014 MacPaw. All rights reserved.
//

@import Foundation;

NS_ASSUME_NONNULL_BEGIN

@protocol ENEncryptorDelegate;
@interface ENEncryptor : NSObject

- (instancetype)initWithSourceURLs:(NSArray <NSURL *> *)sourceURLs;
+ (instancetype)encryptorWithSourceURLs:(NSArray <NSURL *> *)sourceURLs;

@property (weak, nonatomic, nullable) id <ENEncryptorDelegate> delegate;

- (void)encryptWithPassword:(NSString *)password hint:(NSString *)hint preview:(nullable NSImage *)preview;
- (void)cancel;

@end

@protocol ENEncryptorDelegate <NSObject>
@optional

- (void)encryptor:(ENEncryptor *)encryptor didStartWithURLs:(NSArray *)sourceFiles;
- (void)encryptor:(ENEncryptor *)encryptor didFailWithError:(NSError *)error;
- (void)encryptor:(ENEncryptor *)encryptor didFinishWithResultURL:(NSURL *)resultURL;

- (void)encryptor:(ENEncryptor *)encryptor didUpdateProgress:(float)progress;
- (void)encryptor:(ENEncryptor *)encryptor didUpdateEstimationTime:(NSTimeInterval)estimationTime;

@end

NS_ASSUME_NONNULL_END