//
//  NSFileManager+MHAdditions.h
//  Encrypto
//
//  Created by tanlan on 10/8/13.
//  Copyright (c) 2013 MacPaw. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSFileManager (Additions)

- (BOOL)en_ftsWalkAtPath:(NSString *)path
                 handler:(void (^)(NSString *currentPath, BOOL isRoot, NSUInteger size, BOOL *cancelled))handler;

- (NSURL *)en_createUniqueTemporaryDirectory;
- (NSURL *)en_rootURLForURLs:(NSArray *)urls;

@end

@interface NSFileManager (SystemPaths)

+ (NSURL *)en_userLibraryURL;
+ (NSURL *)en_temporaryDirectoryURL;

@end

@interface NSFileManager (Rights)

- (BOOL)en_checkSourceReadability:(NSURL *)sourceURL failedFile:(NSString **)failedFilePath;

@end
