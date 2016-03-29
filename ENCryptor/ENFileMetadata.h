//
//  ENFileMetadata.h
//  Encrypto
//
//  Created by tanlan on 11/8/13.
//  Copyright (c) 2013 MacPaw. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ENFileMetadata : NSObject

- (instancetype)initWithFilePath:(NSString *)filePath;
+ (instancetype)metadataOfFile:(NSString *)filePath;

+ (NSDictionary *)extendedAttributesOfFile:(NSString *)filePath;
+ (NSData *)extendedSecurityOptionsOfFile:(NSString *)filePath;

+ (BOOL)applyExtendedAttributes:(NSDictionary *)attrs toFile:(NSString *)filePath;
+ (BOOL)applyExtendedSecurityOptions:(NSData *)options toFile:(NSString *)filePath;

- (instancetype)initWithAttributes:(NSDictionary *)attributes
                extendedAttributes:(NSDictionary *)extendedAttributes
           extendedSecurityOptions:(NSData *)extendedSecurityOptions;

@property (nonatomic, readonly, strong) NSDictionary *attributes;
@property (nonatomic, readonly, strong) NSDictionary *extendedAttributes;
@property (nonatomic, readonly, strong) NSData *extendedSecurityOptions;

- (void)applyToFileAtPath:(NSString *)filePath;

@end
