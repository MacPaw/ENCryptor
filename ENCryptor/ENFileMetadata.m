//
//  ENFileMetadata.h
//  Encrypto
//
//  Created by tanlan on 11/8/13.
//  Copyright (c) 2013 MacPaw. All rights reserved.
//

#import "ENFileMetadata.h"
#import <sys/xattr.h>
#import <sys/attr.h>

@interface ENFileMetadata ()

@property (nonatomic, strong) NSDictionary *attributes;
@property (nonatomic, strong) NSDictionary *extendedAttributes;
@property (nonatomic, strong) NSData *extendedSecurityOptions;

@end

struct FInfoAttrBuf {
    uint32_t length;
    attribute_set_t returned_attrs;
    attrreference_t extended_security;
    guid_t owner;
    guid_t group;
    char buffer[4096];
};

@implementation ENFileMetadata

- (instancetype)init {
    return [self initWithFilePath:nil];
}

- (instancetype)initWithFilePath:(NSString *)filePath {
    if (filePath.length == 0)
        return nil;

    self = [super init];

    if (self) {
        _attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:filePath error:nil];
        _extendedAttributes = [self.class extendedAttributesOfFile:filePath];
        _extendedSecurityOptions = [self.class extendedSecurityOptionsOfFile:filePath];
    }

    return self;
}

+ (instancetype)metadataOfFile:(NSString *)filePath {
    return [[ENFileMetadata alloc] initWithFilePath:filePath];
}

#pragma mark -

+ (NSDictionary *)extendedAttributesOfFile:(NSString *)filePath {
    NSMutableDictionary *extendedAttributes = [NSMutableDictionary new];

    ssize_t listSize = listxattr(filePath.fileSystemRepresentation, NULL, 0, XATTR_NOFOLLOW);

    if (listSize < 0) {
        return nil;
    }

    char *attributesList = malloc(listSize + 1);
    listSize = listxattr(filePath.fileSystemRepresentation, attributesList, listSize, XATTR_NOFOLLOW);
    attributesList[listSize] = '\0';

    if (listSize < 0) {
        return nil;
    }

    size_t currentAttributeLength = 0;
    size_t attributeOffset = 0;
    while ((currentAttributeLength = strlen(attributesList + attributeOffset)) && currentAttributeLength + attributeOffset < listSize) {
        @autoreleasepool {
            char *currentAttribute = malloc(currentAttributeLength + 1);
            strcpy(currentAttribute, attributesList + attributeOffset);
            currentAttribute[currentAttributeLength] = '\0';
            attributeOffset += currentAttributeLength + 1;

            if (memcmp(currentAttribute, "com.apple.quarantine", currentAttributeLength)) {
                ssize_t currentValueSize = getxattr(filePath.fileSystemRepresentation, currentAttribute, NULL, 0, 0, XATTR_NOFOLLOW);

                if (currentValueSize > 0) {
                    void *currentValue = malloc(currentValueSize);
                    currentValueSize = getxattr(filePath.fileSystemRepresentation, currentAttribute, currentValue, currentValueSize, 0, XATTR_NOFOLLOW);

                    NSString *key = [NSString stringWithUTF8String:currentAttribute];
                    NSData *value = [NSData dataWithBytes:currentValue length:currentValueSize];

                    [extendedAttributes addEntriesFromDictionary:@{key : value}];

                    free(currentValue);
                }
            }

            free(currentAttribute);
        }
    }

    free(attributesList);

    return extendedAttributes;
}

+ (NSData *)extendedSecurityOptionsOfFile:(NSString *)filePath {
    int err;
    struct attrlist attrList;
    struct FInfoAttrBuf attrBuf;

    memset(&attrList, 0, sizeof(attrList));
    attrList.bitmapcount = ATTR_BIT_MAP_COUNT;
    attrList.commonattr = (ATTR_CMN_RETURNED_ATTRS
            | ATTR_CMN_EXTENDED_SECURITY
            | ATTR_CMN_UUID
            | ATTR_CMN_GRPUUID);

    err = getattrlist(filePath.fileSystemRepresentation, &attrList, &attrBuf, sizeof(attrBuf), 0);

    if (err < 0) {
        NSLog(@"Error getting extended security options for path %@ errno %i", filePath, errno);
        return nil;
    }

    NSData *data = [NSData dataWithBytes:&attrBuf length:sizeof(attrBuf)];

    return data;
}

#pragma mark -

+ (BOOL)applyExtendedAttributes:(NSDictionary *)attrs toFile:(NSString *)filePath {
    BOOL __block res = YES;
    [attrs enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        if (setxattr(filePath.fileSystemRepresentation,
                [(NSString *) key UTF8String], [(NSData *) obj bytes], [(NSData *) obj length], 0, XATTR_NOFOLLOW) < 0) {
            NSLog(@"[File Metadata]: can't set extended attribute %@ for file %@", key, filePath);
            res = NO;
        }
    }];

    return res;
}

+ (BOOL)applyExtendedSecurityOptions:(NSData *)options toFile:(NSString *)filePath {
    struct attrlist attrList;
    memset(&attrList, 0, sizeof(attrList));
    attrList.bitmapcount = ATTR_BIT_MAP_COUNT;
    attrList.commonattr = ATTR_CMN_EXTENDED_SECURITY;

    struct FInfoAttrBuf buffer;

    if (options.length > sizeof(attrList))
        return NO;
    memcpy(&buffer, options.bytes, options.length);
    BOOL res = YES;

    if ((buffer.returned_attrs.commonattr & ATTR_CMN_EXTENDED_SECURITY) && buffer.extended_security.attr_length > 0) {
        if (setattrlist(filePath.fileSystemRepresentation, &attrList, &buffer.extended_security, buffer.length, 0) < 0) {
            NSLog(@"Error setting extended security options for path %@ errno %i", filePath, errno);
            res = NO;
        }

        attrList.commonattr = ATTR_CMN_UUID;

        if (buffer.returned_attrs.commonattr & ATTR_CMN_UUID) {
            if (setattrlist(filePath.fileSystemRepresentation, &attrList, &buffer.owner, buffer.length, 0) < 0) {
                NSLog(@"Error setting owner UUID for path %@ errno %i", filePath, errno);
                res = NO;
            }
        }

        attrList.commonattr = ATTR_CMN_GRPUUID;

        if (buffer.returned_attrs.commonattr & ATTR_CMN_GRPUUID) {
            if (setattrlist(filePath.fileSystemRepresentation, &attrList, &buffer.group, buffer.length, 0) < 0) {
                NSLog(@"Error setting group UUID for path %@ errno %i", filePath, errno);
                res = NO;
            }
        }
    }

    return res;
}

#pragma mark -

- (instancetype)initWithAttributes:(NSDictionary *)attribs
                extendedAttributes:(NSDictionary *)extendedAttributes
           extendedSecurityOptions:(NSData *)extendedSecurityOptions {
    self = [super init];

    if (self) {
        self.attributes = attribs;
        self.extendedAttributes = extendedAttributes;
        self.extendedSecurityOptions = extendedSecurityOptions;
    }

    return self;
}

- (void)applyToFileAtPath:(NSString *)filePath {
    if (self.attributes != nil)
        [[NSFileManager defaultManager] setAttributes:self.attributes
                                         ofItemAtPath:filePath
                                                error:nil];

    if (self.extendedAttributes != nil)
        [[self class] applyExtendedAttributes:self.extendedAttributes toFile:filePath];

    if (self.extendedSecurityOptions != nil)
        [[self class] applyExtendedSecurityOptions:self.extendedSecurityOptions toFile:filePath];
}

@end
