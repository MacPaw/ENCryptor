//
//  NSURL+Additions.m
//  ENCryptor
//
//  Created by Oleksii Pavlovskyi on 3/28/16.
//  Copyright © 2016 MacPaw. All rights reserved.
//

#import "NSURL+Additions.h"

@implementation NSURL (Additions)

+ (instancetype)enc_resolvedURLWithPath:(NSString *)path {
    const char *resolvedPath = realpath([path cStringUsingEncoding:NSUTF8StringEncoding], NULL);
    if (resolvedPath)
        return [self fileURLWithPath:[NSString stringWithCString:resolvedPath encoding:NSUTF8StringEncoding]];

    return nil;
}

@end
