//
//  ENCCommand.m
//  ENCryptor
//
//  Created by Oleksii Pavlovskyi on 3/22/16.
//  Copyright © 2016 MacPaw. All rights reserved.
//

#import "ENCCommand.h"

@implementation ENCCommand

- (instancetype)initWithArguments:(NSArray<NSString *> *)arguments {
    self = [super init];
    return self;
}

- (void)performWithCompletion:(void (^)(NSInteger returnCode))completion {
    completion(NSNotFound);
}

+ (NSString *)format {
    return @"";
}

+ (NSString *)helpMessage {
    return @"";
}

@end
