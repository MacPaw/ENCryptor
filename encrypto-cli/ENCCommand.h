//
//  ENCCommand.h
//  ENCryptor
//
//  Created by Oleksii Pavlovskyi on 3/22/16.
//  Copyright © 2016 MacPaw. All rights reserved.
//

@import Foundation;

@interface ENCCommand : NSObject

- (instancetype)initWithArguments:(NSArray <NSString *> *)arguments;
- (void)performWithCompletion:(void (^)(NSInteger returnCode))completion;

+ (NSString *)format;
+ (NSString *)helpMessage;

@end
