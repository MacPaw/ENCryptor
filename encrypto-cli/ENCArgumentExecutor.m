//
//  ENCArgumentExecutor.m
//  ENCryptor
//
//  Created by Oleksii Pavlovskyi on 3/22/16.
//  Copyright © 2016 MacPaw. All rights reserved.
//

#import "ENCArgumentExecutor.h"
#import "ENCCommand.h"
#import "ENCLog.h"

@interface ENCArgumentExecutor ()

@property (nonatomic, strong) NSMutableDictionary <NSString *, NSRegularExpression *> *regularExpressions;
@property (nonatomic, assign) BOOL shouldExit;
@property (nonatomic, assign) NSInteger returnCode;

@end

@implementation ENCArgumentExecutor

- (instancetype)init {
    self = [super init];
    if (self) {
        self.regularExpressions = [NSMutableDictionary dictionary];
    }
    return self;
}

- (void)registerCommandClass:(Class)commandClass {
    NSString *regexFormat = [commandClass format];
    NSString *commandClassName = NSStringFromClass(commandClass);

    NSError *error = nil;
    NSRegularExpression *expression = [NSRegularExpression regularExpressionWithPattern:regexFormat options:0 error:&error];

    if (error)
        @throw [NSException exceptionWithName:@"ENCArgumentExecutorCommandRegistrationException"
                                       reason:@"Unable to parse command format."
                                     userInfo:nil];

    self.regularExpressions[commandClassName] = expression;
}

- (NSInteger)executeArguments:(NSString *)arguments {
    __block NSString *commandClassName = nil;
    __block NSArray *commandArguments = nil;

    [self.regularExpressions enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSRegularExpression *expression, BOOL *stop) {
        NSArray *matches = [expression matchesInString:arguments options:0 range:NSMakeRange(0, arguments.length)];
        if (matches.count > 0) {
            *stop = YES;
            commandClassName = key;

            NSMutableArray *mutableArguments = [NSMutableArray arrayWithCapacity:matches.count];

            for (NSTextCheckingResult *match in matches)
                for (NSUInteger rangeIdx = 1; rangeIdx < match.numberOfRanges; rangeIdx++) {
                    NSRange matchRange = [match rangeAtIndex:rangeIdx];
                    if (matchRange.location != NSNotFound) {
                        NSString *matchString = [arguments substringWithRange:matchRange];
                        [mutableArguments addObject:matchString];
                    }
                }

            commandArguments = mutableArguments.copy;
        }
    }];

    if (commandClassName) {
        __weak typeof(self) bSelf = self;
        ENCCommand *command = [[NSClassFromString(commandClassName) alloc] initWithArguments:commandArguments];
        [command performWithCompletion:^(NSInteger returnCode) {
            bSelf.returnCode = returnCode;
            bSelf.shouldExit = YES;
        }];

        while (!self.shouldExit && [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                                            beforeDate:[NSDate dateWithTimeIntervalSinceNow:1]]) {}
        return self.returnCode;
    } else {
        if (arguments.length > 0)
            ENCNamedLog(@"illegal arguments: %@", arguments);
        
        NSString *prefix = [NSString stringWithFormat:@"usage: %@ ", ENCProcessName()];
        NSString *padding = [NSString.string stringByPaddingToLength:prefix.length withString:@" " startingAtIndex:0];
        
        [self.regularExpressions.allKeys enumerateObjectsUsingBlock:^(NSString *className, NSUInteger idx, BOOL *_) {
            ENCLog(@"%@%@", idx == 0 ? prefix : padding, [NSClassFromString(className) helpMessage]);
        }];
        
        return 1;
    }
}

@end
