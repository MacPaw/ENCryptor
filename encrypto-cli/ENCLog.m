//
//  ENCLog.m
//  ENCryptor
//
//  Created by Oleksii Pavlovskyi on 3/28/16.
//  Copyright © 2016 MacPaw. All rights reserved.
//

#import "ENCLog.h"

@implementation ENCLog

+ (void)namedLogWithFormat:(NSString *)format, ...{
    va_list args;
    va_start(args, format);
    NSString *processName = ENCProcessName();
    NSString *logFormat = [NSString stringWithFormat:@"%@: %@", processName, format];
    NSString *message = [[NSString alloc] initWithFormat:logFormat arguments:args];
    ENCLog(@"%@", message);
    va_end(args);
}

@end
