//
//  ENCLog.h
//  ENCryptor
//
//  Created by Oleksii Pavlovskyi on 3/28/16.
//  Copyright © 2016 MacPaw. All rights reserved.
//

@import Foundation;

#define ENCProcessName() [[[NSProcessInfo processInfo] arguments][0] lastPathComponent]
#define ENCLog(format, ...) printf("%s\n", [[NSString stringWithFormat:format, ## __VA_ARGS__] UTF8String])
#define ENCNamedLog(format, ...) [ENCLog namedLogWithFormat:format, ## __VA_ARGS__]

@interface ENCLog : NSObject

+ (void)namedLogWithFormat:(NSString *)format, ...;

@end
