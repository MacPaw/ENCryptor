//
//  main.m
//  encrypto-cli
//
//  Created by Oleksii Pavlovskyi on 3/22/16.
//  Copyright © 2016 MacPaw. All rights reserved.
//

@import Foundation;
@import ENCryptor;
#import "ENCArgumentExecutor.h"
#import "ENCPreviewCommand.h"
#import "ENCEncryptCommand.h"
#import "ENCDecryptCommand.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSArray *arguments = [[NSProcessInfo processInfo] arguments];
        NSString *joinedArguments = [[arguments subarrayWithRange:NSMakeRange(1, arguments.count - 1)] componentsJoinedByString:@" "];
        ENCArgumentExecutor *executor = [ENCArgumentExecutor new];
        [executor registerCommandClass:[ENCPreviewCommand class]];
        [executor registerCommandClass:[ENCEncryptCommand class]];
        [executor registerCommandClass:[ENCDecryptCommand class]];
        
        return (int)[executor executeArguments:joinedArguments];
    }
}
