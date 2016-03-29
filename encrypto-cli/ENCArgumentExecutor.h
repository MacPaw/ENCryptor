//
//  ENCArgumentExecutor.h
//  ENCryptor
//
//  Created by Oleksii Pavlovskyi on 3/22/16.
//  Copyright © 2016 MacPaw. All rights reserved.
//

@import Foundation;

@interface ENCArgumentExecutor : NSObject

- (void)registerCommandClass:(Class)commandClass;
- (NSInteger)executeArguments:(NSString *)arguments;

@end
