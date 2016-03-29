//
//  NSURL+Additions.h
//  ENCryptor
//
//  Created by Oleksii Pavlovskyi on 3/28/16.
//  Copyright © 2016 MacPaw. All rights reserved.
//

@import Foundation;

@interface NSURL (Additions)

+ (instancetype)enc_resolvedURLWithPath:(NSString *)path;

@end
