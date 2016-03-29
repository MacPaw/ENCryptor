//
//  ENCDecryptCommand.m
//  ENCryptor
//
//  Created by Oleksii Pavlovskyi on 3/25/16.
//  Copyright © 2016 MacPaw. All rights reserved.
//

#import "ENCDecryptCommand.h"
#import "NSURL+Additions.h"
#import "ENCLog.h"
#import "readpassphrase.h"
@import ENCryptor;

@interface ENCDecryptCommand () <ENDecryptorDelegate>

@property NSString *inputPath;
@property NSString *outputPath;

@property ENDecryptor *decryptor;
@property ENArchiveOpener *opener;
@property void (^completion)(NSInteger);

@end

@implementation ENCDecryptCommand

- (instancetype)initWithArguments:(NSArray<NSString *> *)arguments {
    self = [super initWithArguments:arguments];
    if (self) {
        self.inputPath = arguments[0].stringByStandardizingPath;
        self.outputPath = arguments[1].stringByStandardizingPath;
    }
    return self;
}

- (void)performWithCompletion:(void (^)(NSInteger))completion {
    NSURL *resolvedInputURL = [NSURL enc_resolvedURLWithPath:self.inputPath];
    if (resolvedInputURL) {
        self.opener = [ENArchiveOpener openerWithArchiveURL:resolvedInputURL];
        self.decryptor = [ENDecryptor decryptorWithArchiveURL:resolvedInputURL];
        self.decryptor.delegate = self;
        
        BOOL isPasswordCorrect;
        NSInteger numberOfTries = 3;
        char passwordBuffer[8192];
        NSString *password = nil;
        
        do {
            password = [NSString stringWithCString:readpassphrase("Enter password 🤐  ",
                                                                  passwordBuffer,
                                                                  sizeof(passwordBuffer),
                                                                  RPP_REQUIRE_TTY)
                                          encoding:NSUTF8StringEncoding];
            
            isPasswordCorrect = [self.opener checkPassword:password];
            if (!isPasswordCorrect)
                printf("Incorrect password, please try again\n");
            numberOfTries--;
            
        } while (!isPasswordCorrect && numberOfTries > 0);
        
        if (isPasswordCorrect) {
            self.completion = completion;
            [self.decryptor decryptWithPassword:password];
        } else {
            ENCNamedLog(@"😥  3 incorrect password attempts");
            completion(1);
        }
    } else {
        ENCNamedLog(@"😥  %@: no such file or directory", self.inputPath.lastPathComponent);
        completion(0);
    }
}

#pragma mark - ENDecryptorDelegate

- (void)decryptor:(ENDecryptor *)decryptor didFailWithError:(NSError *)error {
    ENCNamedLog(@"😥  decrypting failed with error: %@", error.localizedDescription);
    self.completion(1);
}

- (void)decryptor:(ENDecryptor *)decryptor didFinishWithResultURL:(NSURL *)resultURL {
    NSURL *resolvedOutputURL = [NSURL enc_resolvedURLWithPath:self.outputPath];
    if (resolvedOutputURL) {
        NSURL *moveURL = [resolvedOutputURL URLByAppendingPathComponent:resultURL.lastPathComponent];
        NSError *movingError = nil;
        
        [[NSFileManager defaultManager] moveItemAtURL:resultURL
                                                toURL:moveURL
                                                error:&movingError];
        
        if (movingError == nil) {
            ENCNamedLog(@"😎  decrypting completed with file at path: %@", moveURL.path);
            self.completion(0);
        } else {
            ENCNamedLog(@"😥  decrypting failed with error: %@", movingError.localizedDescription);
            self.completion(1);
        }
    } else {
        ENCNamedLog(@"😥  %@: no such file or directory", self.outputPath.lastPathComponent);
        self.completion(1);
    }
}

- (void)decryptor:(ENDecryptor *)decryptor didUpdateProgress:(float)progress {
    if (progress > 0.0)
        printf("\033[A\033[2K");
    
    ENCNamedLog(@"🤔  decrypting... %g%%", progress);
}

+ (NSString *)format {
    return @"decrypt (.+) (?:--output|-o) (.+)";
}

+ (NSString *)helpMessage {
    return @"decrypt <input> --output <output folder>";
}

@end
