//
//  ENCEncryptCommand.m
//  ENCryptor
//
//  Created by Oleksii Pavlovskyi on 3/24/16.
//  Copyright © 2016 MacPaw. All rights reserved.
//

#import "ENCEncryptCommand.h"
#import "NSURL+Additions.h"
#import "ENCLog.h"
#import "readpassphrase.h"
@import ENCryptor;

@interface ENCEncryptCommand () <ENEncryptorDelegate>

@property NSString *inputPath;
@property NSString *outputPath;

@property ENEncryptor *encryptor;
@property void (^completion)(NSInteger);

@end

@implementation ENCEncryptCommand

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
        self.completion = completion;
        self.encryptor = [ENEncryptor encryptorWithSourceURLs:@[resolvedInputURL]];
        self.encryptor.delegate = self;
        
        NSFileHandle *input = [NSFileHandle fileHandleWithStandardInput];
        NSFileHandle *output = [NSFileHandle fileHandleWithStandardOutput];
        
        [output writeData:[@"Enter hint 👉  " dataUsingEncoding:NSUTF8StringEncoding]];
        NSString *hint = [[NSString alloc] initWithData:input.availableData encoding:NSUTF8StringEncoding];
        
        NSString *password = nil;
        BOOL passwordsMatch;
        char passwordBuffer[8192];
        do {
            NSString *attempt1 = [NSString stringWithCString:readpassphrase("Enter password 🤐  ",
                                                                            passwordBuffer,
                                                                            sizeof(passwordBuffer),
                                                                            RPP_REQUIRE_TTY)
                                                    encoding:NSUTF8StringEncoding];
            
            NSString *attempt2 = [NSString stringWithCString:readpassphrase("Verify password 🕵  ",
                                                                            passwordBuffer,
                                                                            sizeof(passwordBuffer),
                                                                            RPP_REQUIRE_TTY)
                                                    encoding:NSUTF8StringEncoding];
            
            passwordsMatch = [attempt1 isEqualToString:attempt2];
            if (!passwordsMatch)
                printf("Passwords don't match, please try again\n");
            else
                password = attempt1;
            
        } while (!passwordsMatch);
        
        [self.encryptor encryptWithPassword:password hint:hint preview:nil];
    } else {
        ENCNamedLog(@"😞  %@: no such file or directory", self.inputPath.lastPathComponent);
        completion(1);
    }
}

#pragma mark - ENEncryptorDelegate

- (void)encryptor:(ENEncryptor *)encryptor didUpdateProgress:(float)progress {
    if (progress > 0.0)
        printf("\033[A\033[2K");
    
    ENCNamedLog(@"🤔  encrypting... %g%%", progress);
}

- (void)encryptor:(ENEncryptor *)encryptor didFailWithError:(NSError *)error {
    ENCNamedLog(@"😞  encrypting failed with error: %@", error.localizedDescription);
    self.completion(1);
}

- (void)encryptor:(ENEncryptor *)encryptor didFinishWithResultURL:(NSURL *)resultURL {
    NSURL *resolvedOutputURL = [NSURL enc_resolvedURLWithPath:self.outputPath];
    if (resolvedOutputURL) {
        NSURL *moveURL = [resolvedOutputURL URLByAppendingPathComponent:resultURL.lastPathComponent];
        NSError *movingError = nil;

        [[NSFileManager defaultManager] moveItemAtURL:resultURL toURL:moveURL
                                                error:&movingError];

        if (movingError == nil) {
            ENCNamedLog(@"😎  encrypting completed with file at path: %@", moveURL.path);
            self.completion(0);
        } else {
            ENCNamedLog(@"😞  encrypting failed with error: %@", movingError.localizedDescription);
            self.completion(1);
        }
    } else {
        ENCNamedLog(@"😞  %@: no such file or directory", self.outputPath.lastPathComponent);
        self.completion(1);
    }
}

+ (NSString *)format {
    return @"encrypt (.+) (?:--output|-o) (.+)";
}

+ (NSString *)helpMessage {
    return @"encrypt <input> --output <output folder>";
}

@end
