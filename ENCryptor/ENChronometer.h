//
//  ENChronometer.h
//  Encrypto
//
//  Created by tanlan on 05.09.14.
//  Copyright (c) 2014 MacPaw. All rights reserved.
//

#import <Foundation/Foundation.h>

@protocol ENChronometerDelegate;

@interface ENChronometer : NSObject

@property (nonatomic, weak) id <ENChronometerDelegate> delegate;
@property (nonatomic, assign, readonly) double remainingTime;

- (void)start;
- (void)updateProgress:(double)progress;
- (void)stop;

- (BOOL)isMeasuring;

@end

@protocol ENChronometerDelegate <NSObject>

@optional
- (void)chronometer:(ENChronometer *)chronometer didUpdateRemainingTime:(double)remainingTime;

@end
