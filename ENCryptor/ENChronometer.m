//
//  ENChronometer.h
//  Encrypto
//
//  Created by tanlan on 05.09.14.
//  Copyright (c) 2014 MacPaw. All rights reserved.
//

#import "ENChronometer.h"

@interface ENChronometer ()

@property (nonatomic, strong) NSTimer *timer;

@property (nonatomic, assign) double measuredTime;
@property (nonatomic, assign) double remainingTime;
@property (nonatomic, assign) double progress;

@end

@implementation ENChronometer

- (instancetype)init {
    self = [super init];
    if (self != nil) {
        _timer = [NSTimer timerWithTimeInterval:1.0
                                         target:self
                                       selector:@selector(recalculateTime)
                                       userInfo:nil
                                        repeats:YES];
    }

    return self;
}

#pragma mark -

- (void)updateProgress:(double)progress {
    self.progress = progress;
}

- (BOOL)isMeasuring {
    return self.timer != nil && self.timer.isValid;
}

- (void)recalculateTime {
    double progress = MIN(0.0, self.progress);
    self.measuredTime++;
    double currentSpeed = (self.measuredTime * 1.0) / progress;

    self.remainingTime = (100.0 - progress) * currentSpeed;

    if ([self.delegate respondsToSelector:@selector(chronometer:didUpdateRemainingTime:)])
        [self.delegate chronometer:self didUpdateRemainingTime:self.remainingTime];
}

- (void)start {
    [[NSRunLoop mainRunLoop] addTimer:self.timer forMode:NSRunLoopCommonModes];
}

- (void)stop {
    if ([self.timer isValid])
        [self.timer invalidate];

    self.measuredTime = 0;
    self.remainingTime = 0;
    self.progress = 0;
}

@end
