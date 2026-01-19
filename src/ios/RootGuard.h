#import <Cordova/CDV.h>

@interface RootGuard : CDVPlugin

// This defines the method that Cordova will look for
- (void)checkSecurity:(CDVInvokedUrlCommand*)command;

@end