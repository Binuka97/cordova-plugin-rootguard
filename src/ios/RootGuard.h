#import <Cordova/CDV.h>

@interface RootGuard : CDVPlugin

- (void)checkSecurity:(CDVInvokedUrlCommand*)command;
- (void)checkSecurityStatus:(CDVInvokedUrlCommand*)command;
- (void)checkSecurityDetailed:(CDVInvokedUrlCommand*)command;

@end
