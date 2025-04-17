#import <Cordova/CDV.h>
#import <sys/stat.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <sys/sysctl.h>
#import <UIKit/UIKit.h>

@interface RootGuard : CDVPlugin
- (void)checkSecurity:(CDVInvokedUrlCommand*)command;
@end

@implementation RootGuard

- (void)checkSecurity:(CDVInvokedUrlCommand*)command {
    BOOL compromised = [self isJailbroken] || [self isFridaDetected];
    CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsInt:(compromised ? 1 : 0)];
    [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
}

- (BOOL)isJailbroken {
#if TARGET_IPHONE_SIMULATOR
    return NO;
#else
    NSArray *paths = @[
        @"/Applications/Cydia.app",
        @"/Applications/Sileo.app",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/bin/bash",
        @"/usr/sbin/sshd",
        @"/etc/apt",
        @"/private/var/lib/apt/",
        @"/private/var/tmp/cydia.log",
        @"/var/lib/sileo",
        @"/var/jb",
        @"/usr/libexec/sileo",
        @"/opt/procursus" // rootless package manager location
    ];

    for (NSString *path in paths) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
            return YES;
        }
    }

    FILE *f = fopen("/bin/bash", "r");
    if (f != NULL) {
        fclose(f);
        return YES;
    }

    NSArray *urlSchemes = @[@"cydia://", @"sileo://"];
    for (NSString *scheme in urlSchemes) {
        NSURL *url = [NSURL URLWithString:scheme];
        if ([[UIApplication sharedApplication] canOpenURL:url]) {
            return YES;
        }
    }

    return NO;
#endif
}

- (BOOL)isFridaDetected {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *imageName = _dyld_get_image_name(i);
        if (imageName && (strstr(imageName, "frida") || strstr(imageName, "gum-js-loop"))) {
            return YES;
        }
    }
    return NO;
}

@end
