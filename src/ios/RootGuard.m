#import "RootGuard.h"

#import <Cordova/CDV.h>
#import <TargetConditionals.h>
#import <UIKit/UIKit.h>
#import <arpa/inet.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <netinet/in.h>
#import <pthread.h>
#import <limits.h>
#import <string.h>
#import <sys/proc.h>
#import <sys/select.h>
#import <sys/socket.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <unistd.h>

static const NSInteger RGStatusSafe = 0;
static const NSInteger RGStatusCompromised = 1;
static const NSInteger RGStatusUnknown = 2;

typedef NS_ENUM(NSInteger, RGSignalState) {
    RGSignalClear,
    RGSignalDetected,
    RGSignalUnavailable
};

typedef NS_ENUM(NSInteger, RGSignalStrength) {
    RGSignalMedium,
    RGSignalHigh
};

@implementation RootGuard

- (void)checkSecurity:(CDVInvokedUrlCommand *)command {
    [self runAssessmentForAction:@"checkSecurity" command:command];
}

- (void)checkSecurityStatus:(CDVInvokedUrlCommand *)command {
    [self runAssessmentForAction:@"checkSecurityStatus" command:command];
}

- (void)checkSecurityDetailed:(CDVInvokedUrlCommand *)command {
    [self runAssessmentForAction:@"checkSecurityDetailed" command:command];
}

- (void)runAssessmentForAction:(NSString *)action command:(CDVInvokedUrlCommand *)command {
    [self.commandDelegate runInBackground:^{
        NSDictionary *assessment;
        @try {
            assessment = [self assessment];
        } @catch (__unused NSException *exception) {
            assessment = @{
                @"status": @(RGStatusUnknown),
                @"statusName": @"UNKNOWN",
                @"platform": @"ios",
                @"osVersion": [UIDevice currentDevice].systemVersion ?: @"",
                @"evidence": @[],
                @"unavailableChecks": @[@"assessment"],
                @"localOnly": @YES
            };
        }

        NSInteger status = [assessment[@"status"] integerValue];
        CDVPluginResult *result;
        if ([action isEqualToString:@"checkSecurity"]) {
            // Preserve the historical binary contract. UNKNOWN is not a reason to
            // lock out an existing application after a plugin upgrade.
            result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                          messageAsInt:(status == RGStatusCompromised ? 1 : 0)];
        } else if ([action isEqualToString:@"checkSecurityStatus"]) {
            result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsInt:(int)status];
        } else {
            result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                   messageAsDictionary:assessment];
        }
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
    }];
}

- (NSDictionary *)assessment {
    NSMutableArray<NSDictionary *> *signals = [NSMutableArray array];

#if TARGET_OS_SIMULATOR
    [signals addObject:[self signal:@"simulator" category:@"environment"
                                state:RGSignalUnavailable strength:RGSignalHigh]];
#else
    [signals addObject:[self checkJailbreakArtifacts]];
    [signals addObject:[self checkSandboxEscape]];
    [signals addObject:[self checkInjectedEnvironment]];
    [signals addObject:[self checkLoadedImages]];
    [signals addObject:[self checkFridaSymbols]];
    [signals addObject:[self checkSuspiciousThreads]];
    [signals addObject:[self checkSuspiciousFileDescriptors]];
    [signals addObject:[self checkDebugger]];
    [signals addObject:[self checkFridaProtocol]];
#endif

    NSInteger high = 0;
    NSInteger medium = 0;
    BOOL criticalUnavailable = NO;
    NSMutableArray<NSString *> *evidence = [NSMutableArray array];
    NSMutableArray<NSString *> *unavailable = [NSMutableArray array];

    for (NSDictionary *signal in signals) {
        RGSignalState state = [signal[@"state"] integerValue];
        if (state == RGSignalDetected) {
            [evidence addObject:signal[@"id"]];
            if ([signal[@"strength"] integerValue] == RGSignalHigh) high++;
            else medium++;
        } else if (state == RGSignalUnavailable) {
            [unavailable addObject:signal[@"id"]];
            if ([signal[@"strength"] integerValue] == RGSignalHigh) criticalUnavailable = YES;
        }
    }

    NSInteger status;
    if (high > 0 || medium >= 2) status = RGStatusCompromised;
    else if (medium == 1 || criticalUnavailable) status = RGStatusUnknown;
    else status = RGStatusSafe;

    return @{
        @"status": @(status),
        @"statusName": [self statusName:status],
        @"platform": @"ios",
        @"osVersion": [UIDevice currentDevice].systemVersion ?: @"",
        @"evidence": evidence,
        @"unavailableChecks": unavailable,
        @"localOnly": @YES
    };
}

- (NSDictionary *)checkJailbreakArtifacts {
    // Do not check generic /private/preboot: it exists on stock modern iOS.
    const char *paths[] = {
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/usr/lib/TweakInject",
        "/usr/lib/libsubstrate.dylib",
        "/usr/sbin/sshd",
        "/var/jb/usr/bin/su",
        "/var/jb/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/var/jb/basebin/jbctl",
        "/opt/procursus/bin/apt",
        "/private/var/lib/apt"
    };

    for (NSUInteger index = 0; index < sizeof(paths) / sizeof(paths[0]); index++) {
        if (access(paths[index], F_OK) == 0) {
            return [self signal:@"jailbreak_artifact" category:@"jailbreak"
                          state:RGSignalDetected strength:RGSignalHigh];
        }
    }
    return [self signal:@"jailbreak_artifact" category:@"jailbreak"
                  state:RGSignalClear strength:RGSignalHigh];
}

- (NSDictionary *)checkSandboxEscape {
    const char *path = "/private/.rootguard-sandbox-test";
    int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (descriptor >= 0) {
        close(descriptor);
        unlink(path);
        return [self signal:@"sandbox_escape" category:@"jailbreak"
                      state:RGSignalDetected strength:RGSignalHigh];
    }
    return [self signal:@"sandbox_escape" category:@"jailbreak"
                  state:RGSignalClear strength:RGSignalHigh];
}

- (NSDictionary *)checkInjectedEnvironment {
    const char *value = getenv("DYLD_INSERT_LIBRARIES");
    BOOL detected = value != NULL && strlen(value) > 0;
    return [self signal:@"dyld_environment" category:@"instrumentation"
                  state:(detected ? RGSignalDetected : RGSignalClear)
               strength:RGSignalHigh];
}

- (NSDictionary *)checkLoadedImages {
    uint32_t count = _dyld_image_count();
    for (uint32_t index = 0; index < count; index++) {
        const char *name = _dyld_get_image_name(index);
        if (name && [self containsInstrumentationMarker:name]) {
            return [self signal:@"instrumentation_image" category:@"instrumentation"
                          state:RGSignalDetected strength:RGSignalHigh];
        }
    }
    return [self signal:@"instrumentation_image" category:@"instrumentation"
                  state:RGSignalClear strength:RGSignalHigh];
}

- (NSDictionary *)checkFridaSymbols {
    const char *symbols[] = {
        "frida_agent_main",
        "frida_gadget_load",
        "gum_init_embedded",
        "gum_script_backend_create_sync"
    };
    for (NSUInteger index = 0; index < sizeof(symbols) / sizeof(symbols[0]); index++) {
        if (dlsym(RTLD_DEFAULT, symbols[index]) != NULL) {
            return [self signal:@"instrumentation_symbol" category:@"instrumentation"
                          state:RGSignalDetected strength:RGSignalHigh];
        }
    }
    return [self signal:@"instrumentation_symbol" category:@"instrumentation"
                  state:RGSignalClear strength:RGSignalHigh];
}

- (NSDictionary *)checkSuspiciousThreads {
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    if (task_threads(mach_task_self(), &threads, &count) != KERN_SUCCESS) {
        return [self signal:@"instrumentation_thread" category:@"instrumentation"
                      state:RGSignalUnavailable strength:RGSignalHigh];
    }

    BOOL detected = NO;
    for (mach_msg_type_number_t index = 0; index < count; index++) {
        pthread_t thread = pthread_from_mach_thread_np(threads[index]);
        char name[128] = {0};
        if (thread && pthread_getname_np(thread, name, sizeof(name)) == 0
                && [self containsInstrumentationMarker:name]) {
            detected = YES;
        }
        mach_port_deallocate(mach_task_self(), threads[index]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof(thread_t));

    return [self signal:@"instrumentation_thread" category:@"instrumentation"
                  state:(detected ? RGSignalDetected : RGSignalClear)
               strength:RGSignalHigh];
}

- (NSDictionary *)checkSuspiciousFileDescriptors {
    for (int descriptor = 0; descriptor < 256; descriptor++) {
        char path[PATH_MAX] = {0};
        if (fcntl(descriptor, F_GETPATH, path) == 0 && [self containsInstrumentationMarker:path]) {
            return [self signal:@"instrumentation_fd" category:@"instrumentation"
                          state:RGSignalDetected strength:RGSignalHigh];
        }
    }
    return [self signal:@"instrumentation_fd" category:@"instrumentation"
                  state:RGSignalClear strength:RGSignalHigh];
}

- (NSDictionary *)checkDebugger {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc processInfo;
    memset(&processInfo, 0, sizeof(processInfo));
    size_t size = sizeof(processInfo);
    if (sysctl(mib, 4, &processInfo, &size, NULL, 0) != 0) {
        return [self signal:@"debugger" category:@"instrumentation"
                      state:RGSignalUnavailable strength:RGSignalMedium];
    }
    BOOL traced = (processInfo.kp_proc.p_flag & P_TRACED) != 0;
    return [self signal:@"debugger" category:@"instrumentation"
                  state:(traced ? RGSignalDetected : RGSignalClear)
               strength:RGSignalMedium];
}

- (NSDictionary *)checkFridaProtocol {
    int ports[] = {27042, 27043};
    BOOL openPort = NO;
    for (NSUInteger index = 0; index < sizeof(ports) / sizeof(ports[0]); index++) {
        int socketFd = socket(AF_INET, SOCK_STREAM, 0);
        if (socketFd < 0) continue;

        int flags = fcntl(socketFd, F_GETFL, 0);
        if (flags < 0 || fcntl(socketFd, F_SETFL, flags | O_NONBLOCK) < 0) {
            close(socketFd);
            continue;
        }

        struct sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons((uint16_t)ports[index]);
        connect(socketFd, (struct sockaddr *)&address, sizeof(address));

        fd_set writeSet;
        FD_ZERO(&writeSet);
        FD_SET(socketFd, &writeSet);
        struct timeval timeout = {.tv_sec = 0, .tv_usec = 100000};
        if (select(socketFd + 1, NULL, &writeSet, NULL, &timeout) > 0) {
            int error = 0;
            socklen_t errorLength = sizeof(error);
            if (getsockopt(socketFd, SOL_SOCKET, SO_ERROR, &error, &errorLength) == 0 && error == 0) {
                openPort = YES;
                const char probe[] = "\0AUTH\r\n";
                send(socketFd, probe, sizeof(probe) - 1, 0);

                fd_set readSet;
                FD_ZERO(&readSet);
                FD_SET(socketFd, &readSet);
                timeout.tv_sec = 0;
                timeout.tv_usec = 100000;
                if (select(socketFd + 1, &readSet, NULL, NULL, &timeout) > 0) {
                    char response[96] = {0};
                    ssize_t length = recv(socketFd, response, sizeof(response) - 1, 0);
                    if (length > 0) {
                        NSString *banner = [[[NSString alloc] initWithBytes:response
                                                                    length:(NSUInteger)length
                                                                  encoding:NSASCIIStringEncoding] uppercaseString];
                        if ([banner containsString:@"REJECTED"] || [banner containsString:@"OK"]
                                || [banner containsString:@"AGREE"]) {
                            close(socketFd);
                            return [self signal:@"frida_protocol" category:@"instrumentation"
                                          state:RGSignalDetected strength:RGSignalHigh];
                        }
                    }
                }
            }
        }
        close(socketFd);
    }
    return [self signal:@"frida_protocol" category:@"instrumentation"
                  state:(openPort ? RGSignalDetected : RGSignalClear)
               strength:RGSignalMedium];
}

- (BOOL)containsInstrumentationMarker:(const char *)value {
    if (value == NULL) return NO;
    NSString *text = [[[NSString alloc] initWithUTF8String:value] lowercaseString];
    return [text containsString:@"frida"]
        || [text containsString:@"gum-js"]
        || [text containsString:@"linjector"]
        || [text containsString:@"/re.frida."];
}

- (NSDictionary *)signal:(NSString *)identifier
                category:(NSString *)category
                   state:(RGSignalState)state
                strength:(RGSignalStrength)strength {
    return @{
        @"id": identifier,
        @"category": category,
        @"state": @(state),
        @"strength": @(strength)
    };
}

- (NSString *)statusName:(NSInteger)status {
    if (status == RGStatusCompromised) return @"COMPROMISED";
    if (status == RGStatusUnknown) return @"UNKNOWN";
    return @"SAFE";
}

@end
