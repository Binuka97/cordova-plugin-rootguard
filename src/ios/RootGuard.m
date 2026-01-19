#import "RootGuard.h"
#import <Cordova/CDV.h>
#import <sys/stat.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <sys/sysctl.h>
#import <UIKit/UIKit.h>
#import <fcntl.h>
#import <unistd.h>
#import <arpa/inet.h>
#import <libproc.h>
#import <sys/proc_info.h>
#import <pthread.h>
#import <mach/mach.h>
#include <ctype.h>

@implementation RootGuard

- (void)checkSecurity:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        BOOL compromised = [self isJailbroken] || [self isFridaDetected] || [self checkFridaPipes];
        
        CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK 
                                                       messageAsInt:(compromised ? 1 : 0)];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
    }];
}

#pragma mark - Jailbreak Detection (Low-Level)

- (BOOL)isJailbroken {
#if TARGET_IPHONE_SIMULATOR
    return NO;
#else
    // 1. Path check using access() instead of NSFileManager (Harder to hook)
    const char* paths[] = {
        "/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app",
        "/usr/sbin/sshd", "/bin/bash", "/etc/apt", "/var/jb", "/private/preboot",
        "/opt/procursus", "/var/mobile/Library/TrollStore", "/usr/lib/TweakInject",
        "/Library/MobileSubstrate/MobileSubstrate.dylib", "/private/preboot/dopamine",
        "/private/preboot/palera1n", "/usr/lib/libsubstrate.dylib"
    };
    
    for (int i = 0; i < sizeof(paths) / sizeof(char*); i++) {
        if (access(paths[i], F_OK) == 0) return YES;
    }

    // 2. Symbolic Link Integrity Check
    // System folders should NOT be symlinks (classic jailbreak relocation trick)
    const char* symlinkPaths[] = {"/Applications", "/usr/libexec", "/usr/share", "/Library"};
    for (int i = 0; i < 4; i++) {
        struct stat s;
        if (lstat(symlinkPaths[i], &s) == 0 && S_ISLNK(s.st_mode)) return YES;
    }

    // 3. Sandbox Write Test
    NSString *testPath = @"/private/jb_test.txt";
    if ([@"test" writeToFile:testPath atomically:YES encoding:NSUTF8StringEncoding error:nil]) {
        [[NSFileManager defaultManager] removeItemAtPath:testPath error:nil];
        return YES;
    }

    // 4. URL Scheme Check (Requires LSApplicationQueriesSchemes in Info.plist)
    NSArray *schemes = @[@"cydia://", @"sileo://", @"zbra://", @"trollstore://", @"dopamine://", @"palera1n://"];
    for (NSString *scheme in schemes) {
        NSURL *url = [NSURL URLWithString:scheme];
        if (url && [[UIApplication sharedApplication] canOpenURL:url]) return YES;
    }

    // 5. Check for dyld injection
    char *env = getenv("DYLD_INSERT_LIBRARIES");
    if (env != NULL && strlen(env) > 0) return YES;

    return NO;
#endif
}

#pragma mark - Frida & Thread Detection

- (BOOL)isFridaDetected {
    // 1. Scan for Frida threads by name (Very effective!)
    if ([self scanThreadsForFrida]) return YES;

    // 2. Dynamic Library Scan (Case-insensitive)
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name) {
            NSString *n = [[NSString stringWithUTF8String:name] lowercaseString];
            if ([n containsString:@"frida"] || [n containsString:@"gadget"] || [n containsString:@"gum-js"]) {
                return YES;
            }
        }
    }

    // 3. Symbol Check
    if (dlsym(RTLD_DEFAULT, "frida_agent_main") || 
        dlsym(RTLD_DEFAULT, "frida_gadget_load") ||
        dlsym(RTLD_DEFAULT, "gum_init_embedded")) {
        return YES;
    }

    // 4. Port scan with proper timeout
    return [self checkFridaPorts];
}

- (BOOL)scanThreadsForFrida {
    char name[256];
    mach_msg_type_number_t count;
    thread_act_array_t list;
    
    if (task_threads(mach_task_self(), &list, &count) != KERN_SUCCESS) {
        return NO;
    }

    BOOL foundFrida = NO;
    for (int i = 0; i < count; i++) {
        pthread_t pt = pthread_from_mach_thread_np(list[i]);
        if (pt && pthread_getname_np(pt, name, sizeof(name)) == 0) {
            // Case-insensitive check for thread names
            char lowerName[256];
            size_t len = strlen(name);
            for (size_t j = 0; j < len; j++) {
                lowerName[j] = tolower((unsigned char)name[j]);
            }
            lowerName[len] = '\0';
            
            if (strstr(lowerName, "frida") || strstr(lowerName, "gum-js") || strstr(lowerName, "gadget")) {
                foundFrida = YES;
                break;
            }
        }
    }
    
    // Clean up Mach port array
    for (int i = 0; i < count; i++) {
        mach_port_deallocate(mach_task_self(), list[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)list, count * sizeof(thread_act_t));
    
    return foundFrida;
}

- (BOOL)checkFridaPorts {
    int ports[] = {27042, 27043, 27044, 27045};
    int portCount = sizeof(ports) / sizeof(ports[0]);
    
    for (int i = 0; i < portCount; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        
        // Set socket to non-blocking mode
        int flags = fcntl(sock, F_GETFL, 0);
        if (flags < 0) {
            close(sock);
            continue;
        }
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        addr.sin_port = htons(ports[i]);

        // Attempt connection
        connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        
        // Wait for connection with timeout
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000; // 100ms timeout
        
        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);
        
        int selectResult = select(sock + 1, NULL, &writefds, NULL, &tv);
        
        if (selectResult > 0) {
            // Socket became writable - but did connection succeed?
            int error = 0;
            socklen_t len = sizeof(error);
            
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) {
                // Connection succeeded - port is open
                close(sock);
                return YES;
            }
        }
        
        close(sock);
    }
    return NO;
}

- (BOOL)checkFridaPipes {
    int pid = getpid();
    int size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
    if (size <= 0) return NO;

    struct proc_fdinfo *fds = malloc(size);
    if (!fds) return NO;
    
    int ret = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, size);
    if (ret <= 0) {
        free(fds);
        return NO;
    }
    
    int count = size / sizeof(struct proc_fdinfo);
    BOOL foundFrida = NO;

    for (int i = 0; i < count; i++) {
        if (fds[i].proc_fdtype == PROX_FDTYPE_VNODE) {
            struct vnode_fdinfowithpath vnode;
            int res = proc_pidinfo(pid, PROC_PIDFDVNODEPATHINFO, fds[i].proc_fd, &vnode, sizeof(vnode));
            
            if (res > 0) {
                // Case-insensitive search
                char lowerPath[MAXPATHLEN];
                strncpy(lowerPath, vnode.pvip.vip_path, sizeof(lowerPath) - 1);
                lowerPath[sizeof(lowerPath) - 1] = '\0';
                for (char *p = lowerPath; *p; p++) *p = tolower(*p);
                
                if (strstr(lowerPath, "frida") || strstr(lowerPath, "gadget") || strstr(lowerPath, "gum-js")) {
                    foundFrida = YES;
                    break;
                }
            }
        }
    }
    
    free(fds);
    return foundFrida;
}

@end