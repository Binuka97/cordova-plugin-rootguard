package com.rootguard.detection;

import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONException;
import android.util.Log;
import java.io.*;
import java.net.*;
import java.util.concurrent.*;

public class RootGuard extends CordovaPlugin {
    private static final String TAG = "RootGuard";
    private static final boolean ENABLE_LOGS = false; // Always false in prod

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        if ("checkSecurity".equals(action)) {
            // Use Cordova's thread pool to keep the UI snappy
            cordova.getThreadPool().execute(() -> {
                try {
                    boolean isCompromised = isDeviceRooted() || isFridaPresent();
                    callbackContext.success(isCompromised ? 1 : 0);
                } catch (Exception e) {
                    // Fail-safe: if the check crashes, assume the device is compromised
                    callbackContext.success(1);
                }
            });
            return true;
        }
        return false;
    }

    private boolean isDeviceRooted() {
        return checkRootFiles() || checkSuBinaryEfficiently();
    }

    private boolean checkRootFiles() {
        // Updated 2026 paths (Includes KernelSU and Magisk/Zygisk)
        String[] paths = {
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/sbin/.magisk",
            "/data/adb/ksu",
            "/data/adb/magisk"
        };
        for (String path : paths) {
            if (new File(path).exists()) return true;
        }
        return false;
    }

    private boolean checkSuBinaryEfficiently() {
        Process process = null;
        try {
            // 'command -v su' is more portable than 'which su' or 'type su'
            process = Runtime.getRuntime().exec(new String[]{"sh", "-c", "command -v su"});
            // 1.5s timeout to avoid ANRs while allowing slower devices to finish
            if (!process.waitFor(1500, TimeUnit.MILLISECONDS)) {
                process.destroyForcibly();
                return false;
            }
            return process.exitValue() == 0;
        } catch (Exception e) {
            return false;
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }

    private boolean isFridaPresent() {
        return checkFridaPort() || checkMemoryMaps() || checkFridaNamedPipes();
    }

    private boolean checkFridaPort() {
        // Standard Frida server port
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", 27042), 200);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkMemoryMaps() {
        // Scans the current process memory for injected Frida agents or Zygisk hooks
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String lower = line.toLowerCase();
                if (lower.contains("frida") ||
                    lower.contains("gadget") ||
                    lower.contains("gum-js") ||
                    lower.contains("zygisk")) {
                    return true;
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    private boolean checkFridaNamedPipes() {
        // Checks for Frida-related named pipes via file descriptors
        try {
            File fdDir = new File("/proc/self/fd");
            File[] files = fdDir.listFiles();
            if (files == null) return false;

            for (File f : files) {
                try {
                    String path = f.getCanonicalPath();
                    if (path.toLowerCase().contains("frida")) {
                        return true;
                    }
                } catch (Exception ignored) {}
            }
        } catch (Exception ignored) {}
        return false;
    }
}
