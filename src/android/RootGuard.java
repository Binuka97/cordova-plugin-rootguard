package com.rootguard.detection;

import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONException;
import android.util.Log;

import java.io.*;
import java.net.*;
import java.util.concurrent.TimeUnit;

public class RootGuard extends CordovaPlugin {
    private static final String TAG = "RootGuard";
    private static final boolean ENABLE_LOGS = true; // Set to false for production

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        if ("checkSecurity".equals(action)) {
            cordova.getThreadPool().execute(() -> {
                try {
                    boolean isCompromised = isDeviceRooted() || isFridaPresent();
                    callbackContext.success(isCompromised ? 1 : 0);
                } catch (Exception e) {
                    log("Exception during detection: " + e.getMessage());
                    // If detection fails or hangs, assume compromised
                    callbackContext.success(1);
                }
            });
            return true;
        }
        return false;
    }

    // ---------------------------
    // Root Detection
    // ---------------------------
    private boolean isDeviceRooted() {
        return checkRootFiles() || checkSuCommand() || checkSystemMount();
    }

    private boolean checkRootFiles() {
        String[] rootPaths = {
            "/system/app/Superuser.apk",
            "/system/xbin/su",
            "/system/bin/su",
            "/sbin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/data/local/su",
            "/system/su",
            "/sbin/.magisk"
        };

        for (String path : rootPaths) {
            if (new File(path).exists()) {
                log("Root detected: " + path);
                return true;
            }
        }
        return false;
    }

    private boolean checkSuCommand() {
        return runCommandWithTimeout(new String[]{"/system/xbin/which", "su"}, 500);
    }

    private boolean checkSystemMount() {
        try {
            Process process = new ProcessBuilder("mount").start();
            if (!process.waitFor(500, TimeUnit.MILLISECONDS)) {
                process.destroy();
                log("Mount command timed out (possible Magisk hide).");
                return true; // Treat timeout as compromised
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains(" /system ") && !line.contains(" ro ")) {
                    log("Root detected via mount command!");
                    reader.close();
                    return true;
                }
            }
            reader.close();
        } catch (Exception e) {
            log("Error checking mount: " + e.getMessage());
            return true; // Fail-safe: treat error as compromised
        }
        return false;
    }

    // ---------------------------
    // Frida Detection
    // ---------------------------
    private boolean isFridaPresent() {
        return checkFridaPorts() || checkFridaLibraries() || checkFridaProcesses() || checkFridaProperties();
    }

    private boolean checkFridaPorts() {
        int[] ports = {27042, 27043}; // Frida default ports
        for (int port : ports) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("127.0.0.1", port), 500);
                log("Frida server detected on port " + port);
                return true;
            } catch (IOException ignored) {}
        }
        return false;
    }

    private boolean checkFridaLibraries() {
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("frida") || line.contains("gadget") || line.contains("gum-js")) {
                    log("Frida detected in memory maps!");
                    return true;
                }
            }
        } catch (IOException e) {
            log("Error checking Frida libraries: " + e.getMessage());
            return true; // Fail-safe
        }
        return false;
    }

    private boolean checkFridaProcesses() {
        return runCommandWithTimeout(new String[]{"pidof", "frida-server"}, 500);
    }

    private boolean checkFridaProperties() {
        try {
            Process process = new ProcessBuilder("getprop").start();
            if (!process.waitFor(500, TimeUnit.MILLISECONDS)) {
                process.destroy();
                log("getprop command timed out.");
                return true;
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.toLowerCase().contains("frida")) {
                    log("Frida detected in system properties!");
                    reader.close();
                    return true;
                }
            }
            reader.close();
        } catch (Exception e) {
            log("Error checking system properties: " + e.getMessage());
            return true; // Fail-safe
        }
        return false;
    }

    // ---------------------------
    // Utility
    // ---------------------------
    private boolean runCommandWithTimeout(String[] command, int timeoutMs) {
        try {
            Process process = new ProcessBuilder(command).start();
            if (!process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) {
                process.destroy();
                log("Command timed out: " + String.join(" ", command));
                return true; // Timeout → assume compromised
            }

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            boolean hasOutput = reader.readLine() != null;
            reader.close();

            if (hasOutput) {
                log("Command output detected: " + String.join(" ", command));
            }
            return hasOutput;
        } catch (Exception e) {
            log("Error running command: " + String.join(" ", command) + " | " + e.getMessage());
            return true; // Fail-safe
        }
    }

    private void log(String message) {
        if (ENABLE_LOGS) {
            Log.d(TAG, message);
        }
    }
}
