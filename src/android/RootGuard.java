package com.rootguard.detection;

import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONException;
import android.util.Log;
import java.io.*;
import java.net.*;

public class RootGuard extends CordovaPlugin {
    private static final String TAG = "RootGuard";
    private static final boolean ENABLE_LOGS = true; // Set to false for production

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        if ("checkSecurity".equals(action)) {
            boolean isCompromised = isDeviceRooted() || isFridaPresent();
            callbackContext.success(isCompromised ? 1 : 0);
            return true;
        }
        return false;
    }

    /** 
     * Detects if the device is rooted using multiple checks.
     */
    private boolean isDeviceRooted() {
        return checkRootFiles() || checkSuCommand() || checkSystemMount();
    }

    /** 
     * Detects if Frida is present using multiple detection mechanisms.
     */
    private boolean isFridaPresent() {
        return checkFridaPorts() || checkFridaLibraries() || checkFridaProcesses() || checkFridaProperties();
    }

    /** 
     * Checks for common root indicator files.
     */
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

    /** 
     * Tries executing the 'su' command to detect root access.
     */
    private boolean checkSuCommand() {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"/system/xbin/which", "su"});
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            boolean isRooted = in.readLine() != null;
            in.close();
            return isRooted;
        } catch (IOException ignored) {
            return false;
        }
    }

    /** 
     * Checks if /system is mounted as read-write instead of read-only.
     */
    private boolean checkSystemMount() {
        try {
            Process process = Runtime.getRuntime().exec("mount");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains(" /system ") && !line.contains(" ro ")) {
                    log("Root detected via mount command!");
                    return true;
                }
            }
            reader.close();
        } catch (IOException e) {
            log("Error checking mount: " + e.getMessage());
        }
        return false;
    }

    /** 
     * Checks if Frida's default ports are open.
     */
    private boolean checkFridaPorts() {
        int[] ports = {27042, 27043}; // Frida default ports
        for (int port : ports) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("127.0.0.1", port), 500);
                log("Frida server detected on port " + port);
                return true;
            } catch (IOException ignored) {
                // No Frida server detected on this port
            }
        }
        return false;
    }

    /** 
     * Scans process memory maps for Frida-related libraries.
     */
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
        }
        return false;
    }

    /** 
     * Checks if a Frida process (frida-server) is running.
     */
    private boolean checkFridaProcesses() {
        try {
            Process process = Runtime.getRuntime().exec("pidof frida-server");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            boolean isFridaRunning = reader.readLine() != null;
            reader.close();
            if (isFridaRunning) {
                log("Frida process detected!");
            }
            return isFridaRunning;
        } catch (IOException e) {
            log("Error checking Frida processes: " + e.getMessage());
        }
        return false;
    }

    /** 
     * Searches system properties for Frida-related indicators.
     */
    private boolean checkFridaProperties() {
        try {
            Process process = Runtime.getRuntime().exec("getprop");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.toLowerCase().contains("frida")) {
                    log("Frida detected in system properties!");
                    return true;
                }
            }
            reader.close();
        } catch (IOException e) {
            log("Error checking system properties: " + e.getMessage());
        }
        return false;
    }

    /** 
     * Utility function to log messages if logging is enabled.
     */
    private void log(String message) {
        if (ENABLE_LOGS) {
            Log.d(TAG, message);
        }
    }
}
