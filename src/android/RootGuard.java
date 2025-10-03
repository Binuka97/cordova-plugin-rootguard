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

    /**
     * Tries multiple strategies to detect su:
     * 1) Try `which su` (system-resolved)
     * 2) Fallback to checking common su paths
     */
    private boolean checkSuCommand() {
        // 1) Try plain `which su` (no absolute path) — runCommandWithTimeout will handle missing binary gracefully
        try {
            if (runCommandWithTimeout(new String[]{"which", "su"}, 500)) {
                log("su detected via `which su`");
                return true;
            }
        } catch (Exception ignored) {
            // runCommandWithTimeout already logs; continue to fallbacks
        }

        // 2) Fallback: check common su locations directly
        String[] suPaths = {
            "/system/xbin/su",
            "/system/bin/su",
            "/sbin/su",
            "/vendor/bin/su",
            "/su/bin/su"
        };

        for (String path : suPaths) {
            try {
                if (new File(path).exists()) {
                    log("su binary found at: " + path);
                    return true;
                }
            } catch (SecurityException se) {
                // If checking file existence causes a security exception, treat as suspicious (fail-safe)
                log("SecurityException when checking su path: " + se.getMessage());
                return true;
            }
        }

        return false;
    }

    private boolean checkSystemMount() {
        Process process = null;
        BufferedReader reader = null;
        try {
            process = new ProcessBuilder("mount").start();
            if (!process.waitFor(500, TimeUnit.MILLISECONDS)) {
                process.destroy();
                log("Mount command timed out (possible Magisk hide).");
                return true; // Treat timeout as compromised
            }

            reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains(" /system ") && !line.contains(" ro ")) {
                    log("Root detected via mount command!");
                    return true;
                }
            }
        } catch (IOException e) {
            // If mount binary is missing or cannot run, that alone isn't proof of root; but treat other IO issues as suspicious.
            String msg = e.getMessage() != null ? e.getMessage() : "";
            log("Error checking mount: " + msg);
            // If it's "No such file or directory" specifically, don't assume compromised just for that.
            if (msg.contains("error=2") || msg.toLowerCase().contains("no such file")) {
                log("mount binary missing — not a definitive root indicator.");
                return false;
            }
            return true; // Fail-safe for other errors
        } catch (InterruptedException ie) {
            log("Interrupted while checking mount: " + ie.getMessage());
            Thread.currentThread().interrupt();
            return true;
        } finally {
            if (reader != null) {
                try { reader.close(); } catch (IOException ignored) {}
            }
            if (process != null) {
                process.destroy();
            }
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
        Process process = null;
        BufferedReader reader = null;
        try {
            process = new ProcessBuilder("getprop").start();
            if (!process.waitFor(500, TimeUnit.MILLISECONDS)) {
                process.destroy();
                log("getprop command timed out.");
                return true;
            }

            reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.toLowerCase().contains("frida")) {
                    log("Frida detected in system properties!");
                    return true;
                }
            }
        } catch (IOException e) {
            String msg = e.getMessage() != null ? e.getMessage() : "";
            log("Error checking system properties: " + msg);
            // don't treat missing getprop binary as a root indicator
            if (msg.contains("error=2") || msg.toLowerCase().contains("no such file")) {
                log("getprop binary missing — not a definitive frida indicator.");
                return false;
            }
            return true; // Fail-safe
        } catch (InterruptedException ie) {
            log("Interrupted while checking properties: " + ie.getMessage());
            Thread.currentThread().interrupt();
            return true;
        } finally {
            if (reader != null) {
                try { reader.close(); } catch (IOException ignored) {}
            }
            if (process != null) {
                process.destroy();
            }
        }
        return false;
    }

    // ---------------------------
    // Utility
    // ---------------------------
    /**
     * Run a command with a timeout. Returns true if the command produced output (meaning suspicious for checks like `which su` / `pidof`),
     * false if no output or the binary is missing.
     *
     * Behavior:
     * - If process cannot be started because binary is missing (IOException containing error=2 / No such file) -> return false.
     * - If process times out (hangs) -> treat as suspicious and return true.
     * - If process runs and produces output -> return true.
     * - For other unexpected exceptions -> treat as suspicious (return true).
     */
    private boolean runCommandWithTimeout(String[] command, int timeoutMs) {
        Process process = null;
        BufferedReader reader = null;
        try {
            process = new ProcessBuilder(command).start();
            if (!process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) {
                process.destroy();
                log("Command timed out: " + String.join(" ", command));
                return true; // Timeout → assume compromised / suspicious
            }

            reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            boolean hasOutput = reader.readLine() != null;

            if (hasOutput) {
                log("Command output detected: " + String.join(" ", command));
            }
            return hasOutput;
        } catch (IOException e) {
            String msg = e.getMessage() != null ? e.getMessage() : "";
            log("IOException running command: " + String.join(" ", command) + " | " + msg);
            // If binary is missing on the system (error=2 / No such file or directory), treat as NOT compromised
            if (msg.contains("error=2") || msg.toLowerCase().contains("no such file")) {
                return false;
            }
            // Other IOExceptions could be suspicious — fail-safe
            return true;
        } catch (InterruptedException e) {
            log("Interrupted while running command: " + String.join(" ", command) + " | " + e.getMessage());
            Thread.currentThread().interrupt();
            return true; // Fail-safe
        } catch (Exception e) {
            log("Error running command: " + String.join(" ", command) + " | " + e.getMessage());
            return true; // Fail-safe for unknown issues
        } finally {
            if (reader != null) {
                try { reader.close(); } catch (IOException ignored) {}
            }
            if (process != null) {
                process.destroy();
            }
        }
    }

    private void log(String message) {
        if (ENABLE_LOGS) {
            Log.d(TAG, message);
        }
    }
}
