package com.example.rootguard;

import android.content.Context;
import android.util.Log;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;
import org.json.JSONArray;
import org.json.JSONException;
import java.io.File;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class RootGuard extends CordovaPlugin {
    private static final String TAG = "RootGuard";

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        if (action.equals("checkSecurity")) {
            boolean isCompromised = checkRootAndFrida();
            callbackContext.success(isCompromised ? 1 : 0);
            return true;
        }
        return false;
    }

    private boolean checkRootAndFrida() {
        return isRooted() || isFridaDetected();
    }

    private boolean isRooted() {
        String[] paths = {
            "/system/app/Superuser.apk",
            "/system/xbin/su",
            "/system/bin/su",
            "/sbin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/data/local/su",
            "/system/su"
        };
        for (String path : paths) {
            if (new File(path).exists()) {
                return true;
            }
        }
        return false;
    }

    private boolean isFridaDetected() {
        try {
            Process process = Runtime.getRuntime().exec("cat /proc/self/maps");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("frida") || line.contains("gum-js")) {
                    Log.d(TAG, "Frida detected in memory maps!");
                    return true;
                }
            }
            reader.close();
        } catch (Exception e) {
            Log.e(TAG, "Error checking Frida: " + e.getMessage());
        }
        return false;
    }
}
