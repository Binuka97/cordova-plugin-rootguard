package com.rootguard.detection;

import android.os.Build;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Local, best-effort compromise detection.
 *
 * This class deliberately avoids shell commands. A command failure or timeout is
 * a capability failure, never evidence of compromise. High-assurance enforcement
 * belongs on a backend using Play Integrity; see SECURITY.md.
 */
public final class RootGuard extends CordovaPlugin {
    private static final int SAFE = 0;
    private static final int COMPROMISED = 1;
    private static final int UNKNOWN = 2;
    private static final int ANDROID_13 = 33;
    private static final int SOCKET_TIMEOUT_MS = 60;
    private static final int MAX_MAP_LINES = 20000;
    private static final int MAX_FDS = 512;
    private static final int MAX_TASKS = 512;
    private static final int MAX_TCP_LINES = 256;
    private static final int MAX_PROTOCOL_PORTS = 8;

    private enum State { DETECTED, CLEAR, UNAVAILABLE }
    private enum Strength { HIGH, MEDIUM }

    private static final class Signal {
        final String id;
        final String category;
        final State state;
        final Strength strength;

        Signal(String id, String category, State state, Strength strength) {
            this.id = id;
            this.category = category;
            this.state = state;
            this.strength = strength;
        }
    }

    private static final class Assessment {
        final int status;
        final List<Signal> signals;

        Assessment(int status, List<Signal> signals) {
            this.status = status;
            this.signals = signals;
        }
    }

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callback) throws JSONException {
        if (!"checkSecurity".equals(action)
                && !"checkSecurityStatus".equals(action)
                && !"checkSecurityDetailed".equals(action)) {
            return false;
        }

        cordova.getThreadPool().execute(() -> {
            Assessment assessment;
            try {
                assessment = assess();
            } catch (Throwable ignored) {
                assessment = new Assessment(UNKNOWN, new ArrayList<>());
            }

            if ("checkSecurity".equals(action)) {
                // Backward compatibility: the legacy API remains binary and UNKNOWN
                // must not lock out existing users.
                callback.success(assessment.status == COMPROMISED ? 1 : 0);
            } else if ("checkSecurityStatus".equals(action)) {
                callback.success(assessment.status);
            } else {
                callback.success(toJson(assessment));
            }
        });
        return true;
    }

    private Assessment assess() {
        List<Signal> signals = new ArrayList<>();
        signals.add(checkRootArtifacts());
        signals.add(checkSuOnPath());
        signals.add(checkBuildProvenance());
        signals.add(checkProcessMaps());
        signals.add(checkFileDescriptors());
        signals.add(checkThreadNames());
        signals.add(checkFridaProtocol());

        int high = countDetected(signals, Strength.HIGH);
        int medium = countDetected(signals, Strength.MEDIUM);
        int status;
        if (high > 0 || medium >= 2) {
            status = COMPROMISED;
        } else if (medium == 1 || criticalChecksUnavailable(signals)) {
            status = UNKNOWN;
        } else if (Build.VERSION.SDK_INT >= ANDROID_13) {
            // Local absence checks cannot establish device integrity on modern
            // Android. A server-verified Play Integrity verdict is required.
            status = UNKNOWN;
        } else {
            status = SAFE;
        }
        return new Assessment(status, signals);
    }

    private Signal checkRootArtifacts() {
        String[] paths = {
                "/system/app/Superuser.apk",
                "/system/bin/su",
                "/system/xbin/su",
                "/system/bin/.ext/.su",
                "/system/usr/we-need-root/su-backup",
                "/sbin/su",
                "/su/bin/su",
                "/sbin/.magisk",
                "/cache/magisk.log",
                "/data/adb/magisk",
                "/data/adb/ksu",
                "/data/adb/ap"
        };
        try {
            for (String path : paths) {
                if (new File(path).exists()) {
                    return new Signal("root_artifact", "root", State.DETECTED, Strength.HIGH);
                }
            }
            return new Signal("root_artifact", "root", State.CLEAR, Strength.HIGH);
        } catch (SecurityException ignored) {
            return new Signal("root_artifact", "root", State.UNAVAILABLE, Strength.HIGH);
        }
    }

    private Signal checkSuOnPath() {
        String path = System.getenv("PATH");
        if (path == null || path.length() == 0) {
            return new Signal("su_path", "root", State.UNAVAILABLE, Strength.HIGH);
        }
        try {
            for (String directory : path.split(":")) {
                File candidate = new File(directory, "su");
                if (candidate.isFile() && candidate.canExecute()) {
                    return new Signal("su_path", "root", State.DETECTED, Strength.HIGH);
                }
            }
            return new Signal("su_path", "root", State.CLEAR, Strength.HIGH);
        } catch (SecurityException ignored) {
            return new Signal("su_path", "root", State.UNAVAILABLE, Strength.HIGH);
        }
    }

    private Signal checkBuildProvenance() {
        String tags = Build.TAGS == null ? "" : Build.TAGS.toLowerCase(Locale.US);
        String type = Build.TYPE == null ? "" : Build.TYPE.toLowerCase(Locale.US);
        boolean nonProduction = tags.contains("test-keys") || "eng".equals(type) || "userdebug".equals(type);
        return new Signal("non_production_build", "root", nonProduction ? State.DETECTED : State.CLEAR,
                Strength.MEDIUM);
    }

    private Signal checkProcessMaps() {
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            int count = 0;
            while ((line = reader.readLine()) != null && count++ < MAX_MAP_LINES) {
                String value = line.toLowerCase(Locale.US);
                if (containsInstrumentationMarker(value)) {
                    return new Signal("instrumentation_map", "instrumentation", State.DETECTED, Strength.HIGH);
                }
            }
            return new Signal("instrumentation_map", "instrumentation", State.CLEAR, Strength.HIGH);
        } catch (Exception ignored) {
            return new Signal("instrumentation_map", "instrumentation", State.UNAVAILABLE, Strength.HIGH);
        }
    }

    private Signal checkFileDescriptors() {
        File directory = new File("/proc/self/fd");
        File[] descriptors;
        try {
            descriptors = directory.listFiles();
        } catch (SecurityException ignored) {
            descriptors = null;
        }
        if (descriptors == null) {
            return new Signal("instrumentation_fd", "instrumentation", State.UNAVAILABLE, Strength.HIGH);
        }

        int count = 0;
        for (File descriptor : descriptors) {
            if (count++ >= MAX_FDS) break;
            try {
                if (containsInstrumentationMarker(descriptor.getCanonicalPath().toLowerCase(Locale.US))) {
                    return new Signal("instrumentation_fd", "instrumentation", State.DETECTED, Strength.HIGH);
                }
            } catch (Exception ignored) {
                // Individual descriptors can disappear while being enumerated.
            }
        }
        return new Signal("instrumentation_fd", "instrumentation", State.CLEAR, Strength.HIGH);
    }

    private Signal checkThreadNames() {
        File directory = new File("/proc/self/task");
        File[] tasks;
        try {
            tasks = directory.listFiles();
        } catch (SecurityException ignored) {
            tasks = null;
        }
        if (tasks == null) {
            return new Signal("instrumentation_thread", "instrumentation", State.UNAVAILABLE, Strength.HIGH);
        }

        boolean genericGlibThread = false;
        int count = 0;
        for (File task : tasks) {
            if (count++ >= MAX_TASKS) break;
            try (BufferedReader reader = new BufferedReader(new FileReader(new File(task, "comm")))) {
                String name = reader.readLine();
                if (name == null) continue;
                String value = name.trim().toLowerCase(Locale.US);
                if (containsInstrumentationMarker(value)
                        || value.contains("pool-frida")
                        || value.contains("gmain-frida")) {
                    return new Signal("instrumentation_thread", "instrumentation",
                            State.DETECTED, Strength.HIGH);
                }
                // gmain/gdbus are associated with Frida's GLib runtime, but
                // legitimate software can use them too. Never treat either as
                // conclusive without a second independent signal.
                if ("gmain".equals(value) || "gdbus".equals(value)) {
                    genericGlibThread = true;
                }
            } catch (Exception ignored) {
                // Threads can exit while /proc/self/task is being enumerated.
            }
        }
        return new Signal("instrumentation_thread", "instrumentation",
                genericGlibThread ? State.DETECTED : State.CLEAR,
                genericGlibThread ? Strength.MEDIUM : Strength.HIGH);
    }

    private Signal checkFridaProtocol() {
        Set<Integer> ports = new LinkedHashSet<>();
        ports.add(27042);
        ports.add(27043);
        ports.add(27044);
        ports.add(27045);
        addListeningPorts("/proc/self/net/tcp", ports);
        addListeningPorts("/proc/self/net/tcp6", ports);

        boolean portOpen = false;
        for (int port : ports) {
            boolean knownFridaPort = port >= 27042 && port <= 27045;
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("127.0.0.1", port), SOCKET_TIMEOUT_MS);
                socket.setSoTimeout(SOCKET_TIMEOUT_MS);
                portOpen = true;

                OutputStream output = socket.getOutputStream();
                output.write(new byte[]{0});
                output.write("AUTH\r\n".getBytes(StandardCharsets.US_ASCII));
                output.flush();

                InputStream input = socket.getInputStream();
                byte[] response = new byte[96];
                int length = input.read(response);
                if (length > 0) {
                    String banner = new String(response, 0, length, StandardCharsets.US_ASCII)
                            .toUpperCase(Locale.US);
                    if (banner.contains("REJECTED") || banner.contains("OK") || banner.contains("AGREE")) {
                        // D-Bus authentication is Frida-compatible but not unique
                        // to Frida. It is conclusive only on its known ports; a
                        // custom port must be corroborated by another signal.
                        return new Signal("frida_protocol", "instrumentation", State.DETECTED,
                                knownFridaPort ? Strength.HIGH : Strength.MEDIUM);
                    }
                }
            } catch (Exception ignored) {
                // A refused connection or protocol timeout is not evidence.
            }
        }
        return new Signal("frida_protocol", "instrumentation",
                portOpen ? State.DETECTED : State.CLEAR, Strength.MEDIUM);
    }

    private void addListeningPorts(String path, Set<Integer> ports) {
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            String line;
            int count = 0;
            while ((line = reader.readLine()) != null && count++ < MAX_TCP_LINES
                    && ports.size() < MAX_PROTOCOL_PORTS) {
                String[] columns = line.trim().split("\\s+");
                if (columns.length < 4 || !"0A".equals(columns[3])) continue;
                String[] address = columns[1].split(":");
                if (address.length != 2) continue;
                int port = Integer.parseInt(address[1], 16);
                if (port > 1024 && port <= 65535) ports.add(port);
            }
        } catch (Exception ignored) {
            // Procfs visibility varies. Default/common ports are still checked.
        }
    }

    private boolean containsInstrumentationMarker(String value) {
        return value.contains("frida")
                || value.contains("gum-js")
                || value.contains("linjector")
                || value.contains("/re.frida.")
                || value.contains("zygisk");
    }

    private int countDetected(List<Signal> signals, Strength strength) {
        int count = 0;
        for (Signal signal : signals) {
            if (signal.state == State.DETECTED && signal.strength == strength) count++;
        }
        return count;
    }

    private boolean criticalChecksUnavailable(List<Signal> signals) {
        boolean mapsUnavailable = false;
        boolean rootChecksUnavailable = true;
        for (Signal signal : signals) {
            if ("instrumentation_map".equals(signal.id) && signal.state == State.UNAVAILABLE) {
                mapsUnavailable = true;
            }
            if ("root".equals(signal.category) && signal.strength == Strength.HIGH
                    && signal.state != State.UNAVAILABLE) {
                rootChecksUnavailable = false;
            }
        }
        return mapsUnavailable || rootChecksUnavailable;
    }

    private JSONObject toJson(Assessment assessment) {
        JSONObject result = new JSONObject();
        JSONArray evidence = new JSONArray();
        JSONArray unavailable = new JSONArray();
        try {
            for (Signal signal : assessment.signals) {
                if (signal.state == State.DETECTED) evidence.put(signal.id);
                if (signal.state == State.UNAVAILABLE) unavailable.put(signal.id);
            }
            result.put("status", assessment.status);
            result.put("statusName", statusName(assessment.status));
            result.put("platform", "android");
            result.put("osVersion", Build.VERSION.RELEASE);
            result.put("apiLevel", Build.VERSION.SDK_INT);
            result.put("evidence", evidence);
            result.put("unavailableChecks", unavailable);
            result.put("localOnly", true);
        } catch (JSONException ignored) {
            // All keys and values above are JSON-compatible.
        }
        return result;
    }

    private String statusName(int status) {
        if (status == COMPROMISED) return "COMPROMISED";
        if (status == UNKNOWN) return "UNKNOWN";
        return "SAFE";
    }
}
