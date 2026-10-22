package com.rootguard.detection;

import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Debug;

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
import java.util.Map;
import java.util.Set;

/**
 * Device-local root and runtime-instrumentation indicators for Cordova.
 *
 * Local checks are heuristic and can be bypassed. SAFE means these checks did
 * not detect compromise; it is not cryptographic device attestation.
 * The legacy checkSecurity action intentionally returns 1 only for COMPROMISED;
 * use checkSecurityStatus/checkSecurityDetailed to distinguish UNKNOWN from SAFE.
 */
public final class RootGuard extends CordovaPlugin {

    private static final int SAFE = 0;
    private static final int COMPROMISED = 1;
    private static final int UNKNOWN = 2;

    private static final int ANDROID_13 = 33;
    private static final int SOCKET_TIMEOUT_MS = 100;
    private static final int MAX_MAP_LINES = 20000;
    private static final int MAX_FDS = 512;
    private static final int MAX_TASKS = 512;
    private static final int MAX_TCP_LINES = 256;
    private static final int MAX_PORTS = 8;
    private static final int MAX_PROC_SCAN = 1024;
    private static final int MAX_UNIX_LINES = 4096;
    private static final int MAX_STATUS_LINES = 128;

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
        final List<String> unknownReasons;

        Assessment(int status, List<Signal> signals, List<String> unknownReasons) {
            this.status = status;
            this.signals = signals;
            this.unknownReasons = unknownReasons;
        }
    }

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callback)
            throws JSONException {

        if (!"checkSecurity".equals(action)
                && !"checkSecurityStatus".equals(action)
                && !"checkSecurityDetailed".equals(action)) {
            return false;
        }

        cordova.getThreadPool().execute(() -> {
            Assessment assessment;
            try {
                assessment = assess();
            } catch (Exception | LinkageError e) {
                List<String> reasons = new ArrayList<>();
                reasons.add("assessment_exception");
                assessment = new Assessment(UNKNOWN, new ArrayList<>(), reasons);
            }

            try {
                if ("checkSecurity".equals(action)) {
                    callback.success(assessment.status == COMPROMISED ? 1 : 0);
                } else if ("checkSecurityStatus".equals(action)) {
                    callback.success(assessment.status);
                } else {
                    callback.success(toJson(assessment));
                }
            } catch (Exception ignored) {}
        });

        return true;
    }

    // =========================================================
    // AGGREGATION
    // =========================================================

    private Assessment assess() {
        List<Signal> signals = new ArrayList<>();

        // --- base checks ---
        signals.add(checkRootArtifacts());
        signals.add(checkSuOnPath());
        signals.add(checkBuildProvenance());
        signals.add(checkProcessMaps());
        signals.add(checkFileDescriptors());
        signals.add(checkThreadNames());
        signals.add(checkXposedRuntime());
        signals.add(checkFrameworkMaps());
        signals.add(checkMountInfo());
        signals.add(checkFridaProtocol());

        // --- additional root / instrumentation checks ---
        signals.add(checkStackTraces());
        signals.add(checkUnixSockets());
        signals.add(checkProcessList());
        signals.add(checkTracer());
        signals.add(checkAnonymousExec());
        signals.add(checkEnvironment());
        signals.add(checkAdbPaths());
        signals.add(checkRootPackages());
        signals.add(checkDebuggerState());
        signals.add(checkProcSelfExe());

        boolean highDetected = false;
        boolean criticalUnavailable = false;
        boolean rootCheckAvailable = false;

        int mediumDetected = 0;
        int instrumentationUnavailableCount = 0;
        Set<String> mediumCategories = new LinkedHashSet<>();

        for (Signal s : signals) {
            if (s.state == State.DETECTED) {
                if (s.strength == Strength.HIGH) {
                    highDetected = true;
                } else {
                    mediumDetected++;
                    mediumCategories.add(s.category);
                }
            }

            if ("root".equals(s.category)
                    && s.strength == Strength.HIGH
                    && s.state != State.UNAVAILABLE) {
                rootCheckAvailable = true;
            }

            if ("instrumentation".equals(s.category)
                    && s.state == State.UNAVAILABLE) {
                instrumentationUnavailableCount++;
            }

            if ("instrumentation_map".equals(s.id)
                    && s.state == State.UNAVAILABLE) {
                criticalUnavailable = true;
            }
        }

        // Require at least 2 instrumentation checks to fail before treating
        // the whole instrumentation layer as unknown (reduces UNKNOWN noise).
        boolean instrumentationUnavailable = instrumentationUnavailableCount >= 2;

        List<String> unknownReasons = new ArrayList<>();
        int status;

        if (highDetected) {
            status = COMPROMISED;
        } else if (mediumDetected >= 2 && mediumCategories.size() >= 2) {
            status = COMPROMISED;
        } else {
            if (mediumDetected > 0) {
                unknownReasons.add("insufficient_medium_evidence");
            }
            if (!rootCheckAvailable || criticalUnavailable) {
                unknownReasons.add("critical_check_unavailable");
            }
            if (instrumentationUnavailable) {
                unknownReasons.add("instrumentation_check_unavailable");
            }
            if (Build.VERSION.SDK_INT >= ANDROID_13) {
                unknownReasons.add("modern_android_local_integrity_unverifiable");
            }
            status = unknownReasons.isEmpty() ? SAFE : UNKNOWN;
        }

        return new Assessment(status, signals, unknownReasons);
    }

    // =========================================================
    // ROOT ARTIFACTS
    // =========================================================

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
                "/data/adb/ap",
                "/debug_ramdisk"
        };
        try {
            for (String p : paths) {
                if (new File(p).exists()) {
                    return signal("root_artifact", "root", State.DETECTED, Strength.HIGH);
                }
            }
            return signal("root_artifact", "root", State.CLEAR, Strength.HIGH);
        } catch (SecurityException e) {
            return signal("root_artifact", "root", State.UNAVAILABLE, Strength.HIGH);
        }
    }

    private Signal checkSuOnPath() {
        String path = System.getenv("PATH");
        if (path == null || path.isEmpty()) {
            return signal("su_path", "root", State.UNAVAILABLE, Strength.HIGH);
        }
        try {
            for (String d : path.split(":")) {
                if (d.isEmpty()) continue;
                File c = new File(d, "su");
                if (c.isFile() && c.canExecute()) {
                    return signal("su_path", "root", State.DETECTED, Strength.HIGH);
                }
            }
            return signal("su_path", "root", State.CLEAR, Strength.HIGH);
        } catch (SecurityException e) {
            return signal("su_path", "root", State.UNAVAILABLE, Strength.HIGH);
        }
    }

    private Signal checkBuildProvenance() {
        String tags = Build.TAGS == null ? "" : Build.TAGS.toLowerCase(Locale.US);
        String type = Build.TYPE == null ? "" : Build.TYPE.toLowerCase(Locale.US);
        boolean nonProd = tags.contains("test-keys")
                || "eng".equals(type) || "userdebug".equals(type);
        return signal("non_production_build", "build",
                nonProd ? State.DETECTED : State.CLEAR, Strength.MEDIUM);
    }

    // =========================================================
    // PROCESS MEMORY MAPS
    // =========================================================

    private Signal checkProcessMaps() {
        try (BufferedReader r = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line; int n = 0;
            while ((line = r.readLine()) != null && n++ < MAX_MAP_LINES) {
                if (containsInstrumentationMarker(line)) {
                    return signal("instrumentation_map", "instrumentation", State.DETECTED, Strength.HIGH);
                }
            }
            return signal("instrumentation_map", "instrumentation", State.CLEAR, Strength.HIGH);
        } catch (Exception e) {
            return signal("instrumentation_map", "instrumentation", State.UNAVAILABLE, Strength.HIGH);
        }
    }

    private Signal checkFrameworkMaps() {
        try (BufferedReader r = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line; int n = 0;
            while ((line = r.readLine()) != null && n++ < MAX_MAP_LINES) {
                if (containsFrameworkMarker(line.toLowerCase(Locale.US))) {
                    return signal("framework_library_map", "instrumentation", State.DETECTED, Strength.HIGH);
                }
            }
            return signal("framework_library_map", "instrumentation", State.CLEAR, Strength.HIGH);
        } catch (Exception e) {
            return signal("framework_library_map", "instrumentation", State.UNAVAILABLE, Strength.HIGH);
        }
    }

    // =========================================================
    // FILE DESCRIPTORS
    // =========================================================

    private Signal checkFileDescriptors() {
        File dir = new File("/proc/self/fd");
        File[] fds;
        try { fds = dir.listFiles(); } catch (SecurityException e) { fds = null; }
        if (fds == null) {
            return signal("instrumentation_fd", "instrumentation", State.UNAVAILABLE, Strength.HIGH);
        }
        int n = 0;
        for (File fd : fds) {
            if (n++ >= MAX_FDS) break;
            try {
                String p = fd.getCanonicalPath().toLowerCase(Locale.US);
                if (containsInstrumentationMarker(p)) {
                    return signal("instrumentation_fd", "instrumentation", State.DETECTED, Strength.HIGH);
                }
            } catch (Exception ignored) {}
        }
        return signal("instrumentation_fd", "instrumentation", State.CLEAR, Strength.HIGH);
    }

    // =========================================================
    // THREADS
    // =========================================================

    private Signal checkThreadNames() {
        File dir = new File("/proc/self/task");
        File[] tasks;
        try { tasks = dir.listFiles(); } catch (SecurityException e) { tasks = null; }
        if (tasks == null) {
            return signal("instrumentation_thread", "instrumentation", State.UNAVAILABLE, Strength.HIGH);
        }
        int n = 0;
        for (File t : tasks) {
            if (n++ >= MAX_TASKS) break;
            try (BufferedReader r = new BufferedReader(new FileReader(new File(t, "comm")))) {
                String name = r.readLine();
                if (name == null) continue;
                String v = name.trim().toLowerCase(Locale.US);
                if (containsInstrumentationMarker(v)
                        || v.contains("pool-frida")
                        || v.contains("gmain-frida")) {
                    return signal("instrumentation_thread", "instrumentation", State.DETECTED, Strength.HIGH);
                }
            } catch (Exception ignored) {}
        }
        return signal("instrumentation_thread", "instrumentation", State.CLEAR, Strength.HIGH);
    }

    // =========================================================
    // XPOSED / LSPOSED RUNTIME (CLASS)
    // =========================================================

    private Signal checkXposedRuntime() {
        String[] classes = {
                "de.robv.android.xposed.XposedBridge",
                "de.robv.android.xposed.XposedHelpers"
        };
        Set<ClassLoader> loaders = new LinkedHashSet<>();
        loaders.add(getClass().getClassLoader());
        ClassLoader ctx = Thread.currentThread().getContextClassLoader();
        if (ctx != null) loaders.add(ctx);
        try {
            if (cordova != null && cordova.getActivity() != null) {
                ClassLoader al = cordova.getActivity().getClassLoader();
                if (al != null) loaders.add(al);
            }
        } catch (RuntimeException ignored) {}

        for (ClassLoader l : loaders) {
            if (l == null) continue;
            for (String cn : classes) {
                try {
                    Class.forName(cn, false, l);
                    return signal("xposed_bridge_class", "instrumentation", State.DETECTED, Strength.HIGH);
                } catch (ClassNotFoundException ignored) {
                } catch (LinkageError ignored) {
                } catch (SecurityException ignored) {}
            }
        }
        return signal("xposed_bridge_class", "instrumentation", State.CLEAR, Strength.HIGH);
    }

    // =========================================================
    // MOUNT TABLE
    // =========================================================

    private Signal checkMountInfo() {
        try (BufferedReader r = new BufferedReader(new FileReader("/proc/self/mountinfo"))) {
            String line; int n = 0;
            while ((line = r.readLine()) != null && n++ < 4096) {
                String v = line.toLowerCase(Locale.US);
                if (v.contains("zygisk") || v.contains("lsposed")
                        || v.contains("riru_core") || v.contains("liblspd")) {
                    return signal("framework_mount_marker", "instrumentation", State.DETECTED, Strength.HIGH);
                }
            }
            return signal("framework_mount_marker", "instrumentation", State.CLEAR, Strength.HIGH);
        } catch (Exception e) {
            return signal("framework_mount_marker", "instrumentation", State.UNAVAILABLE, Strength.HIGH);
        }
    }

    // =========================================================
    // FRIDA PROTOCOL
    // =========================================================

    private Signal checkFridaProtocol() {
        Set<Integer> ports = new LinkedHashSet<>();
        ports.add(27042); ports.add(27043); ports.add(27044); ports.add(27045);
        addListeningPorts("/proc/self/net/tcp", ports);
        addListeningPorts("/proc/self/net/tcp6", ports);

        boolean unknownResponded = false;
        for (int port : ports) {
            boolean known = port >= 27042 && port <= 27045;
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress("127.0.0.1", port), SOCKET_TIMEOUT_MS);
                s.setSoTimeout(SOCKET_TIMEOUT_MS);
                OutputStream out = s.getOutputStream();
                out.write(new byte[]{0});
                out.write("AUTH\r\n".getBytes(StandardCharsets.US_ASCII));
                out.flush();
                InputStream in = s.getInputStream();
                byte[] buf = new byte[96];
                int len = in.read(buf);
                if (len > 0) {
                    String banner = new String(buf, 0, len, StandardCharsets.US_ASCII)
                            .toUpperCase(Locale.US);
                    // Frida server responds with "REJECTED" or "AGREE".
                    // Do NOT match generic "OK" (HTTP false positives).
                    if (banner.contains("REJECTED") || banner.contains("AGREE")) {
                        return signal("frida_protocol", "instrumentation",
                                State.DETECTED, known ? Strength.HIGH : Strength.MEDIUM);
                    }
                    unknownResponded = true;
                }
            } catch (Exception ignored) {}
        }
        return signal("frida_protocol", "instrumentation",
                unknownResponded ? State.UNAVAILABLE : State.CLEAR, Strength.MEDIUM);
    }

    private void addListeningPorts(String path, Set<Integer> ports) {
        try (BufferedReader r = new BufferedReader(new FileReader(path))) {
            String line; int n = 0;
            while ((line = r.readLine()) != null && n++ < MAX_TCP_LINES && ports.size() < MAX_PORTS) {
                String[] col = line.trim().split("\\s+");
                if (col.length < 4 || !"0A".equals(col[3])) continue;
                String[] addr = col[1].split(":");
                if (addr.length != 2) continue;
                int port = Integer.parseInt(addr[1], 16);
                if (port > 1024 && port <= 65535) ports.add(port);
            }
        } catch (Exception ignored) {}
    }

    // =========================================================
    // STACK TRACES (Xposed / LSPosed / Dreamland)
    // =========================================================

    private Signal checkStackTraces() {
        try {
            StackTraceElement[] stack = new Throwable().getStackTrace();
            for (StackTraceElement e : stack) {
                String cn = e.getClassName();
                if (cn == null) continue;
                String v = cn.toLowerCase(Locale.US);
                if (v.startsWith("de.robv.android.xposed.")
                        || v.startsWith("io.github.lsposed.")
                        || v.startsWith("org.lsposed.")
                        || v.startsWith("top.canyie.dreamland")
                        || v.startsWith("com.elderdrivers.riru")) {
                    return signal("xposed_stack", "instrumentation", State.DETECTED, Strength.HIGH);
                }
            }
            return signal("xposed_stack", "instrumentation", State.CLEAR, Strength.MEDIUM);
        } catch (Throwable t) {
            return signal("xposed_stack", "instrumentation", State.UNAVAILABLE, Strength.MEDIUM);
        }
    }

    // =========================================================
    // UNIX SOCKETS (Frida / LSPosed / Magisk)
    // =========================================================

    private Signal checkUnixSockets() {
        try (BufferedReader r = new BufferedReader(new FileReader("/proc/self/net/unix"))) {
            String line; int n = 0;
            while ((line = r.readLine()) != null && n++ < MAX_UNIX_LINES) {
                String v = line.toLowerCase(Locale.US);
                if (v.contains("frida") || v.contains("gum-js")
                        || v.contains("linjector") || v.contains("magisk")
                        || v.contains("lspd") || v.contains("zygisk")
                        || v.contains("lsposed")) {
                    return signal("unix_socket", "instrumentation", State.DETECTED, Strength.HIGH);
                }
            }
            return signal("unix_socket", "instrumentation", State.CLEAR, Strength.HIGH);
        } catch (Exception e) {
            return signal("unix_socket", "instrumentation", State.UNAVAILABLE, Strength.MEDIUM);
        }
    }

    // =========================================================
    // PROCESS LIST SCAN
    // =========================================================

    private Signal checkProcessList() {
        File[] pids;
        try { pids = new File("/proc").listFiles(); }
        catch (SecurityException e) { pids = null; }

        if (pids == null) {
            return signal("suspicious_process", "instrumentation", State.UNAVAILABLE, Strength.MEDIUM);
        }

        String[] bad = {
                "frida-server", "frida-helper", "frida-agent",
                "magiskd", "lspd", "zygiskd", "rirud", "ksud", "apd",
                "magisk", "lsposed", "edxposed", "xposed", "substrate"
        };

        int n = 0;
        for (File p : pids) {
            if (n++ > MAX_PROC_SCAN) break;
            String name = p.getName();
            if (!name.matches("\\d+")) continue;
            try (BufferedReader r = new BufferedReader(new FileReader(new File(p, "cmdline")))) {
                String cmd = r.readLine();
                if (cmd == null) continue;
                String v = cmd.toLowerCase(Locale.US);
                for (String b : bad) {
                    if (v.contains(b)) {
                        return signal("suspicious_process", "instrumentation", State.DETECTED, Strength.HIGH);
                    }
                }
            } catch (Exception ignored) {}
        }
        return signal("suspicious_process", "instrumentation", State.CLEAR, Strength.HIGH);
    }

    // =========================================================
    // TRACER PID
    // =========================================================

    private Signal checkTracer() {
        try (BufferedReader r = new BufferedReader(new FileReader("/proc/self/status"))) {
            String line; int n = 0;
            while ((line = r.readLine()) != null && n++ < MAX_STATUS_LINES) {
                if (line.startsWith("TracerPid:")) {
                    String[] parts = line.trim().split("\\s+");
                    if (parts.length >= 2) {
                        int pid = Integer.parseInt(parts[1]);
                        return signal("tracer", "debug",
                                pid != 0 ? State.DETECTED : State.CLEAR, Strength.HIGH);
                    }
                }
            }
            return signal("tracer", "debug", State.UNAVAILABLE, Strength.HIGH);
        } catch (Exception e) {
            return signal("tracer", "debug", State.UNAVAILABLE, Strength.HIGH);
        }
    }

    // =========================================================
    // NAMED EXECUTABLE MAPPINGS
    // =========================================================

    private Signal checkAnonymousExec() {
        try (BufferedReader r = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line; int n = 0;
            while ((line = r.readLine()) != null && n++ < MAX_MAP_LINES) {
                String[] parts = line.split("\\s+", 6);
                if (parts.length < 2) continue;
                String perms = parts[1];
                if (perms.length() < 3) continue;
                boolean exec = perms.charAt(2) == 'x';
                if (!exec) continue;
                String path = parts.length >= 6 ? parts[5] : "";
                String lower = path.toLowerCase(Locale.US);

                if (lower.contains("frida") || lower.contains("gum-js")
                        || lower.contains("zygisk") || lower.contains("lspd")
                        || lower.contains("lsposed") || lower.contains("linjector")) {
                    return signal("anon_exec", "instrumentation", State.DETECTED, Strength.HIGH);
                }
                // Generic RWX anon mappings can be legitimate (JIT, etc.);
                // only explicit instrumentation markers count here.
            }
            return signal("anon_exec", "instrumentation", State.CLEAR, Strength.MEDIUM);
        } catch (Exception e) {
            return signal("anon_exec", "instrumentation", State.UNAVAILABLE, Strength.MEDIUM);
        }
    }

    // =========================================================
    // ENVIRONMENT VARIABLES
    // =========================================================

    private Signal checkEnvironment() {
        try {
            Map<String, String> env = System.getenv();
            String[] prefixes = { "FRIDA_", "MAGISK_", "LSPOSED_", "ZYGISK_", "XPOSED_" };
            for (String key : env.keySet()) {
                String u = key.toUpperCase(Locale.US);
                for (String p : prefixes) {
                    if (u.contains(p)) {
                        return signal("suspicious_env", "instrumentation", State.DETECTED, Strength.MEDIUM);
                    }
                }
            }
            return signal("suspicious_env", "instrumentation", State.CLEAR, Strength.MEDIUM);
        } catch (Throwable t) {
            return signal("suspicious_env", "instrumentation", State.UNAVAILABLE, Strength.MEDIUM);
        }
    }

    // =========================================================
    // /data/adb PATHS
    // =========================================================

    private Signal checkAdbPaths() {
        String[] paths = {
                "/data/adb/modules", "/data/adb/magisk", "/data/adb/magisk.db",
                "/data/adb/lspd", "/data/adb/zygisk", "/data/adb/ksu",
                "/data/adb/ap", "/data/adb/kernelsu"
        };
        try {
            for (String p : paths) {
                if (new File(p).exists()) {
                    return signal("adb_path", "root", State.DETECTED, Strength.HIGH);
                }
            }
            return signal("adb_path", "root", State.CLEAR, Strength.MEDIUM);
        } catch (SecurityException e) {
            return signal("adb_path", "root", State.UNAVAILABLE, Strength.MEDIUM);
        }
    }

    // =========================================================
    // ROOT MANAGER PACKAGES  (HIGH strength on hit)
    // =========================================================

    private Signal checkRootPackages() {
        if (cordova == null || cordova.getActivity() == null) {
            return signal("root_package", "root", State.UNAVAILABLE, Strength.MEDIUM);
        }

        try {
            PackageManager pm = cordova.getActivity().getPackageManager();
            String[] pkgs = {
                    "com.topjohnwu.magisk", "eu.chainfire.supersu",
                    "com.koushikdutta.superuser", "com.saurik.substrate",
                    "org.lsposed.manager", "org.lsposed.lspatch",
                    "io.github.lsposed.manager", "com.devadvance.rootcloak",
                    "com.devadvance.rootcloak2", "com.formyhm.hideroot",
                    "com.amphoras.hidemyroot", "com.zachspong.temprootremovejb",
                    "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro",
                    "com.noshufou.android.su", "com.noshufou.android.su.elite",
                    "com.yellowes.su", "com.kingroot.kinguser",
                    "com.kingo.root", "com.zhiqupk.root.global",
                    "com.alephzain.framaroot", "me.weishu.exp",
                    "de.robv.android.xposed.installer"
            };
            for (String p : pkgs) {
                try {
                    pm.getPackageInfo(p, 0);
                    return signal("root_package", "root", State.DETECTED, Strength.HIGH);
                } catch (PackageManager.NameNotFoundException ignored) {}
            }
            return signal("root_package", "root", State.CLEAR, Strength.HIGH);
        } catch (Exception e) {
            return signal("root_package", "root", State.UNAVAILABLE, Strength.MEDIUM);
        }
    }

    // =========================================================
    // DEBUGGER STATE
    // =========================================================

    private Signal checkDebuggerState() {
        try {
            boolean attached = Debug.isDebuggerConnected() || Debug.waitingForDebugger();
            return signal("debugger", "debug",
                    attached ? State.DETECTED : State.CLEAR, Strength.MEDIUM);
        } catch (Exception e) {
            return signal("debugger", "debug", State.UNAVAILABLE, Strength.MEDIUM);
        }
    }

    // =========================================================
    // /proc/self/exe SANITY
    // =========================================================

    private Signal checkProcSelfExe() {
        try {
            String p = new File("/proc/self/exe").getCanonicalPath();
            if (p == null) {
                return signal("proc_self_exe", "instrumentation", State.UNAVAILABLE, Strength.MEDIUM);
            }
            String lower = p.toLowerCase(Locale.US);
            if (lower.contains("frida") || lower.contains("magisk")) {
                return signal("proc_self_exe", "instrumentation", State.DETECTED, Strength.HIGH);
            }
            return signal("proc_self_exe", "instrumentation", State.CLEAR, Strength.MEDIUM);
        } catch (Exception e) {
            return signal("proc_self_exe", "instrumentation", State.UNAVAILABLE, Strength.MEDIUM);
        }
    }

    // =========================================================
    // MARKERS
    // =========================================================

    private boolean containsInstrumentationMarker(String value) {
        if (value == null || value.isEmpty()) return false;
        String v = value.toLowerCase(Locale.US);
        return v.contains("frida") || v.contains("gum-js") || v.contains("linjector")
                || v.contains("/re.frida.") || v.contains("zygisk") || v.contains("lsposed")
                || v.contains("liblspd") || v.contains("liblsplant") || v.contains("xposed")
                || v.contains("edxposed") || v.contains("riru") || v.contains("substrate")
                || v.contains("sandhook") || v.contains("yahfa") || v.contains("dobby")
                || v.contains("shadowhook");
    }

    private boolean containsFrameworkMarker(String value) {
        if (value == null || value.isEmpty()) return false;
        String v = value.toLowerCase(Locale.US);
        return v.contains("zygisk") || v.contains("lsposed") || v.contains("liblspd")
                || v.contains("liblsplant") || v.contains("libxposed") || v.contains("edxposed")
                || v.contains("riru_core");
    }

    private Signal signal(String id, String cat, State st, Strength str) {
        return new Signal(id, cat, st, str);
    }

    // =========================================================
    // JSON OUTPUT
    // =========================================================

    private JSONObject toJson(Assessment a) {
        JSONObject result = new JSONObject();
        JSONArray evidence = new JSONArray();
        JSONArray unavailable = new JSONArray();
        JSONArray unknown = new JSONArray();
        try {
            for (String r : a.unknownReasons) unknown.put(r);
            for (Signal s : a.signals) {
                if (s.state == State.DETECTED) evidence.put(s.id);
                if (s.state == State.UNAVAILABLE) unavailable.put(s.id);
            }
            result.put("status", a.status);
            result.put("statusName", statusName(a.status));
            result.put("platform", "android");
            result.put("osVersion", Build.VERSION.RELEASE);
            result.put("apiLevel", Build.VERSION.SDK_INT);
            result.put("evidence", evidence);
            result.put("unavailableChecks", unavailable);
            result.put("unknownReasons", unknown);
            result.put("localOnly", true);
        } catch (JSONException ignored) {}
        return result;
    }

    private String statusName(int s) {
        if (s == COMPROMISED) return "COMPROMISED";
        if (s == UNKNOWN) return "UNKNOWN";
        return "SAFE";
    }
}
