# Cordova Plugin - RootGuard : cordova-plugin-rootguard

![RootGuard](https://img.shields.io/badge/Cordova%20Plugin-RootGuard-blue.svg)

**`cordova-plugin-rootguard`** is a security plugin for Cordova that detects:
✅ **Root Access** (Magisk, SuperSU, `su` binaries, system modifications)  
✅ **Frida Runtime Instrumentation** (open ports, injected libraries, running processes)

## 📌 Features
- ✅ Detects root access (e.g., presence of `su`, known root apps, and system modifications)
- ✅ Detects Frida-based debugging and instrumentation
- ✅ Efficient and lightweight detection
- ✅ Easy integration with Cordova applications
- ✅ Compatible with Cordova Android projects.
---

## 🚀 Installation

### **Option 1: Install from GitHub**
```sh
cordova plugin add https://github.com/binuka97/cordova-plugin-rootguard.git
```

### **Option 2: Install Locally**
1. Download and place the `cordova-plugin-rootguard/` folder inside your project.
2. Run:
   ```sh
   cordova plugin add ./cordova-plugin-rootguard
   ```

---

## 📖 Usage
### JavaScript API
The plugin provides a single function `checkSecurity` that checks for both root access and Frida detection.

## 🔍 Usage
```js
RootGuard.checkSecurity(function(result) {
    if (result === 1) {
        console.log("Security status: " + (result ? "Compromised" : "Safe"));
        console.log("Security Risk Detected: Root or Frida is present.");
    } else {
        console.log("Device is secure.");
    }
}, function(error) {
    console.error("Error detecting Root/Frida:", error);
});
```

---

## 🔧 How It Works
### Root Detection
- **File Check**: Scans for common root-related files (e.g., `su`, `Superuser.apk`, `.magisk`).
- **Command Execution**: Attempts to execute `su` to check for root access.
- **Mount Check**: Verifies if `/system` is mounted as read-write instead of read-only.

### Frida Detection
- **Port Scan**: Checks for Frida's default listening ports (`27042`, `27043`).
- **Memory Scan**: Reads `/proc/self/maps` to detect Frida-related libraries (`frida`, `gum-js`, `gadget`).
- **Process Check**: Looks for a running `frida-server` process.
- **Property Check**: Scans system properties for any Frida-related entries.

---

## 🛠️ Testing
### **Testing Root Detection**
1. Install **Magisk** or **SuperSU** on your Android device.
2. Run your Cordova app. It should detect root and exit.

### **Testing Frida Detection**
1. Start Frida-server on the device:
   ```sh
   adb push frida-server /data/local/tmp/
   adb shell chmod 755 /data/local/tmp/frida-server
   adb shell /data/local/tmp/frida-server &
   ```
2. Run your Cordova app. It should detect Frida and exit.

---

## Supported Platforms
✅ **Android** (Minimum SDK: API 21+)
❌ iOS (Not supported yet)

---

## Troubleshooting
### Common Issues & Fixes
**1. Plugin Not Found After Installation**  
Run `cordova platform remove android && cordova platform add android` to refresh plugins.

**2. App Crashes on Certain Devices**  
Ensure the plugin has the required permissions and that your app has `minSdkVersion` set to **21 or higher** in `config.xml`.

**3. False Positives or False Negatives**  
Root detection can vary across devices. Consider adding additional root detection methods if needed.

---

## 📜 License
This project is licensed under the MIT License.

## 👨‍💻 Contributing
We welcome contributions! Feel free to submit a pull request or report issues on the repository.

## 🛠 Support
For any issues, please open a GitHub issue in the repository.

---

## Author
📌 **Binuka Kamesh**  
📧 Contact: [binukakamesh97@gmail.com](mailto:binukakamesh97@gmail.com)  
🌍 GitHub: [binuka97](https://github.com/binuka97)

---

**Maintained by Binuka Kamesh**