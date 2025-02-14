# Cordova Plugin - RootGuard

**RootGuard** is a Cordova plugin designed to detect if an Android device is rooted and if Frida-based debugging or root bypass techniques are being used.

## 📌 Features
- ✅ Detects root access (e.g., presence of `su`, known root apps, and system modifications)
- ✅ Detects Frida-based debugging and instrumentation
- ✅ Efficient and lightweight detection
- ✅ Easy integration with Cordova applications

## 🚀 Installation
To install the plugin in your Cordova project, run the following command:

```sh
cordova plugin add https://github.com/your-repo/cordova-plugin-rootguard.git
```

## 📖 Usage
### JavaScript API
The plugin provides a single function `checkSecurity` that checks for both root access and Frida detection.

#### Example:
```js
RootGuard.checkSecurity(function(result) {
    if (result === 1) {
        console.log("Security Risk Detected: Root or Frida is present.");
    } else {
        console.log("Device is secure.");
    }
}, function(error) {
    console.error("Error:", error);
});
```

## 🔧 How It Works
1. **Root Detection:**
   - Checks for the presence of `su` binaries, Superuser APK, and other known root-related files.
   - Scans system paths where root binaries might be located.
2. **Frida Detection:**
   - Reads `/proc/self/maps` to detect Frida-related libraries and runtime modifications.
   - Looks for Frida-specific memory mappings.

## 📜 License
This project is licensed under the MIT License.

## 👨‍💻 Contributing
We welcome contributions! Feel free to submit a pull request or report issues on the repository.

## 🛠 Support
For any issues, please open a GitHub issue in the repository.

---

**Maintained by Binuka Kamesh**