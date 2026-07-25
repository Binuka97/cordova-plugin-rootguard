# Cordova Plugin - RootGuard

![RootGuard](https://img.shields.io/badge/Cordova%20Plugin-RootGuard-blue.svg)
![npm](https://img.shields.io/badge/npm-v2.1.0-CB3837.svg)
![Android](https://img.shields.io/badge/Android-API%2021%2B-3DDC84.svg)
![iOS](https://img.shields.io/badge/iOS-Cordova%20iOS-lightgrey.svg)
[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/Binuka97/cordova-plugin-rootguard/main/LICENSE)

<p align="center">
  <img src="https://github.com/user-attachments/assets/c26f452a-1430-468d-a653-98ffa464898e" alt="RootGuard" />
</p>

`cordova-plugin-rootguard` provides best-effort root, jailbreak, and runtime
instrumentation detection for Cordova applications on Android and iOS.

Version 2.1.0 introduces capability-aware checks and a three-state result model
to reduce false positives on modern Android devices. Errors, restricted
operating-system capabilities, and timeouts are reported as `UNKNOWN`; they are
not treated as proof that a device is compromised.

## Features

### Android

- Detects accessible root, `su`, Magisk, KernelSU, and APatch artifacts.
- Inspects the current process for Frida, Frida Gadget, Gum, and related markers.
- Checks memory maps, file descriptors, thread names, and bounded local ports.
- Probes default and discoverable custom ports for a Frida-compatible protocol.
- Does not execute `su`, `mount`, `which`, `pidof`, `getprop`, or shell commands.
- Returns `UNKNOWN` when modern Android restrictions prevent a reliable local
  conclusion.

### iOS

- Detects common rootful and rootless jailbreak artifacts.
- Performs a sandbox write-escape test.
- Checks loaded images, exported Frida symbols, thread names, open descriptors,
  injected loader state, debugger state, and bounded Frida ports.
- Avoids generic paths such as `/private/preboot` that can exist on stock iOS.
- Runs checks outside the Cordova WebView/UI thread.

> [!IMPORTANT]
> RootGuard is a local risk sensor, not a trust anchor. An attacker who controls
> a device can hide artifacts, hook these checks, or replace their result. Do
> not use this plugin as the only control for login, trading, payments,
> withdrawals, account recovery, or other sensitive operations. Read
> [SECURITY.md](SECURITY.md) and
> [ENTERPRISE-INTEGRATION.md](ENTERPRISE-INTEGRATION.md).

## Installation

### Install the published npm version

```sh
cordova plugin add cordova-plugin-rootguard@2.1.0
```

To follow the latest compatible published release:

```sh
cordova plugin add cordova-plugin-rootguard
```

### Install from GitHub

Use a release tag for reproducible builds:

```sh
cordova plugin add https://github.com/Binuka97/cordova-plugin-rootguard.git#v2.1.0
```

### Install from a local clone

```sh
git clone https://github.com/Binuka97/cordova-plugin-rootguard.git
cordova plugin add ./cordova-plugin-rootguard
```

### Upgrade an existing installation

```sh
cordova plugin remove cordova-plugin-rootguard
cordova plugin add cordova-plugin-rootguard@2.1.0
```

After adding or upgrading the plugin, rebuild the native platforms:

```sh
cordova prepare
cordova build android
cordova build ios
```

Do not manually copy plugin files into the generated `platforms/` directory.
Cordova regenerates that directory and can overwrite manual changes.

## Requirements

- Cordova 9.0.0 or newer
- Android API 21 or newer
- A `cordova-ios` version supporting the target iOS/Xcode release

The project CI currently exercises Cordova Android 15.1 and Cordova iOS 8.1,
along with JavaScript, TypeScript, metadata, and package tests.

No JavaScript import is required in a normal Cordova application. The plugin
exposes the global `RootGuard` object after Cordova fires `deviceready`.

## Quick start

Use `checkSecurityStatus()` for all new integrations:

```js
document.addEventListener("deviceready", function () {
    RootGuard.checkSecurityStatus(function (status) {
        switch (status) {
        case RootGuard.SAFE:
            // No local compromise indicator was found.
            // Continue with the application's normal server-side controls.
            console.log("RootGuard status: SAFE");
            break;

        case RootGuard.COMPROMISED:
            // Strong or corroborated local evidence was found.
            // Apply a proportionate risk policy or request server-side step-up.
            console.warn("RootGuard status: COMPROMISED");
            break;

        case RootGuard.UNKNOWN:
            // The result is inconclusive. Do not label the user as rooted.
            // Request platform attestation or another server-side verification.
            console.warn("RootGuard status: UNKNOWN");
            break;
        }
    }, function (error) {
        // A bridge/plugin error is inconclusive, not proof of compromise.
        console.error("RootGuard check failed", error);
    });
}, false);
```

## Result values

| Constant | Value | Meaning |
|---|---:|---|
| `RootGuard.SAFE` | `0` | Checks completed and no local indicator was found |
| `RootGuard.COMPROMISED` | `1` | Strong evidence, or corroborated independent evidence, was detected |
| `RootGuard.UNKNOWN` | `2` | A capability was unavailable or the local result is inconclusive |

`SAFE` means only that the plugin found no local indicator. It does not prove
that the device or application is trustworthy.

On Android 13 and newer, a result with no strong local compromise evidence is
intentionally `UNKNOWN`, because local absence checks cannot establish verified
boot or application integrity. Use backend-verified Play Integrity for that
purpose.

## Detailed result

Use `checkSecurityDetailed()` when the application needs coarse diagnostic
telemetry:

```js
document.addEventListener("deviceready", function () {
    RootGuard.checkSecurityDetailed(function (result) {
        console.log(result.status);            // 0, 1, or 2
        console.log(result.statusName);        // SAFE, COMPROMISED, or UNKNOWN
        console.log(result.platform);          // android or ios
        console.log(result.osVersion);
        console.log(result.apiLevel);          // Android only
        console.log(result.evidence);
        console.log(result.unavailableChecks);
        console.log(result.unknownReasons);
        console.log(result.localOnly);         // always true
    }, function (error) {
        console.error("RootGuard check failed", error);
    });
}, false);
```

Example response:

```json
{
  "status": 2,
  "statusName": "UNKNOWN",
  "platform": "android",
  "osVersion": "16",
  "apiLevel": 36,
  "evidence": [],
  "unavailableChecks": [],
  "unknownReasons": [
    "modern_android_local_integrity_unverifiable"
  ],
  "localOnly": true
}
```

The detailed result contains:

| Property | Type | Description |
|---|---|---|
| `status` | `0 \| 1 \| 2` | Stable numeric status |
| `statusName` | `string` | `SAFE`, `COMPROMISED`, or `UNKNOWN` |
| `platform` | `string` | `android` or `ios` |
| `osVersion` | `string` | Device operating-system version |
| `apiLevel` | `number` | Android API level; absent on iOS |
| `evidence` | `string[]` | Coarse categories detected locally |
| `unavailableChecks` | `string[]` | Checks unavailable in the environment |
| `unknownReasons` | `string[]` | Stable reason codes explaining an `UNKNOWN` result |
| `localOnly` | `true` | Indicates that this is not a server attestation |

`unknownReasons` is additive and is present in RootGuard 2.1.0 detailed native
results. Clients should still use `result.unknownReasons || []` when supporting
older installed versions.

### Possible `UNKNOWN` scenarios

| Reason code | Scenario | Recommended handling |
|---|---|---|
| `modern_android_local_integrity_unverifiable` | Android 13 or newer has no conclusive local compromise evidence, but local absence checks cannot prove device integrity | Request backend-verified Play Integrity or apply proportionate step-up |
| `single_medium_signal` | Exactly one ambiguous indicator was detected, such as a non-production build, generic GLib thread, open local port, or debugger state | Review `evidence`; do not label the device rooted without corroboration |
| `critical_check_unavailable` | A critical inspection capability, such as process maps, root checks, or iOS thread enumeration, was unavailable | Review `unavailableChecks` and use platform attestation |
| `assessment_exception` | The native assessment encountered an unexpected internal exception | Treat as an operationally inconclusive result and collect non-sensitive diagnostics |
| `ios_simulator` | The application is running in the iOS Simulator, where a physical-device jailbreak conclusion is not meaningful | Use a physical device for security validation |
| `assessment_deadline` | Reserved for a future overall assessment deadline | Treat as inconclusive; never as proof of compromise |

More than one reason may be returned. For example, a modern Android device can
report both `critical_check_unavailable` and
`modern_android_local_integrity_unverifiable`.

Client-side inspection example:

```js
RootGuard.checkSecurityDetailed(function (result) {
    if (result.status !== RootGuard.UNKNOWN) {
        return;
    }

    var reasons = result.unknownReasons || [];
    console.warn("RootGuard UNKNOWN reasons:", reasons);
    console.warn("Unconfirmed evidence:", result.evidence);
    console.warn("Unavailable checks:", result.unavailableChecks);

    // UNKNOWN is inconclusive. Do not classify the device as rooted solely
    // because this array contains a reason.
}, function (error) {
    console.error("RootGuard check failed", error);
});
```

Treat `evidence`, `unavailableChecks`, and `unknownReasons` as internal security
telemetry. Do not display exact detection information to end users.

## Promise wrapper

The Cordova API is callback-based. Applications that prefer promises can wrap
it without changing the plugin:

```js
function getRootGuardStatus() {
    return new Promise(function (resolve, reject) {
        RootGuard.checkSecurityStatus(resolve, reject);
    });
}

document.addEventListener("deviceready", async function () {
    try {
        const status = await getRootGuardStatus();

        if (status === RootGuard.COMPROMISED) {
            console.warn("Local compromise evidence detected");
        } else if (status === RootGuard.UNKNOWN) {
            console.warn("Local security status is inconclusive");
        }
    } catch (error) {
        console.error("RootGuard check failed", error);
    }
}, false);
```

## Legacy API and migration

The original `checkSecurity()` API remains available for applications upgrading
from version 1.x or 2.0.x:

```js
document.addEventListener("deviceready", function () {
    RootGuard.checkSecurity(function (compromised) {
        if (compromised === 1) {
            console.warn("Local compromise evidence detected");
        }
    }, function (error) {
        console.error("RootGuard check failed", error);
    });
}, false);
```

The legacy method returns only:

- `0`: no confirmed compromise evidence
- `1`: compromise evidence detected

For backward compatibility, native `UNKNOWN` results map to `0`. This prevents
an upgrade from unexpectedly locking out existing users, but it also means the
legacy method cannot distinguish `SAFE` from `UNKNOWN`.

New and security-sensitive integrations must use `checkSecurityStatus()` or
`checkSecurityDetailed()`.

## TypeScript

Type declarations are included in the npm package:

```ts
document.addEventListener("deviceready", () => {
    RootGuard.checkSecurityStatus((status: RootGuard.Status) => {
        if (status === RootGuard.COMPROMISED) {
            console.warn("Local compromise evidence detected");
        }
    }, console.error);
});
```

The declaration exposes `RootGuard.Status`, `RootGuard.DetailedResult`, the
three constants, and all three API methods.

## Recommended production policy

For financial, trading, payment, identity, or regulated applications:

1. Use RootGuard as one local risk signal.
2. Verify Google Play Integrity or Apple App Attest on a trusted backend.
3. Bind fresh attestation challenges to the sensitive request.
4. Keep authentication, authorization, limits, and transaction validation on
   the server.
5. Observe status rates by OS and device model before enabling enforcement.
6. Prefer step-up verification and recoverable restrictions over permanent
   account lockouts.

Suggested handling:

| RootGuard result | Suggested application behavior |
|---|---|
| `SAFE` | Continue with normal backend authorization and attestation |
| `UNKNOWN` | Request fresh attestation or proportionate step-up verification |
| `COMPROMISED` | Restrict or step up sensitive operations according to server policy |
| Plugin error | Treat as inconclusive and request server-side verification |

Never authorize or reject a sensitive transaction solely from a value returned
by JavaScript or native client code.

## Detection limitations

RootGuard raises the cost of common attacks but cannot provide guaranteed
detection:

- Magisk DenyList, Zygisk modules, and customized root solutions can hide
  artifacts from an application.
- Frida Server can be renamed or use a custom port.
- Frida Gadget can be renamed, embedded, or modified to remove common markers.
- iOS Shadow and similar tweaks can hook filesystem, loader, socket, process,
  and Cordova APIs.
- An attacker can patch the application or force a different plugin response.

See [SECURITY.md](SECURITY.md) for the threat model and primary references.

## Troubleshooting

### `RootGuard` is undefined

Call the plugin only after Cordova's `deviceready` event. Confirm that the plugin
is installed:

```sh
cordova plugin list
```

If necessary, remove and add the plugin again, then run `cordova prepare`.

### Native changes are not appearing

Remove and regenerate the affected Cordova platform:

```sh
cordova platform remove android
cordova platform add android
```

For iOS, replace `android` with `ios`. Commit or back up any intentional host
application platform changes before removing a platform.

### A stock device returns `UNKNOWN`

This can be expected on Android 13 and newer or whenever a required local
capability is restricted. `UNKNOWN` does not mean rooted. Use backend
attestation or step-up verification.

### A rooted or jailbroken device returns `SAFE` or `UNKNOWN`

Local checks can be concealed or hooked. Confirm that you are testing a release
build, review `checkSecurityDetailed()` internally, test platform attestation,
and do not depend on RootGuard as the sole security boundary.

### The app becomes slow during a check

Version 2.1.0 does not execute shell commands and uses bounded network probes on
Cordova background workers. If a device remains slow, collect the platform, OS,
device model, plugin result, and timing without exposing sensitive user data,
then open an issue.

## Testing your integration

Before production rollout, test:

- Stock Android devices across Android 12, 13, 14, 15, and 16, including
  relevant OEM ROMs.
- Rooted Android test devices with the root frameworks supported by your threat
  model.
- Frida Server using default and non-default configurations.
- Frida Gadget injection in a controlled test build.
- Stock and jailbroken physical iOS devices.
- iOS runtime-hooking and jailbreak-hiding tools included in your threat model.
- Offline, degraded-service, plugin-error, and `UNKNOWN` handling.
- Debug and release application builds.

Run the plugin's package tests:

```sh
npm test
npm pack --dry-run
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history and migration notes.

## Security

Please report vulnerabilities privately to the maintainer address in
`package.json`. Do not post credentials, customer information, or proprietary
assessment reports in a public issue.

## Support and contributing

Bug reports and contributions are welcome through
[GitHub Issues](https://github.com/Binuka97/cordova-plugin-rootguard/issues).
Include the plugin version, Cordova platform version, operating-system version,
device model, and a minimal reproduction when possible.

## License

This project is licensed under the [MIT License](LICENSE).

## Author

**Binuka Kamesh**<br>
Email: [binukakamesh97@gmail.com](mailto:binukakamesh97@gmail.com)<br>
GitHub: [Binuka97](https://github.com/Binuka97)

---

Maintained by Binuka Kamesh.
