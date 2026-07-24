# Security model and limitations

RootGuard is a local risk sensor, not a trust anchor. Code executing on a
compromised device can inspect, hook, patch, or replace every client-side check
and its return value. No open-source Cordova plugin can promise 100% detection.

## Result policy

| Status | Value | Meaning | Recommended action |
|---|---:|---|---|
| `SAFE` | 0 | Checks completed and found no local indicator | Continue; apply normal server controls |
| `COMPROMISED` | 1 | Strong evidence, or two independent medium indicators | Step up, restrict sensitive actions, or block according to risk |
| `UNKNOWN` | 2 | A capability was unavailable, one weak indicator exists, or local checks cannot establish trust | Do not automatically label the user rooted; request attestation or step up |

An exception, permission denial, connection timeout, or inaccessible file is
never evidence of compromise.

## Android

Magisk DenyList and Zygisk modules can selectively hide files, mounts, processes,
properties, and injected code from this app. Frida Server can use a different
port, and Frida Gadget can be renamed and configured without a listening socket.
These are fundamental limits of in-process heuristics.

For sensitive server operations, use Play Integrity standard requests with a
fresh request hash, decrypt and verify the token on a trusted backend, validate
app recognition and licensing, and apply a tiered policy to device-integrity
labels. Do not accept a verdict decoded or asserted only by the client.

RootGuard intentionally reports `UNKNOWN` on Android 13+ when it finds no strong
local evidence. This is not a claim that `/proc/self` is universally unreadable;
it means local absence checks cannot prove a certified boot state.

## iOS

Shadow and similar tweaks can hook filesystem, dynamic-loader, process, socket,
and Cordova result APIs. A renamed payload can evade string indicators, while a
patched application can simply force a safe return. RootGuard adds independent
checks to raise bypass cost, but cannot guarantee Shadow detection.

Use App Attest for sensitive backend requests. Generate and attest a per-install
key, validate attestations on the server, bind assertions to one-time challenges
and request payloads, and enforce monotonic counters. Apple explicitly describes
App Attest as one signal in a broader risk assessment, not definitive jailbreak
detection. Roll out enforcement gradually and handle unsupported or transient
service states.

## Operational guidance

- Never exit or permanently lock an account based only on this plugin.
- Keep security decisions and valuable data on the server.
- Treat diagnostic `evidence` as telemetry; do not display exact checks to users.
- Test stock and modified physical devices across OEMs and OS updates.
- Maintain an allow/observe phase before changing enforcement.
- Rate-limit sensitive operations and retain a recoverable support path.

Please report vulnerabilities privately to the maintainer contact in
`package.json`. Do not include user data, live credentials, or proprietary
assessment material in a public issue.

## Primary references

- [Google Play Integrity overview](https://developer.android.com/google/play/integrity/overview)
- [Google Play Integrity verdicts](https://developer.android.com/google/play/integrity/verdicts)
- [Apple: Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
- [Apple DeviceCheck and App Attest](https://developer.apple.com/documentation/devicecheck)
- [Apache Cordova Android plugin threading](https://cordova.apache.org/docs/en/latest/guide/platforms/android/plugin.html)
- [Apache Cordova iOS plugin threading](https://cordova.apache.org/docs/en/latest/guide/platforms/ios/plugin.html)
- [Frida modes of operation](https://frida.re/docs/modes/)
- [Frida Gadget configuration and renaming](https://frida.re/docs/gadget/)
- [OWASP reverse-engineering tool detection](https://mas.owasp.org/MASTG-KNOW-0030/)
- [OWASP Android anti-reversing limitations](https://mas.owasp.org/MASTG/0x05j-Testing-Resiliency-Against-Reverse-Engineering/)
- [Magisk source and documentation](https://github.com/topjohnwu/Magisk)
- [Shadow jailbreak-detection bypass](https://github.com/jjolano/shadow)
