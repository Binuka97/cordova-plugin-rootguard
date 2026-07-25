# Enterprise integration profile

This profile is intended for regulated or financially sensitive Cordova
applications, including trading applications.

## Mandatory policy

RootGuard is local risk telemetry. It must not be the component that authorizes
orders, withdrawals, beneficiary changes, credential recovery, device
enrollment, or other high-value actions.

For every sensitive operation:

1. Authenticate the user and authorize the operation on the backend.
2. Bind a fresh server challenge to the exact operation and material request
   fields.
3. Verify platform attestation on the backend:
   - Android: [Play Integrity](https://developer.android.com/google/play/integrity/overview)
     app recognition, licensing, request binding, and an appropriate
     device-integrity tier.
   - iOS: [App Attest](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
     key attestation followed by per-request assertions and monotonic-counter
     validation.
4. Add RootGuard status and coarse evidence as risk telemetry.
5. Apply rate, velocity, behavioral, account, and transaction controls.
6. Keep a recoverable step-up and support route for legitimate customers.

Never trust an attestation token decoded, validated, or asserted only by the
client.

## Required API

High-risk applications must use `checkSecurityStatus()` or
`checkSecurityDetailed()`. The legacy `checkSecurity()` method maps `UNKNOWN` to
0 for compatibility and is not suitable as the sole enforcement input.

```js
RootGuard.checkSecurityDetailed(function (localRisk) {
    sendRiskTelemetry(localRisk);

    if (localRisk.status === RootGuard.COMPROMISED) {
        requestServerRiskDecision({ localRisk: "compromised" });
        return;
    }

    if (localRisk.status === RootGuard.UNKNOWN) {
        requestFreshPlatformAttestation({ stepUp: true });
        return;
    }

    // SAFE means only that no local indicator was found. A sensitive action
    // still requires the normal server-side authorization and attestation.
    requestFreshPlatformAttestation({ stepUp: false });
}, function () {
    // Plugin errors are operationally inconclusive, not proof of compromise.
    requestFreshPlatformAttestation({ stepUp: true });
});
```

## Suggested server decision tiers

| Local status | Valid attestation | Suggested handling |
|---|---|---|
| `SAFE` | Strong/accepted | Continue under normal transaction controls |
| `UNKNOWN` | Strong/accepted | Continue or step up according to transaction risk |
| `COMPROMISED` | Strong/accepted | Step up, restrict high-risk operations, and investigate signal disagreement |
| Any | Missing, invalid, replayed, or mismatched | Reject the sensitive request or require remediation |

Do not permanently lock an account solely because one device is
`COMPROMISED`. Device compromise and account ownership are different questions.

## Mobile build controls

- Build a release artifact from a protected CI environment.
- Keep signing keys outside the repository.
- Enable Android release shrinking/obfuscation in the host application and test
  all Cordova bridge calls afterward.
- Disable WebView debugging in production.
- Store no trading secrets, backend authorization rules, or reusable privileged
  credentials in JavaScript or native client code.
- Use TLS and independently maintained certificate/key-management controls.
- Require supported app versions and maintain an emergency revocation path.
- Verify the packaged plugin version and source after Cordova platform
  regeneration; never patch generated `platforms/` code directly.

## Rollout

1. Deploy in observe-only mode.
2. Measure outcomes by app version, platform, OS, OEM/model, and distribution
   channel without collecting unnecessary personal data.
3. Exercise stock, rooted/jailbroken, Magisk/Zygisk, Frida Server, Frida Gadget,
   Shadow, offline, degraded-service, and timeout cases.
4. Review false positives and false negatives with the fraud and support teams.
5. Introduce step-up controls before denials.
6. Roll back enforcement independently from the mobile binary when possible.

## Residual risk

Client-side detection can be hooked, patched, hidden, or replaced. A determined
attacker with control of the device can eventually bypass local checks. RootGuard
raises cost and produces useful telemetry; it does not create a trusted execution
environment.
