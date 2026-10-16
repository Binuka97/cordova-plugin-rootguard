# Release procedure
## 2.1.2 release gates
# Zygisk Root Detection — Release Gates
- [ ] Review all Android Java, JavaScript, and plugin configuration changes.
- [ ] Verify package.json and plugin.xml contain the correct plugin version.
- [ ] Confirm root detection covers Magisk, Zygisk-related indicators, KernelSU, APatch, SuperSU, and root artifacts.
- [ ] Test on a clean, non-rooted device; confirm SAFE (0).
- [ ] Test on rooted devices with Magisk and Zygisk enabled; confirm COMPROMISED (1).
- [ ] Test with root-hiding enabled for the application; investigate any false SAFE (0) result.
- [ ] Verify Frida detection and instrumentation checks.
- [ ] Confirm shell-command timeouts and process cleanup prevent plugin hangs.
- [ ] Verify detection runs on the Cordova thread pool without blocking the UI.
- [ ] Confirm the existing Ionic/Cordova JavaScript API and result contract remain compatible.
- [ ] Run regression tests on supported Android versions and RootAVD test environments.
- [ ] Validate all scenarios with the VAPT team and document any undetectable bypass limitations.
- [ ] Approve the release only after test results meet the defined security requirements.

## 2.1.0 release gates

- [ ] Review every source and documentation change.
- [ ] Confirm `package.json` and `plugin.xml` both contain `2.1.0`.
- [ ] Run `npm test`.
- [ ] Compile `types/index.d.ts` with the pinned CI TypeScript version.
- [ ] Run `npm pack --dry-run` and inspect every included path.
- [ ] Run `npm publish --dry-run`.
- [ ] Build a clean Cordova Android application with Cordova Android 15.1,
      JDK 17, compile SDK 36, and target SDK 36.
- [ ] Build a clean Cordova iOS application with Cordova iOS 8.1 and a supported
      current Xcode/iPhoneOS SDK.
- [ ] Test stock physical devices before modified-device scenarios.
- [ ] Complete the VAPT retest matrix in the remediation response.
- [ ] Verify the host trading application uses the three-state API and
      server-side attestation.
- [ ] Tag the exact reviewed commit as `v2.1.0`.
- [ ] Publish from that tag using npm trusted publishing and provenance.
- [ ] Require strong npm publishing authentication and remove obsolete tokens.
- [ ] Install `cordova-plugin-rootguard@2.1.0` from npm into clean Android and
      iOS sample applications and repeat smoke tests.
- [ ] Roll out to production gradually with monitoring and rollback controls.

## Packaging commands

```sh
npm test
npm pack --dry-run
npm publish --dry-run
```

Do not run the real `npm publish` command until the native CI jobs, VAPT retest,
release review, tag, npm authentication, and rollout approvals are complete.

Prefer [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/) from
the protected release workflow. It avoids long-lived publish tokens and
automatically generates provenance for eligible public packages. Configure the
package's npm settings to require strong publishing authentication.

An npm version cannot be reused after publication. If 2.1.0 is already present
in the registry or the artifact changes after approval, increment the version and
repeat the gates.
