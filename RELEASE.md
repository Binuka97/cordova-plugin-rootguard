# Release procedure

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
