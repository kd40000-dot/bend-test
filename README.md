# Bend 7.6.6 — background workout timer patch (v2)

## Current patch
Bend's workout timer uses a `java.util.Timer` inside the obfuscated `Lfn0;` class. Its `Lfr1;->i(Lm45;Lc45;)` lifecycle observer reacts to `ON_STOP` by calling `Lfn0;->d()`, which cancels the Timer and **resets the remaining time**. The targeted v2 patch replaces just that lifecycle stop invocation with three Dalvik NOPs. The explicit workout pause/stop methods and third-party timer methods remain unchanged.

The previous v1 experiment globally replaced `java.util.Timer.schedule` with `scheduleAtFixedRate`, unintentionally modifying calls in reCAPTCHA and animation classes. **Do not use the original v1 patch; it was too broad and was reported to crash on launch.**

The build repackages the APK, keeps all uncompressed files 4-byte aligned, and applies new v1 and v2 signatures with a locally generated signing key.

## Limitations
- Static APK, DEX, signature, ZIP and file-alignment verification passed. **Not yet tested on an Android device.**
- The timer can continue in the background while the Android process is alive. **This does not guarantee accuracy after process termination or Android power-management suspension**; that would need elapsed-time state reconciliation and potentially a foreground service.
- Resigning changes the app's certificate. Normally uninstall the original before installing this version, which can delete app data. Back up first.
- The original proprietary APK and private signing key should not be added to this public repository.

## Rebuild
Requirements: Python 3.10+, `cryptography`, Java `jarsigner`.

```sh
python -m pip install cryptography
python build.py Bend_original_7.6.6.apk Bend_background_v2.apk \
  --key private/BendPatch.p12 --password YOUR_PASSWORD
```

To update installations using the same patch certificate, keep your generated `private/BendPatch.p12` securely. Do not publish it.

## Validation
The patch expects exactly one target lifecycle start and stop call and refuses other versions. After building, check the app on a physical device by starting an exercise countdown, switching to another app for 30 seconds, and returning. If it still crashes, capture the beginning of an Android logcat crash stacktrace to separate signature-related crashes from the timer modification.

## Startup investigation — October 28, 2026

**Do not treat v2 as working.** On an Android 16 Fairphone, the user reports the splash screen immediately returns to the launcher. The log shows:

```
14:06:52.194  nativeloader: Load .../lib/arm64/libyrf.so ... ok
14:06:52.209  System.exit called, status: 0
14:06:52.209  AndroidRuntime: VM exiting with result code 0
14:06:52.225  Process com.bowerydigital.bend has died
```

The original and v2 APK ZIP contents differ only in `classes.dex` and `META-INF` signing files. The original `lib/arm64-v8a/libyrf.so` is byte-for-byte unchanged. Its ELF exports `JNI_OnLoad` and its strings include references to `PackageManager`, `getPackageInfo`, `CertificateFactory`, `X509Certificate`, and `MessageDigest`. This is **consistent** with a native certificate/integrity check but does not by itself prove the cause. Check signature verification and native startup behavior before attempting further releases.

Next diagnostic control: install a separately signed **unmodified** (no DEX changes) APK, using the same certificate as v2, to determine whether re-signing alone triggers the exit. Then trace the `System.exit(0)` call stack (via debugger/hook or static tracing), and check whether it originates from the native library or its caller. Preserve the user's data and original APK. No v3 release is claimed to work.
