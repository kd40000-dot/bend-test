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

## Control APK result
The user installed the no-DEX-modification, re-signed control APK and reported the **same immediate launcher-return** as v2. This rules out the timer bytecode change as a necessary cause. The shared change is repackaging/re-signing. Native `libyrf.so` integrity/certificate enforcement remains a hypothesis, not confirmed. Do not ship another timer patch until a re-signed baseline can launch. Diagnose certificate checks and consider distinguishing rebuilt ZIP structure from signing certificate. The next test should ideally capture a `System.exit(0)` call stack or native backtrace.

## Byte-for-byte control comparison
Local ZIP entry comparison of the original `Bend_(7.6.6)(1).apk` and the failing `Bend_7.6.6_Resigned_Control.apk` gives the following: both have 2,113 entries; **all non-META-INF entries have exactly identical uncompressed bytes**, including every DEX file, resources and ARM native libraries. Re-signed control changes `META-INF/MANIFEST.MF`, replaces `YOUAREFINISHED.RSA` / `YOUAREFINISHED.SF` with `BENDPATC.RSA` / `BENDPATC.SF`, and changes signing metadata. The native library `libyrf.so` exports `JNI_OnLoad` and contains the Java strings `java/lang/System`, `java/lang/Runtime`, `getPackageInfo`, `java/security/cert/X509Certificate`, and `java/security/MessageDigest`. These establish certificate-handling code is present but do not prove its branch decisions.

Given that only signature material changed in the failing control, the strongest supported diagnosis is that **signature-dependent startup behavior rejects the replacement certificate** (or a signature-related packaging assumption). Changing the workout DEX again cannot solve this. Do not claim a tested working replacement APK until this problem is resolved. A proper next experiment is to observe which code path invokes `System.exit(0)` on-device, preferably with a stack trace at that call and a baseline trace of the original app.

## Diagnostic result — Crashlytics exit-handler hypothesis

Static inspection found exactly **three** `java/lang/System.exit(I)` call sites inside `classes2.dex` class `Ljt1;->uncaughtException(Thread, Throwable)`, a Firebase Crashlytics uncaught-exception handler. The other DEX direct exit site is in Google Phenotype's `PhenotypeProcessReaper`. The normal-looking `System.exit(0)` in the startup log **may be the Crashlytics handler masking a Java startup exception**. This reduces certainty of the earlier certificate-only root cause hypothesis; re-signing remains the trigger, but the failure mechanism is not established.

A diagnostic APK was built locally using original code and assets with only three replacement instructions in `classes2.dex`: each Crashlytics `invoke-static System.exit(I)` becomes `invoke-virtual Throwable.printStackTrace()`, passing its exception argument `p2/v14`. Both instructions are three Dalvik code units, so the change preserves instruction layout. ZIP CRC, DEX checksums, v1/v2 signatures, APK v2 content digest, and unchanged non-signature files (except `classes2.dex`) were verified. This is **not a corrected Bend release**; it is a diagnostic. If Crashlytics is responsible, a new logcat should include the original exception stack trace. If not, the native exit hypothesis remains viable. Install only for collecting a diagnostic log and return to the original app afterward.
