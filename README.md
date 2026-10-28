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
