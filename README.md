# Bend 7.6.6 — background timer experiment

Patches the user's original **Bend 7.6.6** APK to use `java.util.Timer.scheduleAtFixedRate` instead of `Timer.schedule` for repeating timers. This allows callbacks that Android delayed while the app was in the background to catch up later.

## Status and limitations
- **DEX patch verified:** `classes.dex` method-ID replacement is structurally valid; checksums recomputed.
- **APK built and validated:** ZIP CRC, DEX checksum, JAR/v1 signature, APK v2 signature and content digest.
- **Not tested on-device.** A fixed-rate timer helps with delayed callbacks, but cannot guarantee continuous execution if Android kills the app or if a different app component explicitly pauses.
- This is a **method-ID replacement**, so it changes every call to the same `Timer.schedule(TimerTask,long,long)` overload in `classes.dex`, not just the workout counter. Future versions should use more narrowly scoped bytecode instrumentation.
- Signing with a new key means you usually must uninstall the original APK before installing the modified one. Back up user data first. Keep the generated PKCS#12 signing key private for updates.

## Rebuild
Requires Python 3.10+, `cryptography`, and Java `jarsigner`.

```bash
python -m pip install cryptography
python build.py original-bend-7.6.6.apk Bend-background-timer.apk \
  --key private/BendPatch.p12 --password YOUR_SECRET_PASSWORD
```

When the key does not exist, the build script generates one. **Never commit the original proprietary APK, signed APK, or private key to this public repository.**

## Files
- `dexinspect.py`: minimal DEX method table reader.
- `patchdex.py`: precise DEX patch with DEX signature/checksum fix.
- `build.py`: unsigned repack, v1 signing, 4-byte resource alignment, v2 signing and verification.

The source APK itself is not redistributed here.
