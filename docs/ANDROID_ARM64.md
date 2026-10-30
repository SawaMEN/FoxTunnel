# Android ARM64-v8a distribution

On each new published VetroffProxy release, `.github/workflows/android-arm64.yml`
builds a standalone Android ARMv8 64-bit AAR via gomobile and attaches:

- `vetroff_VERSION_android_arm64-v8a.aar`
- `vetroff_VERSION_android_arm64-v8a-sources.jar`
- `SHA256SUMS-android-arm64-v8a`

CI additionally uploads the AAR as a workflow artifact for main and relevant
pull requests. Prior Linux-only releases are **not** retroactively modified.
Android uses the Go transport backend: Linux NSS/Necko libraries are not bundled.

## Kotlin

Add the verified AAR to your app's Android dependencies. It contains one
`jni/arm64-v8a/libgojni.so` binary and generated Java/Kotlin-compatible
bindings (minimum Android API 24). Use the generated `com.vetroff.androidsdk`
package:

```kotlin
val session = Androidsdk.newSession(vetroffShareLink)
try {
    val port = session.startSOCKS()
    // Connect a SOCKS-aware client to 127.0.0.1:port.
} finally {
    session.stop()
}
```

The share link contains secrets. Do not log it. The SOCKS5 listener is limited
to localhost and does not require authentication, so the host should treat
it as private to the process/device. The Android host is responsible for
TUN capture, DNS/routing and excluding the **outer VetroffProxy sockets**
from its own VPN tunnel. This standalone AAR does not configure Android
VpnService or protect native sockets.

Other bindings: `statusJSON()` (aggregate local stats), `lastError()`
(fixed diagnostic label), `notifyNetworkChange()`, `stop()`.
For actual Java names inspect `classes.jar` in the AAR.

**VetrOFF Client already embeds VetroffProxy inside its sing-box Go kernel.**
Do not also load this standalone AAR into that client: it would duplicate Go
runtimes and networking layers. The AAR is for independent Android apps.
For VetrOFF Client, publish a rebuilt *hiddify-core.aar* with the SDK integrated.

CI pins Go from `go.mod`, Android NDK and gomobile revision. It checks the
ARM64 ELF architecture, Java API, computes SHA-256 and attests the release AAR.
Real Android VPN connection tests still require a device/emulator.
