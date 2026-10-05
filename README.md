# Lab421Licensing

Shared Swift package for the Lab421 licensing system in macOS apps. It manages
trials, license activation, validation and deactivation, Keychain storage, and
offline verification of signed Ed25519 tokens.

Requires **Swift 6.3** and **macOS 14 or later**. The package has no external
dependencies. Error messages and access-state descriptions include English,
French, German, Spanish and Italian translations.

## Installation

Add the package to your app's `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/lab421/licensing.git", branch: "main"),
],
targets: [
    .target(
        name: "MyApp",
        dependencies: [
            .product(name: "Lab421Licensing", package: "licensing"),
        ]
    ),
]
```

For local development, use `.package(path: "../licensing")` instead.

## Usage

Create and retain one manager per app on the main actor:

```swift
import Foundation
import Lab421Licensing

@MainActor
func makeLicenseManager(publicKeyRaw: Data) -> LicenseManager {
    let manager = LicenseManager(
        isEnabled: true,
        productID: "my-app",
        appName: "My App",
        deviceNameFallback: "My Mac",
        secureStore: KeychainLicenseStore(service: "com.example.myapp.license"),
        deviceIdentifierProvider: HardwareDeviceIdentifierProvider(
            userDefaultsSuiteName: "com.example.myapp"
        ),
        offlineTokenPublicKeyRaw: publicKeyRaw
    )
    manager.start()
    return manager
}
```

Use your app's registered product ID, its own Keychain service and UserDefaults
suite, and the raw 32-byte Ed25519 public key matching the server's signing key.
Pass `baseURL` to override the default Lab421 licensing endpoint.
Pass `isEnabled: false` for a distribution that does not use direct licensing.

Observe `state`, `isWorking` and `lastError` to update your UI. Use `hasAccess` to
gate app features and `state.isDefinitivelyDenied` to decide when to present a
license prompt. The app owns the licensing UI.

```swift
await manager.activate(licenseKey: enteredKey)
await manager.validate(force: true)
await manager.deactivate()
manager.importLicenseToken(signedToken)
```

The manager exposes licensed, trial and initial offline-grace states. Keep it
alive for the app's lifetime and call `start()` to synchronize access.

See [SECURITY.md](SECURITY.md) for integration precautions.

## Development

```sh
swift build
swift test
```

Tests cover the API client, license manager, offline tokens, Keychain storage,
device identifiers and localization. The test target includes framework search
paths for Swift Testing when using Apple's Command Line Tools without full Xcode.
