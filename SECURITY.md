# Security considerations

Use the registered product ID and signing public key for your app, and configure
its own Keychain service and UserDefaults suite. Signing private keys and server
credentials must never be included in an app or this package.

Use `LicenseManager` for access decisions and observe its published state.
Direct users of `OfflineLicenseToken.verify` must also check the returned
product ID and entitlement against their intended use.

Offline verification reflects a signed entitlement, not the server's current
status. Applications requiring live authorization must obtain it from the API.
Treat client code, local storage and device identifiers as client-side data;
the server must enforce its own authorization.
