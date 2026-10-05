import CryptoKit
import Foundation

/// Authenticated payload returned by offline token verification.
public struct OfflineLicensePayload: Equatable, Sendable {
    /// `nil` for a trial token, which proves a trial period rather than a
    /// purchased license.
    public var licenseKey: String?
    public var deviceID: String
    public var productID: String
    /// `nil` denotes a perpetual license token. Trial tokens require an expiry.
    public var validUntil: Date?
}

public enum OfflineLicenseTokenError: Error, Equatable, Sendable {
    case malformed
    case invalidSignature
    case deviceMismatch
    case expired
}

public enum OfflineLicenseToken {
    /// Verifies a `base64url(payload).base64url(signature)` token: checks the
    /// Ed25519 signature over the raw payload bytes, then that it was issued
    /// for `deviceID` and hasn't passed its `validUntil` (if any).
    /// Callers must also check the returned product and entitlement against
    /// their intended use. `LicenseManager` performs these checks for apps.
    public static func verify(
        _ token: String,
        deviceID: String,
        now: Date,
        publicKeyRaw: Data
    ) throws -> OfflineLicensePayload {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 2,
              let payloadData = Data(base64URLEncoded: String(parts[0])),
              let signatureData = Data(base64URLEncoded: String(parts[1])) else {
            throw OfflineLicenseTokenError.malformed
        }

        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyRaw)
        guard publicKey.isValidSignature(signatureData, for: payloadData) else {
            throw OfflineLicenseTokenError.invalidSignature
        }

        guard let json = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any],
              let payloadDeviceID = json["device_id"] as? String,
              let productID = json["product_id"] as? String,
              !payloadDeviceID.isEmpty, !productID.isEmpty else {
            throw OfflineLicenseTokenError.malformed
        }
        let licenseKey = json["license_key"] as? String
        if let raw = json["license_key"], !(raw is NSNull) {
            guard let licenseKey, !licenseKey.isEmpty else {
                throw OfflineLicenseTokenError.malformed
            }
        }

        guard payloadDeviceID == deviceID else {
            throw OfflineLicenseTokenError.deviceMismatch
        }

        var validUntil: Date?
        if let raw = json["valid_until"], !(raw is NSNull) {
            guard let validUntilString = raw as? String,
                  let parsed = Self.dateFormatter().date(from: validUntilString) else {
                throw OfflineLicenseTokenError.malformed
            }
            validUntil = parsed
        }

        if let validUntil, now >= validUntil {
            throw OfflineLicenseTokenError.expired
        }

        return OfflineLicensePayload(
            licenseKey: licenseKey,
            deviceID: payloadDeviceID,
            productID: productID,
            validUntil: validUntil
        )
    }
}

private extension OfflineLicenseToken {
    /// Token timestamps use ISO 8601 with fractional seconds.
    static func dateFormatter() -> ISO8601DateFormatter {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }
}

private extension Data {
    init?(base64URLEncoded string: String) {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 {
            base64.append("=")
        }
        self.init(base64Encoded: base64)
    }
}
