import AppKit
import Combine
import Foundation
import IOKit
import Security

public struct LicenseRecord: Codable, Equatable, Sendable {
    public var lastObservedAt: Date
    public var trialIsValid: Bool? = nil
    public var trialLastCheckedAt: Date? = nil
    /// Deadline for the initial offline grace period.
    public var trialGraceDeadline: Date? = nil
    /// Cached trial countdown for display.
    public var trialDaysRemaining: Int? = nil
    /// Cached signed trial proof.
    public var trialToken: String? = nil
    public var licenseKey: String? = nil
    public var licenseIsValid: Bool? = nil
    public var invalidReason: LicenseInvalidReason? = nil
    public var lastValidatedAt: Date? = nil
    /// Cached signed paid-license proof.
    public var licenseToken: String? = nil
    /// Optional local denial history.
    fileprivate var deniedLicenseKeys: [String]? = nil

    public init(
        lastObservedAt: Date,
        trialIsValid: Bool? = nil,
        trialLastCheckedAt: Date? = nil,
        trialGraceDeadline: Date? = nil,
        trialDaysRemaining: Int? = nil,
        trialToken: String? = nil,
        licenseKey: String? = nil,
        licenseIsValid: Bool? = nil,
        invalidReason: LicenseInvalidReason? = nil,
        lastValidatedAt: Date? = nil,
        licenseToken: String? = nil
    ) {
        self.lastObservedAt = lastObservedAt
        self.trialIsValid = trialIsValid
        self.trialLastCheckedAt = trialLastCheckedAt
        self.trialGraceDeadline = trialGraceDeadline
        self.trialDaysRemaining = trialDaysRemaining
        self.trialToken = trialToken
        self.licenseKey = licenseKey
        self.licenseIsValid = licenseIsValid
        self.invalidReason = invalidReason
        self.lastValidatedAt = lastValidatedAt
        self.licenseToken = licenseToken
    }
}

@MainActor
public protocol LicenseSecureStoring {
    func load() throws -> LicenseRecord?
    func save(_ record: LicenseRecord) throws
}

public protocol DeviceIdentifierProviding {
    var deviceID: String { get }
}

public struct HardwareDeviceIdentifierProvider: DeviceIdentifierProviding {
    private static let fallbackIdentifierKey = "device.fallbackIdentifier"

    private let defaults: UserDefaults

    /// - Parameter userDefaultsSuiteName: A UserDefaults suite unique to the app.
    public init(userDefaultsSuiteName: String) {
        self.defaults = UserDefaults(suiteName: userDefaultsSuiteName) ?? .standard
    }

    public var deviceID: String {
        if let uuid = ioRegistryStringProperty(key: "IOPlatformUUID") {
            return uuid
        }
        if let serialNumber = ioRegistryStringProperty(key: "IOPlatformSerialNumber") {
            return serialNumber
        }
        if let persisted = defaults.string(forKey: Self.fallbackIdentifierKey) {
            return persisted
        }
        let generated = UUID().uuidString
        defaults.set(generated, forKey: Self.fallbackIdentifierKey)
        return generated
    }

    private func ioRegistryStringProperty(key: String) -> String? {
        let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        guard service != 0 else {
            return nil
        }
        defer { IOObjectRelease(service) }
        return IORegistryEntryCreateCFProperty(service, key as CFString, kCFAllocatorDefault, 0)?
            .takeRetainedValue() as? String
    }
}

@MainActor
public final class KeychainLicenseStore: LicenseSecureStoring {
    private let service: String
    private let account: String

    /// - Parameters:
    ///   - service: A Keychain service string unique to the consuming app
    ///     (e.g. `"com.example.myapp.license"`), so multiple apps using this
    ///     package don't share a Keychain item.
    ///   - account: Defaults to `"direct-license"`; override only if an app
    ///     needs multiple independent license records.
    public init(service: String, account: String = "direct-license") {
        self.service = service
        self.account = account
    }

    public func load() throws -> LicenseRecord? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw KeychainError(status: status)
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(LicenseRecord.self, from: data)
    }

    public func save(_ record: LicenseRecord) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(record)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let status = SecItemUpdate(baseQuery as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var item = baseQuery
            attributes.forEach { item[$0.key] = $0.value }
            let addStatus = SecItemAdd(item as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw KeychainError(status: addStatus) }
        } else if status != errSecSuccess {
            throw KeychainError(status: status)
        }
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    public struct KeychainError: Error {
        public let status: OSStatus
    }
}

public enum LicenseAccessState: Equatable, Sendable {
    case bypassed
    case trial
    /// Access during the initial offline grace period.
    case trialGracePeriod(deadline: Date)
    /// The initial offline grace period has expired.
    case trialGracePeriodExpired
    /// No verified trial proof is currently available.
    case trialUnverified
    case trialExpired
    case licensed
    case invalid(LicenseInvalidReason)

    public var grantsAccess: Bool {
        switch self {
        case .bypassed, .trial, .licensed, .trialGracePeriod: true
        case .trialGracePeriodExpired, .trialUnverified, .trialExpired, .invalid: false
        }
    }

    /// Whether access is denied for a confirmed reason; use for license prompts.
    public var isDefinitivelyDenied: Bool {
        switch self {
        case .trialExpired, .invalid, .trialGracePeriodExpired: true
        case .bypassed, .trial, .trialGracePeriod, .trialUnverified, .licensed: false
        }
    }
}

/// Licensing errors exposed to the host app.
public enum LicenseManagerError: Error, Equatable, Sendable {
    case licenseKeyRequired
    /// The affected app name is included for localized error messages.
    case storage(statusCode: Int, appName: String)
    case server(LicenseAPIError)
    case serverUnavailable
    case validationUnavailable
    case importDeviceMismatch
    case importExpired
    case importInvalid
}

@MainActor
public final class LicenseManager: ObservableObject {
    public static let validationInterval: TimeInterval = 24 * 60 * 60
    public static let trialSyncInterval = validationInterval
    /// Duration of the initial offline grace period.
    public static let trialGracePeriod: TimeInterval = 24 * 60 * 60

    @Published public private(set) var state: LicenseAccessState
    @Published public private(set) var isWorking = false
    @Published public private(set) var lastError: LicenseManagerError?

    private let isEnabled: Bool
    private let productID: String
    private let secureStore: any LicenseSecureStoring
    private let client: any LicenseAPIClientProtocol
    private let now: () -> Date
    private let offlineTokenPublicKeyRaw: Data
    /// Device identifier resolved for this manager.
    private let deviceID: String
    public let deviceName: String
    /// Display name used in localized error messages.
    private let appName: String
    private let reachabilityMonitor: any NetworkReachabilityMonitoring
    private var record: LicenseRecord?
    private var accessRefreshTimer: Timer?
    private var accessDeadline: Date?
    private var lifecycleSubscriptions = Set<AnyCancellable>()
    private var isStarted = false
    private var isSyncingTrial = false

    /// - Parameters:
    ///   - isEnabled: Whether this distribution uses direct licensing.
    ///     When `false`, the manager always
    ///     reports `.bypassed` / `hasAccess == true` and never talks to the
    ///     network or Keychain.
    ///   - productID: The `product_id` this app registers trials under on
    ///     the shared license server.
    ///   - appName: This app's display name, e.g. `"My App"`. Interpolated
    ///     into user-facing error text such as the Keychain storage failure.
    ///   - deviceNameFallback: Shown/sent when `Host.current().localizedName`
    ///     is unavailable. Pass an already-localized string.
    ///   - secureStore: Typically a `KeychainLicenseStore` configured with
    ///     this app's own Keychain service string.
    ///   - deviceIdentifierProvider: Typically a
    ///     `HardwareDeviceIdentifierProvider` configured with this app's own
    ///     `UserDefaults` suite.
    ///   - offlineTokenPublicKeyRaw: The raw Ed25519 public key matching the
    ///     signing key used by this app's license server.
    ///   - baseURL: The license server's base URL. Defaults to the shared
    ///     `api.ombrelle.app` server; override for a different backend.
    ///     Ignored if `client` is provided.
    ///   - client: Full override of the networking layer, e.g. a mock in
    ///     tests. Defaults to a `LicenseAPIClient` built from `baseURL`.
    ///   - reachabilityMonitor: Notifies `start()` when connectivity comes
    ///     back, so a trial sync that failed at launch (no internet) is
    ///     retried immediately instead of waiting for the next scheduled
    ///     attempt. Defaults to a real `NWPathReachabilityMonitor`; override
    ///     with a mock in tests.
    public init(
        isEnabled: Bool,
        productID: String,
        appName: String,
        deviceNameFallback: String,
        secureStore: any LicenseSecureStoring,
        deviceIdentifierProvider: any DeviceIdentifierProviding,
        offlineTokenPublicKeyRaw: Data,
        baseURL: URL = LicenseAPIClient.defaultBaseURL,
        client: (any LicenseAPIClientProtocol)? = nil,
        reachabilityMonitor: any NetworkReachabilityMonitoring = NWPathReachabilityMonitor(),
        now: @escaping () -> Date = Date.init
    ) {
        self.isEnabled = isEnabled
        self.productID = productID
        self.appName = appName
        self.secureStore = secureStore
        self.client = client ?? LicenseAPIClient(baseURL: baseURL)
        self.reachabilityMonitor = reachabilityMonitor
        self.now = now
        self.offlineTokenPublicKeyRaw = offlineTokenPublicKeyRaw
        self.deviceID = deviceIdentifierProvider.deviceID
        self.deviceName = Host.current().localizedName ?? deviceNameFallback

        guard isEnabled else {
            state = .bypassed
            return
        }

        let currentDate = now()
        do {
            record = try secureStore.load() ?? LicenseRecord(lastObservedAt: currentDate)
        } catch {
            state = .trialUnverified
            lastError = Self.storageError(for: error, appName: appName)
            scheduleAccessRefresh()
            return
        }

        let isCreatingGrace = record?.trialGraceDeadline == nil && record?.trialLastCheckedAt == nil
        if isCreatingGrace {
            record?.trialGraceDeadline = currentDate.addingTimeInterval(Self.trialGracePeriod)
        }

        state = Self.state(
            for: record!,
            deviceID: deviceID,
            productID: productID,
            now: max(currentDate, record!.lastObservedAt),
            offlineTokenPublicKeyRaw: offlineTokenPublicKeyRaw
        )
        if !persistRecord(), isCreatingGrace, record?.licenseKey == nil {
            record?.trialGraceDeadline = currentDate
        }
        refreshState()
    }

    public var hasAccess: Bool {
        state.grantsAccess && (accessDeadline.map { effectiveNow() < $0 } ?? true)
    }

    public var licenseKey: String? { record?.licenseKey }

    public var trialDaysRemaining: Int? { record?.trialDaysRemaining }

    public func start() {
        guard isEnabled, !isStarted else { return }
        isStarted = true
        let onResume: @Sendable (Notification) -> Void = { [weak self] _ in
            Task { @MainActor in
                self?.refreshState()
                await self?.synchronizeAccessState()
            }
        }
        NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)
            .sink(receiveValue: onResume)
            .store(in: &lifecycleSubscriptions)
        NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.didWakeNotification)
            .sink(receiveValue: onResume)
            .store(in: &lifecycleSubscriptions)
        reachabilityMonitor.startMonitoring { [weak self] in
            Task { @MainActor in
                self?.refreshState()
                await self?.synchronizeAccessState()
            }
        }
        refreshState()
        Task { await synchronizeAccessState() }
    }

    public func activate(licenseKey: String) async {
        let key = licenseKey.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !key.isEmpty else {
            lastError = .licenseKeyRequired
            return
        }

        guard !isWorking, recoverStorageIfNeeded() else { return }
        isWorking = true
        lastError = nil
        defer { isWorking = false }
        do {
            let licenseToken = try await client.activate(
                licenseKey: key,
                deviceID: deviceID,
                deviceName: deviceName,
                deviceProfile: .current
            )
            if let licenseToken,
               Self.verifiedEntitlement(licenseToken, deviceID: deviceID, productID: productID,
                   licenseKey: key, now: effectiveNow(), publicKeyRaw: offlineTokenPublicKeyRaw) == nil {
                throw LicenseAPIError(code: "INVALID_TOKEN", message: "The license proof could not be verified.", field: nil)
            }
            if self.record?.licenseKey != key {
                self.record?.licenseToken = nil
            }
            let validationDate = effectiveNow()
            self.record?.licenseKey = key
            self.record?.deniedLicenseKeys?.removeAll { $0 == key }
            self.record?.licenseIsValid = true
            self.record?.invalidReason = nil
            self.record?.lastValidatedAt = validationDate
            if let licenseToken {
                self.record?.licenseToken = licenseToken
            }
            persistRecord()
            refreshState()
        } catch {
            lastError = Self.error(for: error)
        }
    }

    /// Imports a signed paid-license token for this app and device.
    /// Verification is offline against the app's configured public key.
    public func importLicenseToken(_ token: String) {
        guard isEnabled, recoverStorageIfNeeded() else { return }
        let token = token.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            let payload = try OfflineLicenseToken.verify(
                token,
                deviceID: deviceID,
                now: effectiveNow(),
                publicKeyRaw: offlineTokenPublicKeyRaw
            )
            guard payload.productID == productID,
                  let key = payload.licenseKey, !key.isEmpty else {
                throw OfflineLicenseTokenError.malformed
            }
            guard record?.deniedLicenseKeys?.contains(key) != true,
                  !(record?.licenseKey == key && record?.licenseIsValid == false) else {
                throw OfflineLicenseTokenError.malformed
            }
            lastError = nil
            self.record?.licenseKey = key
            self.record?.licenseIsValid = nil
            self.record?.invalidReason = nil
            self.record?.lastValidatedAt = nil
            self.record?.licenseToken = token
            persistRecord()
            refreshState()
        } catch let error as OfflineLicenseTokenError {
            lastError = Self.error(forImportError: error)
        } catch {
            lastError = .importInvalid
        }
    }

    public func validate(force: Bool = false) async {
        guard isEnabled, !isWorking, recoverStorageIfNeeded() else { return }
        guard let record, let key = record.licenseKey else { return }
        guard force || validationIsDue else { return }

        isWorking = true
        lastError = nil
        defer { isWorking = false }
        do {
            let result = try await client.validate(licenseKey: key, deviceID: deviceID)
            guard self.record?.licenseKey == key else {
                if case .failure = result {
                    rememberDenial(for: key)
                    persistRecord()
                }
                return
            }
            let validationDate = effectiveNow()
            switch result {
            case .success(let licenseToken):
                if let licenseToken,
                   Self.verifiedEntitlement(licenseToken, deviceID: deviceID, productID: productID,
                       licenseKey: key, now: validationDate, publicKeyRaw: offlineTokenPublicKeyRaw) == nil {
                    throw OfflineLicenseTokenError.malformed
                }
                self.record?.deniedLicenseKeys?.removeAll { $0 == key }
                self.record?.licenseIsValid = true
                self.record?.invalidReason = nil
                if let licenseToken {
                    self.record?.licenseToken = licenseToken
                }
            case .failure(let reason):
                self.record?.licenseIsValid = false
                self.record?.invalidReason = reason
            }
            self.record?.lastValidatedAt = validationDate
            persistRecord()
            refreshState()
        } catch {
            lastError = .validationUnavailable
            refreshState()
        }
    }

    public func deactivate() async {
        guard isEnabled, !isWorking, recoverStorageIfNeeded() else { return }
        guard let record, let key = record.licenseKey else { return }

        isWorking = true
        lastError = nil
        defer { isWorking = false }
        do {
            try await client.deactivate(licenseKey: key, deviceID: deviceID)
            rememberDenial(for: key)
            guard self.record?.licenseKey == key else {
                persistRecord()
                return
            }
            self.record?.licenseKey = nil
            self.record?.licenseIsValid = nil
            self.record?.invalidReason = nil
            self.record?.lastValidatedAt = nil
            self.record?.licenseToken = nil
            persistRecord()
            await synchronizeTrialState()
        } catch {
            lastError = Self.error(for: error)
        }
    }

    public func refreshState() {
        guard isEnabled else { return }
        guard let record else {
            scheduleAccessRefresh()
            return
        }
        let currentDate = effectiveNow()
        state = Self.state(
            for: record,
            deviceID: deviceID,
            productID: productID,
            now: currentDate,
            offlineTokenPublicKeyRaw: offlineTokenPublicKeyRaw
        )
        accessDeadline = nil
        switch state {
        case .trialGracePeriod(let deadline):
            accessDeadline = deadline
        case .trial, .licensed:
            let token = record.licenseKey == nil ? record.trialToken : record.licenseToken
            if let token {
                accessDeadline = Self.verifiedEntitlement(token, deviceID: deviceID, productID: productID,
                    licenseKey: record.licenseKey, now: currentDate, publicKeyRaw: offlineTokenPublicKeyRaw)?.validUntil
            }
        default:
            break
        }
        if record.lastObservedAt < currentDate {
            persistRecord()
        }
        scheduleAccessRefresh()
    }

    private func recoverStorageIfNeeded() -> Bool {
        guard isEnabled else { return false }
        guard record == nil else { return true }
        do {
            let currentDate = now()
            record = try secureStore.load() ?? LicenseRecord(
                lastObservedAt: currentDate, trialGraceDeadline: currentDate
            )
            if case .storage = lastError { lastError = nil }
            refreshState()
            return true
        } catch {
            lastError = Self.storageError(for: error, appName: appName)
            return false
        }
    }

    private var validationIsDue: Bool {
        guard record?.licenseToken != nil else { return true }
        guard let lastValidatedAt = record?.lastValidatedAt else { return true }
        let currentDate = now()
        guard lastValidatedAt <= currentDate else { return true }
        return currentDate.timeIntervalSince(lastValidatedAt) >= Self.validationInterval
    }

    private func effectiveNow() -> Date {
        let currentDate = now()
        guard let lastObservedAt = record?.lastObservedAt else { return currentDate }
        return max(currentDate, lastObservedAt)
    }

    private static func state(
        for record: LicenseRecord,
        deviceID: String,
        productID: String,
        now: Date,
        offlineTokenPublicKeyRaw: Data
    ) -> LicenseAccessState {
        if let key = record.licenseKey {
            if record.deniedLicenseKeys?.contains(key) == true {
                return .invalid(record.invalidReason ?? .unknown)
            }
            switch record.licenseIsValid {
            case true:
                guard let licenseToken = record.licenseToken else {
                    return .invalid(.unknown)
                }
                return verifiedEntitlement(
                    licenseToken,
                    deviceID: deviceID,
                    productID: productID,
                    licenseKey: record.licenseKey,
                    now: now,
                    publicKeyRaw: offlineTokenPublicKeyRaw
                ) != nil ? .licensed : .invalid(.unknown)
            case false:
                return .invalid(record.invalidReason ?? .unknown)
            case nil:
                if let licenseToken = record.licenseToken,
                   verifiedEntitlement(
                       licenseToken,
                       deviceID: deviceID,
                       productID: productID,
                       licenseKey: record.licenseKey,
                       now: now,
                       publicKeyRaw: offlineTokenPublicKeyRaw
                   ) != nil {
                    return .licensed
                }
                return .invalid(.unknown)
            }
        }
        if record.trialIsValid == false {
            return .trialExpired
        }
        if let trialToken = record.trialToken,
           let payload = verifiedEntitlement(
               trialToken,
               deviceID: deviceID,
               productID: productID,
               licenseKey: nil,
               now: .distantPast,
               publicKeyRaw: offlineTokenPublicKeyRaw
           ), let deadline = payload.validUntil {
            return now < deadline ? .trial : .trialExpired
        }
        if record.trialLastCheckedAt == nil {
            if let deadline = record.trialGraceDeadline, now < deadline {
                return .trialGracePeriod(deadline: deadline)
            }
            return .trialGracePeriodExpired
        }
        return .trialUnverified
    }

    private static func verifiedEntitlement(
        _ token: String,
        deviceID: String,
        productID: String,
        licenseKey: String?,
        now: Date,
        publicKeyRaw: Data
    ) -> OfflineLicensePayload? {
        guard let payload = try? OfflineLicenseToken.verify(
            token, deviceID: deviceID, now: now, publicKeyRaw: publicKeyRaw
        ), payload.productID == productID, payload.licenseKey == licenseKey else { return nil }
        if licenseKey == nil, payload.validUntil == nil { return nil }
        return payload
    }

    private func synchronizeAccessState() async {
        guard recoverStorageIfNeeded(), let record else { return }
        if record.licenseKey != nil {
            if validationIsDue {
                await validate(force: true)
            }
            return
        }
        await synchronizeTrialState()
    }

    private func synchronizeTrialState() async {
        guard isEnabled, let record, record.licenseKey == nil else { return }
        guard !isSyncingTrial else { return }
        isSyncingTrial = true
        defer { isSyncingTrial = false }
        do {
            if record.trialLastCheckedAt == nil {
                try await client.startTrial(
                    deviceID: deviceID,
                    product: productID,
                    deviceName: deviceName,
                    deviceProfile: .current
                )
            }
            let result = try await client.trialStatus(deviceID: deviceID, product: productID)
            let checkDate = effectiveNow()
            self.record?.trialLastCheckedAt = checkDate
            switch result {
            case .success(let status):
                self.record?.trialIsValid = true
                self.record?.trialDaysRemaining = status.daysRemaining
                self.record?.trialToken = status.trialToken
            case .failure:
                self.record?.trialIsValid = false
                self.record?.trialDaysRemaining = nil
                self.record?.trialToken = nil
            }
            persistRecord()
            refreshState()
        } catch {
            refreshState()
            lastError = lastError ?? .serverUnavailable
        }
    }

    isolated deinit {
        accessRefreshTimer?.invalidate()
    }

    private func scheduleAccessRefresh() {
        accessRefreshTimer?.invalidate()
        accessRefreshTimer = nil
        guard isEnabled else { return }
        var interval = Self.validationInterval
        if let deadline = accessDeadline {
            interval = min(interval, max(0.001, deadline.timeIntervalSince(effectiveNow())))
        }
        if record?.licenseKey != nil, let lastValidatedAt = record?.lastValidatedAt {
            let remaining = lastValidatedAt.addingTimeInterval(Self.validationInterval).timeIntervalSince(effectiveNow())
            if remaining > 0 { interval = min(interval, remaining) }
        }
        let timer = Timer(timeInterval: interval, repeats: false) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                self.refreshState()
                if self.isStarted { await self.synchronizeAccessState() }
            }
        }
        accessRefreshTimer = timer
        RunLoop.main.add(timer, forMode: .common)
    }

    private func rememberDenial(for key: String) {
        guard record?.deniedLicenseKeys?.contains(key) != true else { return }
        if record?.deniedLicenseKeys == nil { record?.deniedLicenseKeys = [] }
        record?.deniedLicenseKeys?.append(key)
    }

    @discardableResult
    private func persistRecord() -> Bool {
        if record?.licenseIsValid == false, let key = record?.licenseKey {
            rememberDenial(for: key)
        }
        guard var record else { return false }
        record.lastObservedAt = max(now(), record.lastObservedAt)
        self.record = record
        do {
            try secureStore.save(record)
            return true
        } catch {
            lastError = Self.storageError(for: error, appName: appName)
            return false
        }
    }

    private static func storageError(for error: Error, appName: String) -> LicenseManagerError {
        let code = (error as? KeychainLicenseStore.KeychainError).map { Int($0.status) }
            ?? (error as NSError).code
        return .storage(statusCode: code, appName: appName)
    }

    private static func error(for error: Error) -> LicenseManagerError {
        if let apiError = error as? LicenseAPIError {
            return .server(apiError)
        }
        return .serverUnavailable
    }

    private static func error(forImportError error: OfflineLicenseTokenError) -> LicenseManagerError {
        switch error {
        case .deviceMismatch:
            .importDeviceMismatch
        case .expired:
            .importExpired
        case .malformed, .invalidSignature:
            .importInvalid
        }
    }
}
