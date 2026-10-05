import AppKit
import CryptoKit
import Foundation
import Testing
@testable import Lab421Licensing

@Suite(.serialized)
@MainActor
struct LicenseManagerTests {
    @Test func activateCachesLicenseTokenAndGrantsAccessAfterANetworkOutage() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let store = MemoryLicenseStore()
        let client = MockLicenseClient()
        let privateKey = Curve25519.Signing.PrivateKey()
        await client.setActivationLicenseToken(
            signedToken(privateKey: privateKey, licenseKey: "TEST-KEY", deviceID: "hardware-fingerprint")
        )
        let manager = makeManager(store: store, client: client, clock: clock, publicKey: privateKey.publicKey)

        await manager.activate(licenseKey: "TEST-KEY")
        #expect(manager.state == .licensed)
        #expect(store.record?.licenseToken != nil)

        let record = store.record!
        let offlineOnlyStore = MemoryLicenseStore(record: LicenseRecord(
            lastObservedAt: record.lastObservedAt,
            trialIsValid: nil,
            trialLastCheckedAt: nil,
            trialDaysRemaining: nil,
            licenseKey: record.licenseKey,
            licenseIsValid: nil,
            invalidReason: nil,
            lastValidatedAt: nil,
            licenseToken: record.licenseToken
        ))
        let offlineClient = MockLicenseClient()
        await offlineClient.setNetworkFailure(true)
        let offlineManager = makeManager(store: offlineOnlyStore, client: offlineClient, clock: clock, publicKey: privateKey.publicKey)

        #expect(offlineManager.state == .licensed)
        #expect(offlineManager.hasAccess)
    }

    @Test func keychainSaveFailureSurfacesAnActionableErrorWithTheErrorCode() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let store = MemoryLicenseStore()
        store.saveError = KeychainLicenseStore.KeychainError(status: -25300)
        let manager = makeManager(store: store, clock: clock)

        await manager.activate(licenseKey: "TEST-KEY")

        #expect(manager.lastError == .storage(statusCode: -25300, appName: "Test App"))
    }

    @Test func aRecordCopiedFromAnotherMacIsNotTrustedEvenWithLicenseIsValidTrue() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let privateKey = Curve25519.Signing.PrivateKey()
        let copiedRecord = LicenseRecord(
            lastObservedAt: clock.date,
            trialIsValid: nil,
            trialLastCheckedAt: nil,
            trialDaysRemaining: nil,
            licenseKey: "TEST-KEY",
            licenseIsValid: true,
            invalidReason: nil,
            lastValidatedAt: clock.date,
            licenseToken: signedToken(
                privateKey: privateKey,
                licenseKey: "TEST-KEY",
                deviceID: "original-mac-device-id"
            )
        )
        let store = MemoryLicenseStore(record: copiedRecord)
        let manager = makeManager(store: store, clock: clock, publicKey: privateKey.publicKey)

        #expect(manager.state == .invalid(.unknown))
        #expect(!manager.hasAccess)
    }

    @Test func cachedLicenseBooleanWithoutASignedTokenDoesNotGrantAccess() {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let record = LicenseRecord(
            lastObservedAt: clock.date,
            licenseKey: "FORGED-KEY",
            licenseIsValid: true,
            lastValidatedAt: Date.distantFuture
        )
        let manager = makeManager(
            store: MemoryLicenseStore(record: record),
            clock: clock
        )

        #expect(manager.state == .invalid(.unknown))
        #expect(!manager.hasAccess)
    }

    @Test func unconfirmedLicenseWithAnInvalidTokenIsExplicitlyDenied() {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let record = LicenseRecord(
            lastObservedAt: clock.date,
            licenseKey: "TEST-KEY",
            licenseIsValid: nil,
            licenseToken: "not-a-signed-token"
        )
        let manager = makeManager(
            store: MemoryLicenseStore(record: record),
            clock: clock
        )

        #expect(manager.state == .invalid(.unknown))
        #expect(!manager.hasAccess)
    }

    @Test func futureValidationDateWithoutATokenCannotSuppressServerValidation() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let store = MemoryLicenseStore(record: LicenseRecord(
            lastObservedAt: Date.distantFuture,
            licenseKey: "FORGED-KEY",
            licenseIsValid: true,
            lastValidatedAt: Date.distantFuture
        ))
        let client = MockLicenseClient()
        let manager = makeManager(store: store, client: client, clock: clock)

        manager.start()
        await waitUntil({
            await client.validationCount == 1
        }, timeout: 1.0)

        #expect(manager.state == .invalid(.unknown))
    }

    @Test func importLicenseTokenGrantsAccessWithoutEverReachingTheNetwork() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let store = MemoryLicenseStore()
        let client = MockLicenseClient()
        await client.setNetworkFailure(true)
        let privateKey = Curve25519.Signing.PrivateKey()
        let manager = makeManager(store: store, client: client, clock: clock, publicKey: privateKey.publicKey)

        let token = signedToken(privateKey: privateKey, licenseKey: "HAND-SIGNED", deviceID: "hardware-fingerprint")
        manager.importLicenseToken(token)

        #expect(manager.state == .licensed)
        #expect(manager.hasAccess)
        #expect(store.record?.licenseKey == "HAND-SIGNED")
        #expect(manager.lastError == nil)
    }

    @Test func importLicenseTokenRejectsATokenIssuedForAnotherDevice() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let store = MemoryLicenseStore()
        let client = MockLicenseClient()
        let privateKey = Curve25519.Signing.PrivateKey()
        let manager = makeManager(store: store, client: client, clock: clock, publicKey: privateKey.publicKey)

        let token = signedToken(privateKey: privateKey, licenseKey: "OTHER", deviceID: "some-other-mac")
        manager.importLicenseToken(token)

        guard case .trialGracePeriod = manager.state else {
            Issue.record("Expected .trialGracePeriod, got \(manager.state)")
            return
        }
        #expect(store.record?.licenseKey == nil)
        #expect(manager.lastError == .importDeviceMismatch)
    }

    @Test func reconnectingRetriesImmediatelyInsteadOfWaitingForTheDailyTimer() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let store = MemoryLicenseStore()
        let client = MockLicenseClient()
        let privateKey = Curve25519.Signing.PrivateKey()
        await client.setNetworkFailure(true)
        let reachability = MockReachabilityMonitor()
        let manager = makeManager(
            store: store,
            client: client,
            clock: clock,
            publicKey: privateKey.publicKey,
            reachabilityMonitor: reachability
        )

        manager.start()
        await waitUntil({ manager.lastError != nil }, timeout: 1.0)
        #expect(await client.trialStatusCount == 0)
        #expect(manager.hasAccess) // offline, but still within the grace period

        await client.setNetworkFailure(false)
        await client.setTrialStatus(.success(TrialStatus(
            daysRemaining: 5,
            expiresAt: clock.date.addingTimeInterval(5 * 86400),
            trialToken: signedToken(privateKey: privateKey, deviceID: "hardware-fingerprint", validUntil: clock.date.addingTimeInterval(5 * 86400))
        )))
        reachability.simulateReachable()

        await waitUntil({
            await client.trialStatusCount == 1 && manager.state == .trial
        }, timeout: 1.0)

        #expect(manager.hasAccess)
    }

    @Test func trialStartAndStatusDriveAccess() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let store = MemoryLicenseStore()
        let client = MockLicenseClient()
        let privateKey = Curve25519.Signing.PrivateKey()
        await client.setTrialStatus(.success(TrialStatus(
            daysRemaining: 5,
            expiresAt: clock.date.addingTimeInterval(5 * 86400),
            trialToken: signedToken(privateKey: privateKey, deviceID: "hardware-fingerprint", validUntil: clock.date.addingTimeInterval(5 * 86400))
        )))
        let manager = makeManager(store: store, client: client, clock: clock, publicKey: privateKey.publicKey)

        manager.start()
        await waitUntil({
            await client.trialStatusCount == 1 && manager.state == .trial
        }, timeout: 1.0)

        #expect(manager.hasAccess)
        #expect(await client.trialStartCount == 1)
        #expect(store.record?.trialIsValid == true)
        #expect(store.record?.trialToken != nil)
        #expect(manager.trialDaysRemaining == 5)
    }

    @Test func trialStatusValidWithoutASignedTokenDoesNotGrantAccess() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let store = MemoryLicenseStore()
        let client = MockLicenseClient()
        await client.setTrialStatus(.success(TrialStatus(
            daysRemaining: 5,
            expiresAt: clock.date.addingTimeInterval(5 * 86400),
            trialToken: nil
        )))
        let manager = makeManager(store: store, client: client, clock: clock)

        manager.start()
        await waitUntil({
            await client.trialStatusCount == 1
        }, timeout: 1.0)

        #expect(manager.state == .trialUnverified)
        #expect(!manager.hasAccess)
    }

    @Test func trialTokenSignedByAnotherKeyDoesNotGrantAccess() {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let privateKey = Curve25519.Signing.PrivateKey()
        let otherKey = Curve25519.Signing.PrivateKey()
        let record = LicenseRecord(
            lastObservedAt: clock.date,
            trialIsValid: true,
            trialLastCheckedAt: clock.date,
            trialDaysRemaining: 5,
            trialToken: signedToken(privateKey: otherKey, deviceID: "hardware-fingerprint")
        )
        let manager = makeManager(
            store: MemoryLicenseStore(record: record),
            clock: clock,
            publicKey: privateKey.publicKey
        )

        #expect(manager.state == .trialUnverified)
        #expect(!manager.hasAccess)
    }

    @Test func trialTokenForADifferentDeviceDoesNotGrantAccess() {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let privateKey = Curve25519.Signing.PrivateKey()
        let record = LicenseRecord(
            lastObservedAt: clock.date,
            trialIsValid: true,
            trialLastCheckedAt: clock.date,
            trialDaysRemaining: 5,
            trialToken: signedToken(privateKey: privateKey, deviceID: "some-other-mac")
        )
        let manager = makeManager(
            store: MemoryLicenseStore(record: record),
            clock: clock,
            publicKey: privateKey.publicKey
        )

        #expect(manager.state == .trialUnverified)
        #expect(!manager.hasAccess)
    }

    @Test func expiredTrialTokenDoesNotGrantAccess() {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let privateKey = Curve25519.Signing.PrivateKey()
        let validUntil = Date(timeIntervalSince1970: 1_700_000_000)
        let record = LicenseRecord(
            lastObservedAt: clock.date,
            trialIsValid: true,
            trialLastCheckedAt: clock.date,
            trialDaysRemaining: 0,
            trialToken: signedToken(
                privateKey: privateKey,
                deviceID: "hardware-fingerprint",
                validUntil: validUntil
            )
        )
        let manager = makeManager(
            store: MemoryLicenseStore(record: record),
            clock: TestClock(validUntil.addingTimeInterval(1)),
            publicKey: privateKey.publicKey
        )

        #expect(manager.state == .trialExpired)
        #expect(!manager.hasAccess)
    }

    @Test func expiredTrialBlocksAccess() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let store = MemoryLicenseStore()
        let client = MockLicenseClient()
        await client.setTrialStatus(.failure(.trialExpired))
        let manager = makeManager(store: store, client: client, clock: clock)

        manager.start()
        await waitUntil({
            await client.trialStatusCount == 1 && manager.state == .trialExpired
        }, timeout: 1.0)

        #expect(!manager.hasAccess)
        #expect(store.record?.trialIsValid == false)
    }

    @Test func newInstallWithNoNetworkGrantsATemporaryGracePeriod() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let store = MemoryLicenseStore()
        let client = MockLicenseClient()
        await client.setNetworkFailure(true)
        let manager = makeManager(store: store, client: client, clock: clock)

        guard case .trialGracePeriod(let deadline) = manager.state else {
            Issue.record("Expected .trialGracePeriod, got \(manager.state)")
            return
        }
        #expect(deadline == clock.date.addingTimeInterval(LicenseManager.trialGracePeriod))
        #expect(manager.hasAccess)
        #expect(!manager.state.isDefinitivelyDenied)
    }

    @Test func graceExpiryWithoutEverReachingTheServerIsDefinitivelyDenied() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let store = MemoryLicenseStore()
        let client = MockLicenseClient()
        await client.setNetworkFailure(true)
        let manager = makeManager(store: store, client: client, clock: clock)

        guard case .trialGracePeriod = manager.state else {
            Issue.record("Expected .trialGracePeriod, got \(manager.state)")
            return
        }

        clock.date.addTimeInterval(LicenseManager.trialGracePeriod + 1)
        manager.refreshState()

        #expect(manager.state == .trialGracePeriodExpired)
        #expect(!manager.hasAccess)
        #expect(manager.state.isDefinitivelyDenied)
    }

    @Test func relaunchingWhileOfflineDoesNotPushTheGraceDeadlineBack() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let store = MemoryLicenseStore()
        let client = MockLicenseClient()
        await client.setNetworkFailure(true)
        let firstManager = makeManager(store: store, client: client, clock: clock)
        guard case .trialGracePeriod(let firstDeadline) = firstManager.state else {
            Issue.record("Expected .trialGracePeriod, got \(firstManager.state)")
            return
        }

        clock.date.addTimeInterval(60 * 60)
        let secondManager = makeManager(store: store, client: client, clock: clock)
        guard case .trialGracePeriod(let secondDeadline) = secondManager.state else {
            Issue.record("Expected .trialGracePeriod, got \(secondManager.state)")
            return
        }
        #expect(secondDeadline == firstDeadline)
    }

    @Test func trialExpiredIsDefinitivelyDeniedButUnverifiedIsNot() {
        #expect(LicenseAccessState.trialExpired.isDefinitivelyDenied)
        #expect(LicenseAccessState.invalid(.licenseDisabled).isDefinitivelyDenied)
        #expect(LicenseAccessState.trialGracePeriodExpired.isDefinitivelyDenied)
        #expect(!LicenseAccessState.trialUnverified.isDefinitivelyDenied)
        #expect(!LicenseAccessState.trial.isDefinitivelyDenied)
        #expect(!LicenseAccessState.trialGracePeriod(deadline: .distantFuture).isDefinitivelyDenied)
        #expect(!LicenseAccessState.licensed.isDefinitivelyDenied)
        #expect(!LicenseAccessState.bypassed.isDefinitivelyDenied)

        #expect(LicenseAccessState.trialGracePeriod(deadline: .distantFuture).grantsAccess)
        #expect(!LicenseAccessState.trialGracePeriodExpired.grantsAccess)
    }

    @Test func cachedTrialBooleanWithoutASignedTokenDoesNotGrantAccess() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let record = LicenseRecord(
            lastObservedAt: clock.date,
            trialIsValid: true,
            trialLastCheckedAt: clock.date,
            trialDaysRemaining: 3
        )
        let store = MemoryLicenseStore(record: record)
        let client = MockLicenseClient()
        await client.setNetworkFailure(true)
        let manager = makeManager(store: store, client: client, clock: clock)

        #expect(manager.state == .trialUnverified)
        #expect(!manager.hasAccess)

        manager.start()
        await waitUntil({
            await client.trialStatusCount == 1
        }, timeout: 1.0)

        #expect(manager.state == .trialUnverified)
        #expect(!manager.hasAccess)
    }

    @Test func networkFailureKeepsPreviouslyValidatedTrialActive() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let privateKey = Curve25519.Signing.PrivateKey()
        let record = LicenseRecord(
            lastObservedAt: clock.date,
            trialIsValid: true,
            trialLastCheckedAt: clock.date,
            trialDaysRemaining: 3,
            trialToken: signedToken(privateKey: privateKey, deviceID: "hardware-fingerprint", validUntil: clock.date.addingTimeInterval(5 * 86400))
        )
        let store = MemoryLicenseStore(record: record)
        let client = MockLicenseClient()
        await client.setNetworkFailure(true)
        let manager = makeManager(store: store, client: client, clock: clock, publicKey: privateKey.publicKey)

        #expect(manager.state == .trial)
        #expect(manager.hasAccess)

        manager.start()
        await waitUntil({
            await client.trialStatusCount == 1
        }, timeout: 1.0)

        #expect(manager.state == .trial)
        #expect(manager.hasAccess)
        #expect(manager.lastError != nil)
    }

    @Test func cachedTrialOnlyGrantsAccessAfterStartupVerificationSucceeds() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let store = MemoryLicenseStore(record: LicenseRecord(
            lastObservedAt: clock.date,
            trialIsValid: true,
            trialLastCheckedAt: clock.date,
            trialDaysRemaining: 3
        ))
        let client = MockLicenseClient()
        let privateKey = Curve25519.Signing.PrivateKey()
        await client.setTrialStatus(.success(TrialStatus(
            daysRemaining: 2,
            expiresAt: clock.date.addingTimeInterval(2 * 86400),
            trialToken: signedToken(privateKey: privateKey, deviceID: "hardware-fingerprint", validUntil: clock.date.addingTimeInterval(5 * 86400))
        )))
        let manager = makeManager(store: store, client: client, clock: clock, publicKey: privateKey.publicKey)

        #expect(manager.state == .trialUnverified)
        #expect(!manager.hasAccess)

        manager.start()
        await waitUntil({
            await client.trialStatusCount == 1 && manager.state == .trial
        }, timeout: 1.0)

        #expect(manager.hasAccess)
        #expect(manager.trialDaysRemaining == 2)
    }

    @Test func activationValidationAndDeactivationDriveAccess() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let store = MemoryLicenseStore()
        let client = MockLicenseClient()
        let privateKey = Curve25519.Signing.PrivateKey()
        await client.setActivationLicenseToken(
            signedToken(
                privateKey: privateKey,
                licenseKey: "TEST-KEY",
                deviceID: "hardware-fingerprint"
            )
        )
        let manager = makeManager(
            store: store,
            client: client,
            clock: clock,
            publicKey: privateKey.publicKey
        )

        await manager.activate(licenseKey: "  TEST-KEY  ")
        #expect(manager.state == .licensed)
        #expect(store.record?.licenseKey == "TEST-KEY")

        clock.date.addTimeInterval(LicenseManager.validationInterval + 1)
        await client.setValidation(.failure(.deviceDeactivated))
        await manager.validate()
        #expect(manager.state == .invalid(.deviceDeactivated))
        #expect(!manager.hasAccess)

        await manager.activate(licenseKey: "TEST-KEY")
        await client.setTrialStatus(.success(TrialStatus(
            daysRemaining: 7,
            expiresAt: clock.date.addingTimeInterval(7 * 86400),
            trialToken: signedToken(privateKey: privateKey, deviceID: "hardware-fingerprint", validUntil: clock.date.addingTimeInterval(5 * 86400))
        )))
        await manager.deactivate()
        #expect(manager.state == .trial)
        #expect(store.record?.licenseKey == nil)
    }

    @Test func deactivateFailureLeavesTheLicenseActive() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let privateKey = Curve25519.Signing.PrivateKey()
        let record = LicenseRecord(
            lastObservedAt: clock.date,
            licenseKey: "TEST-KEY",
            licenseIsValid: true,
            lastValidatedAt: clock.date,
            licenseToken: signedToken(privateKey: privateKey, licenseKey: "TEST-KEY", deviceID: "hardware-fingerprint")
        )
        let store = MemoryLicenseStore(record: record)
        let client = MockLicenseClient()
        await client.setNetworkFailure(true)
        let manager = makeManager(store: store, client: client, clock: clock, publicKey: privateKey.publicKey)

        await manager.deactivate()

        #expect(manager.state == .licensed)
        #expect(manager.hasAccess)
        #expect(store.record?.licenseKey == "TEST-KEY")
        #expect(manager.lastError == .serverUnavailable)
    }

    @Test func activationRejectedByTheServerSurfacesItsMessage() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let store = MemoryLicenseStore()
        let client = MockLicenseClient()
        let apiError = LicenseAPIError(code: "SEAT_LIMIT_REACHED", message: "No seats left", field: nil)
        await client.setActivationError(apiError)
        let manager = makeManager(store: store, client: client, clock: clock)

        await manager.activate(licenseKey: "TEST-KEY")

        #expect(manager.lastError == .server(apiError))
        #expect(manager.state != .licensed)
        #expect(store.record?.licenseKey == nil)
    }

    @Test func importLicenseTokenRejectsAnExpiredToken() {
        let privateKey = Curve25519.Signing.PrivateKey()
        let validUntil = Date(timeIntervalSince1970: 1_700_000_000)
        let store = MemoryLicenseStore()
        let manager = makeManager(
            store: store,
            clock: TestClock(validUntil.addingTimeInterval(1)),
            publicKey: privateKey.publicKey
        )

        let token = signedToken(
            privateKey: privateKey,
            licenseKey: "EXPIRED",
            deviceID: "hardware-fingerprint",
            validUntil: validUntil
        )
        manager.importLicenseToken(token)

        #expect(manager.lastError == .importExpired)
        #expect(store.record?.licenseKey == nil)
    }

    @Test func importLicenseTokenRejectsAMalformedToken() {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let manager = makeManager(store: MemoryLicenseStore(), clock: clock)

        manager.importLicenseToken("not-a-token")

        #expect(manager.lastError == .importInvalid)
    }

    @Test func keychainLoadFailureAtLaunchStartsInASafeDeniedState() {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let store = MemoryLicenseStore()
        store.loadError = KeychainLicenseStore.KeychainError(status: -25293)
        let manager = makeManager(store: store, clock: clock)

        #expect(manager.state == .trialUnverified)
        #expect(!manager.hasAccess)
        #expect(store.saveCount == 0)
        #expect(manager.lastError == .storage(statusCode: -25293, appName: "Test App"))
    }

    @Test func networkFailureKeepsPreviouslyValidatedLicenseActive() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let privateKey = Curve25519.Signing.PrivateKey()
        let record = LicenseRecord(
            lastObservedAt: clock.date,
            trialIsValid: true,
            trialLastCheckedAt: clock.date,
            trialDaysRemaining: nil,
            licenseKey: "TEST-KEY",
            licenseIsValid: true,
            invalidReason: nil,
            lastValidatedAt: clock.date,
            licenseToken: signedToken(
                privateKey: privateKey,
                licenseKey: "TEST-KEY",
                deviceID: "hardware-fingerprint"
            )
        )
        let store = MemoryLicenseStore(record: record)
        let client = MockLicenseClient()
        let manager = makeManager(
            store: store,
            client: client,
            clock: clock,
            publicKey: privateKey.publicKey
        )

        clock.date.addTimeInterval(LicenseManager.validationInterval + 1)
        await client.setNetworkFailure(true)
        await manager.validate()

        #expect(manager.state == .licensed)
        #expect(manager.hasAccess)
        #expect(manager.lastError == .validationUnavailable)
    }

    @Test func trialPeriodicRefreshUsesADailyInterval() {
        #expect(LicenseManager.trialSyncInterval == 24 * 60 * 60)
    }

    @Test func activationPersistsOnlyOnceAfterUpdatingTheClock() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let store = MemoryLicenseStore()
        let client = MockLicenseClient()
        let privateKey = Curve25519.Signing.PrivateKey()
        await client.setActivationLicenseToken(
            signedToken(
                privateKey: privateKey,
                licenseKey: "TEST-KEY",
                deviceID: "hardware-fingerprint"
            )
        )
        let manager = makeManager(
            store: store,
            client: client,
            clock: clock,
            publicKey: privateKey.publicKey
        )
        let savesAfterInitialization = store.saveCount
        clock.date.addTimeInterval(60)

        await manager.activate(licenseKey: "TEST-KEY")

        #expect(store.saveCount == savesAfterInitialization + 1)
    }

    @Test func disabledLicensingBypassesAccessChecks() {
        let manager = LicenseManager(
            isEnabled: false,
            productID: "example-product",
            appName: "Test App",
            deviceNameFallback: "This Mac",
            secureStore: MemoryLicenseStore(),
            deviceIdentifierProvider: StaticDeviceIdentifierProvider(deviceID: "hardware-fingerprint"),
            offlineTokenPublicKeyRaw: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation,
            client: MockLicenseClient()
        )

        #expect(manager.state == .bypassed)
        #expect(manager.hasAccess)
    }

    @Test(arguments: [true, nil] as [Bool?])
    func cachedLicenseForAnotherProductIsDenied(valid: Bool?) {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let key = Curve25519.Signing.PrivateKey()
        let store = MemoryLicenseStore(record: LicenseRecord(
            lastObservedAt: clock.date, licenseKey: "KEY", licenseIsValid: valid,
            licenseToken: signedToken(privateKey: key, licenseKey: "KEY",
                deviceID: "hardware-fingerprint", productID: "another-app")
        ))
        let manager = makeManager(store: store, clock: clock, publicKey: key.publicKey)
        #expect(manager.state == .invalid(.unknown))
        #expect(!manager.hasAccess)
    }

    @Test func importRejectsAnotherProductWithoutReplacingAnExistingLicense() {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let key = Curve25519.Signing.PrivateKey()
        let store = MemoryLicenseStore()
        let manager = makeManager(store: store, clock: clock, publicKey: key.publicKey)
        manager.importLicenseToken(signedToken(privateKey: key, licenseKey: "ORIGINAL", deviceID: "hardware-fingerprint"))
        let original = store.record
        manager.importLicenseToken(signedToken(privateKey: key, licenseKey: "OTHER", deviceID: "hardware-fingerprint", productID: "another-app"))
        #expect(manager.lastError == .importInvalid)
        #expect(store.record == original)
        #expect(manager.hasAccess)
    }

    @Test(arguments: [true, nil] as [Bool?])
    func trialProofCannotGrantPaidAccess(valid: Bool?) {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let key = Curve25519.Signing.PrivateKey()
        let store = MemoryLicenseStore(record: LicenseRecord(
            lastObservedAt: clock.date, licenseKey: "FORGED", licenseIsValid: valid,
            licenseToken: signedToken(privateKey: key, deviceID: "hardware-fingerprint", validUntil: clock.date.addingTimeInterval(3600))
        ))
        #expect(!makeManager(store: store, clock: clock, publicKey: key.publicKey).hasAccess)
    }

    @Test func paidProofMustMatchTheStoredLicenseKey() {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let key = Curve25519.Signing.PrivateKey()
        let store = MemoryLicenseStore(record: LicenseRecord(
            lastObservedAt: clock.date, licenseKey: "OTHER", licenseIsValid: true,
            licenseToken: signedToken(privateKey: key, licenseKey: "KEY", deviceID: "hardware-fingerprint")
        ))
        #expect(!makeManager(store: store, clock: clock, publicKey: key.publicKey).hasAccess)
    }

    @Test(arguments: ["another-app", "example-product"])
    func invalidTrialEntitlementsAreDenied(product: String) {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let key = Curve25519.Signing.PrivateKey()
        let token = signedToken(privateKey: key, deviceID: "hardware-fingerprint", productID: product,
            validUntil: product == "example-product" ? nil : clock.date.addingTimeInterval(3600))
        let store = MemoryLicenseStore(record: LicenseRecord(
            lastObservedAt: clock.date, trialIsValid: true, trialLastCheckedAt: clock.date, trialToken: token
        ))
        let manager = makeManager(store: store, clock: clock, publicKey: key.publicKey)
        #expect(!manager.hasAccess)
        manager.importLicenseToken(token)
        #expect(manager.lastError == .importInvalid)
    }

    @Test func activationRejectsWrongProofAndPreservesThePreviousLicense() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let key = Curve25519.Signing.PrivateKey()
        let store = MemoryLicenseStore()
        let client = MockLicenseClient()
        let manager = makeManager(store: store, client: client, clock: clock, publicKey: key.publicKey)
        manager.importLicenseToken(signedToken(privateKey: key, licenseKey: "ORIGINAL", deviceID: "hardware-fingerprint"))
        let original = store.record
        await client.setActivationLicenseToken(signedToken(privateKey: key, licenseKey: "OTHER", deviceID: "hardware-fingerprint", productID: "another-app"))
        await manager.activate(licenseKey: "OTHER")
        #expect(manager.lastError != nil)
        #expect(store.record == original)
        #expect(manager.hasAccess)
    }

    @Test func legacySuccessWithoutANewTokenKeepsOnlyAMatchingCachedLicense() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let key = Curve25519.Signing.PrivateKey()
        let store = MemoryLicenseStore()
        let client = MockLicenseClient()
        let manager = makeManager(store: store, client: client, clock: clock, publicKey: key.publicKey)
        manager.importLicenseToken(signedToken(privateKey: key, licenseKey: "ORIGINAL", deviceID: "hardware-fingerprint"))
        await manager.activate(licenseKey: "ORIGINAL")
        #expect(manager.hasAccess)
        await manager.validate(force: true)
        #expect(manager.hasAccess)
        await manager.activate(licenseKey: "NEW")
        #expect(!manager.hasAccess)
        #expect(store.record?.licenseToken == nil)
    }

    @Test func invalidValidationProofDoesNotDestroyOfflineAccessOrPostponeValidation() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let key = Curve25519.Signing.PrivateKey()
        let store = MemoryLicenseStore()
        let client = MockLicenseClient()
        let manager = makeManager(store: store, client: client, clock: clock, publicKey: key.publicKey)
        manager.importLicenseToken(signedToken(privateKey: key, licenseKey: "KEY", deviceID: "hardware-fingerprint"))
        let token = store.record?.licenseToken
        await client.setValidation(.success(signedToken(privateKey: key, licenseKey: "OTHER", deviceID: "hardware-fingerprint")))
        await manager.validate(force: true)
        #expect(manager.hasAccess)
        #expect(manager.lastError == .validationUnavailable)
        #expect(store.record?.licenseToken == token)
        #expect(store.record?.lastValidatedAt == nil)
    }

    @Test func importingAKnownRevokedLicenseCannotRestoreAccess() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let key = Curve25519.Signing.PrivateKey()
        let store = MemoryLicenseStore()
        let client = MockLicenseClient()
        let manager = makeManager(store: store, client: client, clock: clock, publicKey: key.publicKey)
        let token = signedToken(privateKey: key, licenseKey: "KEY", deviceID: "hardware-fingerprint")
        manager.importLicenseToken(token)
        await client.setValidation(.failure(.licenseDisabled))
        await manager.validate(force: true)
        manager.importLicenseToken(token)
        #expect(manager.lastError == .importInvalid)
        #expect(manager.state == .invalid(.licenseDisabled))
        #expect(!manager.hasAccess)
        await client.setActivationLicenseToken(token)
        await manager.activate(licenseKey: "KEY")
        #expect(manager.hasAccess)
    }

    @Test func startupUsesThePersistedClockWhenCheckingTrialExpiry() {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let key = Curve25519.Signing.PrivateKey()
        let expiry = clock.date.addingTimeInterval(3600)
        let store = MemoryLicenseStore(record: LicenseRecord(
            lastObservedAt: expiry.addingTimeInterval(1), trialIsValid: true,
            trialLastCheckedAt: clock.date,
            trialToken: signedToken(privateKey: key, deviceID: "hardware-fingerprint", validUntil: expiry)
        ))
        let manager = makeManager(store: store, clock: clock, publicKey: key.publicKey)
        #expect(manager.state == .trialExpired)
        #expect(!manager.hasAccess)
    }

    @Test func refreshedClockIsPersistedAcrossOfflineRelaunches() {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let key = Curve25519.Signing.PrivateKey()
        let expiry = clock.date.addingTimeInterval(3600)
        let store = MemoryLicenseStore(record: LicenseRecord(
            lastObservedAt: clock.date, trialIsValid: true, trialLastCheckedAt: clock.date,
            trialToken: signedToken(privateKey: key, deviceID: "hardware-fingerprint", validUntil: expiry)
        ))
        let manager = makeManager(store: store, clock: clock, publicKey: key.publicKey)
        clock.date = expiry.addingTimeInterval(1)
        manager.refreshState()
        #expect(store.record?.lastObservedAt == clock.date)
        clock.date.addTimeInterval(-3600)
        #expect(!makeManager(store: store, clock: clock, publicKey: key.publicKey).hasAccess)
    }

    @Test(arguments: ["trial", "grace", "license"])
    func readingHasAccessNeverGrantsAnExpiredEntitlement(kind: String) {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let key = Curve25519.Signing.PrivateKey()
        let deadline = clock.date.addingTimeInterval(60)
        var record = LicenseRecord(lastObservedAt: clock.date, trialGraceDeadline: deadline)
        if kind == "trial" {
            record.trialLastCheckedAt = clock.date
            record.trialToken = signedToken(privateKey: key, deviceID: "hardware-fingerprint", validUntil: deadline)
        } else if kind == "license" {
            record.licenseKey = "KEY"
            record.licenseToken = signedToken(privateKey: key, licenseKey: "KEY", deviceID: "hardware-fingerprint", validUntil: deadline)
        }
        let manager = makeManager(store: MemoryLicenseStore(record: record), clock: clock, publicKey: key.publicKey)
        #expect(manager.hasAccess)
        clock.date = deadline
        #expect(!manager.hasAccess)
    }

    @Test func timerPublishesExpiryWithoutNetworkOrManualRefresh() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let key = Curve25519.Signing.PrivateKey()
        let store = MemoryLicenseStore(record: LicenseRecord(lastObservedAt: clock.date,
            trialGraceDeadline: clock.date.addingTimeInterval(0.05)))
        let manager = makeManager(store: store, clock: clock, publicKey: key.publicKey)
        #expect(manager.hasAccess)
        clock.date.addTimeInterval(1)
        await waitUntil({ manager.state == .trialGracePeriodExpired }, timeout: 1)
        #expect(!manager.hasAccess)
    }

    @Test func appResumePublishesSignedTrialExpiryEvenWhenTheNetworkFails() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let key = Curve25519.Signing.PrivateKey()
        let client = MockLicenseClient()
        await client.setNetworkFailure(true)
        let store = MemoryLicenseStore(record: LicenseRecord(lastObservedAt: clock.date,
            trialLastCheckedAt: clock.date,
            trialToken: signedToken(privateKey: key, deviceID: "hardware-fingerprint", validUntil: clock.date.addingTimeInterval(60))))
        let manager = makeManager(store: store, client: client, clock: clock, publicKey: key.publicKey)
        manager.start()
        clock.date.addTimeInterval(61)
        NotificationCenter.default.post(name: NSApplication.didBecomeActiveNotification, object: nil)
        await waitUntil({ manager.state == .trialExpired }, timeout: 1)
        #expect(manager.state.isDefinitivelyDenied)
    }

    @Test func unreadableStorageIsNeverOverwrittenAndRecoversAnExistingLicense() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let key = Curve25519.Signing.PrivateKey()
        let original = LicenseRecord(lastObservedAt: clock.date, licenseKey: "KEY", licenseIsValid: true,
            lastValidatedAt: clock.date,
            licenseToken: signedToken(privateKey: key, licenseKey: "KEY", deviceID: "hardware-fingerprint"))
        let store = MemoryLicenseStore(record: original)
        store.loadError = KeychainLicenseStore.KeychainError(status: -25293)
        let client = MockLicenseClient()
        await client.setNetworkFailure(true)
        let manager = makeManager(store: store, client: client, clock: clock, publicKey: key.publicKey)
        manager.importLicenseToken(signedToken(privateKey: key, licenseKey: "OTHER", deviceID: "hardware-fingerprint"))
        #expect(store.saveCount == 0)
        #expect(store.record == original)
        #expect(!manager.hasAccess)
        store.loadError = nil
        manager.start()
        await waitUntil({ manager.hasAccess }, timeout: 1)
        #expect(store.record == original)
        #expect(manager.lastError == nil)
    }

    @Test func recoveringAMissingRecordAfterAReadFailureDoesNotCreateGrace() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let store = MemoryLicenseStore()
        store.loadError = KeychainLicenseStore.KeychainError(status: -25293)
        let client = MockLicenseClient()
        await client.setNetworkFailure(true)
        let manager = makeManager(store: store, client: client, clock: clock)
        store.loadError = nil
        manager.start()
        await waitUntil({ manager.state == .trialGracePeriodExpired }, timeout: 1)
        #expect(!manager.hasAccess)
    }

    @Test func startIsIdempotent() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let client = MockLicenseClient()
        let manager = makeManager(store: MemoryLicenseStore(), client: client, clock: clock)
        manager.start()
        manager.start()
        await waitUntil({ await client.trialStatusCount == 1 }, timeout: 1)
        #expect(await client.trialStartCount == 1)
    }

    @Test func managerIsReleasedWithScheduledTimersAndLifecycleSubscriptions() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        weak var released: LicenseManager?
        do {
            let manager = makeManager(store: MemoryLicenseStore(), clock: clock)
            manager.start()
            await waitUntil({ manager.state == .trialUnverified }, timeout: 1)
            released = manager
        }
        #expect(released == nil)
    }

    @Test func previousStoredRecordsDecodeWithoutMigrationAndKeepOfflinePaidAccess() throws {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let key = Curve25519.Signing.PrivateKey()
        let token = signedToken(privateKey: key, licenseKey: "LEGACY", deviceID: "hardware-fingerprint")
        let json: [String: Any] = [
            "lastObservedAt": "2023-11-14T22:13:20Z",
            "licenseKey": "LEGACY", "licenseIsValid": true, "licenseToken": token,
        ]
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let record = try decoder.decode(LicenseRecord.self, from: JSONSerialization.data(withJSONObject: json))
        let manager = makeManager(store: MemoryLicenseStore(record: record), clock: clock, publicKey: key.publicKey)
        #expect(manager.hasAccess)
        #expect(manager.licenseKey == "LEGACY")
    }

    @Test func knownDenialSurvivesAnotherLicenseImportAndRelaunch() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let key = Curve25519.Signing.PrivateKey()
        let store = MemoryLicenseStore()
        let client = MockLicenseClient()
        let manager = makeManager(store: store, client: client, clock: clock, publicKey: key.publicKey)
        let denied = signedToken(privateKey: key, licenseKey: "DENIED", deviceID: "hardware-fingerprint")
        manager.importLicenseToken(denied)
        await client.setValidation(.failure(.deviceDeactivated))
        await manager.validate(force: true)
        manager.importLicenseToken(signedToken(privateKey: key, licenseKey: "OTHER", deviceID: "hardware-fingerprint"))
        #expect(manager.hasAccess)
        let relaunched = makeManager(store: store, client: client, clock: clock, publicKey: key.publicKey)
        relaunched.importLicenseToken(denied)
        #expect(relaunched.lastError == .importInvalid)
        #expect(relaunched.licenseKey == "OTHER")
    }

    @Test func confirmedDeactivationPreventsReplayingTheSameOfflineToken() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let key = Curve25519.Signing.PrivateKey()
        let store = MemoryLicenseStore()
        let client = MockLicenseClient()
        let manager = makeManager(store: store, client: client, clock: clock, publicKey: key.publicKey)
        let token = signedToken(privateKey: key, licenseKey: "KEY", deviceID: "hardware-fingerprint")
        manager.importLicenseToken(token)
        await client.setTrialStatus(.failure(.trialExpired))
        await manager.deactivate()
        manager.importLicenseToken(token)
        #expect(manager.lastError == .importInvalid)
        #expect(!manager.hasAccess)
        await client.setActivationLicenseToken(token)
        await manager.activate(licenseKey: "KEY")
        #expect(manager.hasAccess)
    }

    @Test func firstInstallDoesNotGrantGraceWhenItsDeadlineCannotBeStored() {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let store = MemoryLicenseStore()
        store.saveError = KeychainLicenseStore.KeychainError(status: -25293)
        let manager = makeManager(store: store, clock: clock)
        #expect(!manager.hasAccess)
        #expect(store.record == nil)
        #expect(manager.lastError == .storage(statusCode: -25293, appName: "Test App"))
    }

    @Test func validCachedPaidLicenseSurvivesAStorageWriteFailure() {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let key = Curve25519.Signing.PrivateKey()
        let store = MemoryLicenseStore(record: LicenseRecord(lastObservedAt: clock.date,
            licenseKey: "KEY", licenseIsValid: true,
            licenseToken: signedToken(privateKey: key, licenseKey: "KEY", deviceID: "hardware-fingerprint")))
        store.saveError = KeychainLicenseStore.KeychainError(status: -25293)
        let manager = makeManager(store: store, clock: clock, publicKey: key.publicKey)
        #expect(manager.hasAccess)
        #expect(manager.lastError == .storage(statusCode: -25293, appName: "Test App"))
    }

    @Test func lateValidationOfAnOldKeyCannotRevokeItsReplacement() async {
        let clock = TestClock(Date(timeIntervalSince1970: 1_700_000_000))
        let key = Curve25519.Signing.PrivateKey()
        let store = MemoryLicenseStore()
        let client = MockLicenseClient()
        let manager = makeManager(store: store, client: client, clock: clock, publicKey: key.publicKey)
        manager.importLicenseToken(signedToken(privateKey: key, licenseKey: "OLD", deviceID: "hardware-fingerprint"))
        await client.setValidation(.failure(.licenseDisabled))
        await client.suspendNextValidation()
        let pending = Task { await manager.validate(force: true) }
        await waitUntil({ await client.validationCount == 1 }, timeout: 1)
        manager.importLicenseToken(signedToken(privateKey: key, licenseKey: "NEW", deviceID: "hardware-fingerprint"))
        await client.resumeValidation()
        await pending.value
        #expect(manager.hasAccess)
        #expect(manager.licenseKey == "NEW")
        #expect(store.record?.licenseIsValid == nil)
        manager.importLicenseToken(signedToken(privateKey: key, licenseKey: "OLD", deviceID: "hardware-fingerprint"))
        #expect(manager.lastError == .importInvalid)
        #expect(manager.licenseKey == "NEW")
    }

    private func makeManager(
        store: MemoryLicenseStore,
        client: MockLicenseClient = MockLicenseClient(),
        clock: TestClock,
        publicKey: Curve25519.Signing.PublicKey = Curve25519.Signing.PrivateKey().publicKey,
        reachabilityMonitor: any NetworkReachabilityMonitoring = MockReachabilityMonitor()
    ) -> LicenseManager {
        LicenseManager(
            isEnabled: true,
            productID: "example-product",
            appName: "Test App",
            deviceNameFallback: "This Mac",
            secureStore: store,
            deviceIdentifierProvider: StaticDeviceIdentifierProvider(deviceID: "hardware-fingerprint"),
            offlineTokenPublicKeyRaw: publicKey.rawRepresentation,
            client: client,
            reachabilityMonitor: reachabilityMonitor,
            now: { clock.date }
        )
    }

    private func waitUntil(_ condition: @escaping @MainActor () async -> Bool, timeout: TimeInterval) async {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if await condition() { return }
            await Task.yield()
        }
        Issue.record("Timed out waiting for condition")
    }
}

@MainActor
private final class TestClock {
    var date: Date
    init(_ date: Date) { self.date = date }
}

@MainActor
private final class MemoryLicenseStore: LicenseSecureStoring {
    var record: LicenseRecord?
    var saveError: KeychainLicenseStore.KeychainError?
    var loadError: KeychainLicenseStore.KeychainError?
    private(set) var saveCount = 0

    init(record: LicenseRecord? = nil) {
        self.record = record
    }

    func load() throws -> LicenseRecord? {
        if let loadError { throw loadError }
        return record
    }

    func save(_ record: LicenseRecord) throws {
        if let saveError { throw saveError }
        saveCount += 1
        self.record = record
    }
}

private actor MockLicenseClient: LicenseAPIClientProtocol {
    enum MockError: Error { case network }

    private var trialStatus: Result<TrialStatus, TrialInvalidReason> = .success(
        TrialStatus(daysRemaining: 7, expiresAt: Date(timeIntervalSince1970: 1_700_604_800), trialToken: nil)
    )
    private var validation: Result<String?, LicenseInvalidReason> = .success(nil)
    private var activationLicenseToken: String?
    private var activationError: LicenseAPIError?
    private var networkFailure = false
    private var shouldSuspendValidation = false
    private var validationContinuation: CheckedContinuation<Void, Never>?
    private(set) var trialStartCount = 0
    private(set) var trialStatusCount = 0
    private(set) var validationCount = 0

    func setTrialStatus(_ status: Result<TrialStatus, TrialInvalidReason>) {
        self.trialStatus = status
    }

    func setValidation(_ validation: Result<String?, LicenseInvalidReason>) {
        self.validation = validation
    }

    func setActivationLicenseToken(_ token: String?) {
        self.activationLicenseToken = token
    }

    func setActivationError(_ error: LicenseAPIError?) {
        self.activationError = error
    }

    func suspendNextValidation() { shouldSuspendValidation = true }

    func resumeValidation() {
        validationContinuation?.resume()
        validationContinuation = nil
    }

    func setNetworkFailure(_ networkFailure: Bool) {
        self.networkFailure = networkFailure
    }

    func startTrial(deviceID: String, product: String, deviceName: String?, deviceProfile: DeviceProfile?) async throws {
        if networkFailure { throw MockError.network }
        trialStartCount += 1
    }

    func trialStatus(deviceID: String, product: String) async throws -> Result<TrialStatus, TrialInvalidReason> {
        trialStatusCount += 1
        if networkFailure { throw MockError.network }
        return trialStatus
    }

    func activate(
        licenseKey: String,
        deviceID: String,
        deviceName: String?,
        deviceProfile: DeviceProfile?
    ) async throws -> String? {
        if let activationError { throw activationError }
        if networkFailure { throw MockError.network }
        return activationLicenseToken
    }

    func validate(licenseKey: String, deviceID: String) async throws -> Result<String?, LicenseInvalidReason> {
        if networkFailure { throw MockError.network }
        validationCount += 1
        let result = validation
        if shouldSuspendValidation {
            shouldSuspendValidation = false
            await withCheckedContinuation { validationContinuation = $0 }
        }
        return result
    }

    func deactivate(licenseKey: String, deviceID: String) async throws {
        if networkFailure { throw MockError.network }
    }
}

private struct StaticDeviceIdentifierProvider: DeviceIdentifierProviding {
    let deviceID: String
}

@MainActor
private final class MockReachabilityMonitor: NetworkReachabilityMonitoring {
    private var onReachable: (() -> Void)?

    func startMonitoring(onReachable: @escaping @Sendable () -> Void) {
        self.onReachable = onReachable
    }

    func simulateReachable() {
        onReachable?()
    }
}
