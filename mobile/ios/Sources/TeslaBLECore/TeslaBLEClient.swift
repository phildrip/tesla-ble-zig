import Foundation

/// A premium, Swift-idiomatic wrapper around the high-performance pure-Zig secure Tesla BLE control core.
///
/// This class handles secure key exchanges, signs/encrypts vehicle control actions
/// (Lock, Unlock, Wake, Trunk releases), and decrypts authenticated responses from the vehicle.
/// Memory is allocated dynamically using the exact sizing returned by the Zig core, ensuring
/// complete heap-safety and zero-copy performance.
public final class TeslaClient {
    
    public let vin: String
    private let clientBuffer: UnsafeMutableRawPointer
    private let clientSize: Int

    /// Initialize a new secure session context for a vehicle.
    ///
    /// - Parameters:
    ///   - vin: The 17-character vehicle Identification Number (VIN).
    ///   - privateKey: The 32-byte SECP256R1 private key.
    ///   - connectionId: The 16-byte secure connection ID.
    public init?(vin: String, privateKey: Data, connectionId: Data) {
        guard vin.count == 17 else {
            print("[TeslaClient] Invalid VIN length. Must be 17 characters.")
            return nil
        }
        guard privateKey.count == 32 else {
            print("[TeslaClient] Invalid private key size. Must be 32 bytes.")
            return nil
        }
        guard connectionId.count == 16 else {
            print("[TeslaClient] Invalid connection ID size. Must be 16 bytes.")
            return nil
        }
        
        self.vin = vin
        
        // Query the core for the exact size of the Client context structure
        self.clientSize = tesla_client_size()
        self.clientBuffer = UnsafeMutableRawPointer.allocate(byteCount: clientSize, alignment: 8)
        
        // Perform placement-init on the pre-allocated buffer
        let vinBytes = Array(vin.utf8)
        let keyBytes = Array(privateKey)
        let connBytes = Array(connectionId)
        
        let status = tesla_client_init(
            clientBuffer,
            vinBytes,
            vinBytes.count,
            keyBytes,
            connBytes
        )
        
        guard status == 0 else {
            print("[TeslaClient] Native initialization failed with status: \(status)")
            clientBuffer.deallocate()
            return nil
        }
        
        print("[TeslaClient] Native secure session context initialized successfully 🛡️")
    }
    
    deinit {
        // Deallocate native buffer to prevent memory leaks
        clientBuffer.deallocate()
    }
    
    /// Builds a signed and encrypted Wake command ready for transmission over BLE.
    ///
    /// - Parameter timestamp: Current epoch timestamp or synchronized counter.
    /// - Returns: Encrypted BLE package payload ready to write to the Tesla TX characteristic, or nil on error.
    public func createWakeCommand(timestamp: UInt32) -> Data? {
        let maxBufferCapacity = 512
        var outputBuffer = Data(count: maxBufferCapacity)
        var writtenSize: Int = 0
        
        let status = outputBuffer.withUnsafeMutableBytes { (outPtr: UnsafeMutableRawBufferPointer) -> Int32 in
            guard let baseAddress = outPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return -1 }
            return tesla_client_build_wake_command(
                clientBuffer,
                timestamp,
                baseAddress,
                maxBufferCapacity,
                &writtenSize
            )
        }
        
        guard status == 0 else {
            print("[TeslaClient] Failed to build native Wake command: \(status)")
            return nil
        }
        
        return outputBuffer.prefix(writtenSize)
    }

    /// Builds a signed and encrypted Lock command ready for transmission over BLE.
    ///
    /// - Parameter timestamp: Current epoch timestamp or synchronized counter.
    /// - Returns: Encrypted BLE package payload, or nil on error.
    public func createLockCommand(timestamp: UInt32) -> Data? {
        let maxBufferCapacity = 512
        var outputBuffer = Data(count: maxBufferCapacity)
        var writtenSize: Int = 0
        
        let status = outputBuffer.withUnsafeMutableBytes { (outPtr: UnsafeMutableRawBufferPointer) -> Int32 in
            guard let baseAddress = outPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return -1 }
            return tesla_client_build_lock_command(
                clientBuffer,
                timestamp,
                baseAddress,
                maxBufferCapacity,
                &writtenSize
            )
        }
        
        guard status == 0 else {
            print("[TeslaClient] Failed to build native Lock command: \(status)")
            return nil
        }
        
        return outputBuffer.prefix(writtenSize)
    }

    /// Decrypts and verifies a signed, authenticated message received from the vehicle.
    ///
    /// - Parameters:
    ///   - domain: Target domain (2 for VCSEC, 3 for CarServer).
    ///   - rxBytes: The raw bytes received from the vehicle characteristic.
    /// - Returns: Decrypted payload, or nil if authentication/decryption fails.
    public func decryptResponse(domain: UInt32, rxBytes: Data) -> Data? {
        let maxBufferCapacity = 1024
        var outputBuffer = Data(count: maxBufferCapacity)
        var writtenSize: Int = 0
        
        let rxBytesArray = Array(rxBytes)
        let status = outputBuffer.withUnsafeMutableBytes { (outPtr: UnsafeMutableRawBufferPointer) -> Int32 in
            guard let baseAddress = outPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return -1 }
            return tesla_client_decrypt_response(
                clientBuffer,
                domain,
                rxBytesArray,
                rxBytesArray.count,
                baseAddress,
                maxBufferCapacity,
                &writtenSize
            )
        }
        
        guard status == 0 else {
            print("[TeslaClient] Failed to decrypt response on domain \(domain): \(status)")
            return nil
        }
        
        return outputBuffer.prefix(writtenSize)
    }
}
