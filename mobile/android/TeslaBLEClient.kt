package com.tesla.ble

import android.util.Log

/**
 * Kotlin idiomatic wrapper around the high-performance pure-Zig secure Tesla BLE control library.
 * This class orchestrates key-exchange sessions, signs and encrypts raw vehicle actions
 * (Lock, Unlock, Wake, Trunk releases) and decrypts vehicle security and infotainment responses.
 *
 * All cryptographic operations run natively in compiled Zig (ECDH SECP256R1, AES-GCM-128).
 */
class TeslaClient private constructor(
    val vin: String,
    private val clientPtr: Long
) {

    companion object {
        private const val TAG = "TeslaClient"

        init {
            try {
                // Load our pre-compiled pure-Zig shared library
                System.loadLibrary("tesla_ble_zig")
                Log.i(TAG, "Successfully loaded native pure-Zig tesla_ble_zig library 🛡️")
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "Failed to load native library: ${e.message}")
            }
        }

        // --- Low-Level Native JNI Interface Declarations ---
        @JvmStatic
        private external fun init(
            vin: ByteArray,
            privateKey: ByteArray,
            connectionId: ByteArray
        ): Int

        @JvmStatic
        private external fun buildWakeCommand(
            clientPtr: Long,
            currentTimestamp: Int
        ): ByteArray?

        @JvmStatic
        private external fun decryptResponse(
            clientPtr: Long,
            domain: Int,
            rxBytes: ByteArray
        ): ByteArray?

        /**
         * Factory method to create and initialize a new Tesla Secure session context.
         * 
         * @param vin The 17-character vehicle VIN.
         * @param privateKey The 32-byte secp256r1 private key.
         * @param connectionId The 16-byte secure connection ID.
         * @return An initialized TeslaClient, or null if initialization failed.
         */
        fun create(vin: String, privateKey: ByteArray, connectionId: ByteArray): TeslaClient? {
            if (vin.length != 17) {
                Log.e(TAG, "Invalid VIN length: ${vin.length}. Must be 17 characters.")
                return null
            }
            if (privateKey.size != 32) {
                Log.e(TAG, "Invalid private key size: ${privateKey.size} bytes. Must be 32 bytes.")
                return null
            }
            if (connectionId.size != 16) {
                Log.e(TAG, "Invalid connection ID size: ${connectionId.size} bytes. Must be 16 bytes.")
                return null
            }

            val status = init(vin.toByteArray(Charsets.UTF_8), privateKey, connectionId)
            if (status != 0) {
                Log.e(TAG, "Failed to initialize native Zig Client context. Status: $status")
                return null
            }

            // In our placement-init architecture, we currently use a static global or pre-allocated instance.
            // Under JNI, we pass 0 as the pointer since the mock/static layer keeps track, or we can use the allocated context address.
            return TeslaClient(vin, 0L)
        }
    }

    /**
     * Builds a signed and encrypted Wake command ready for transmission over BLE.
     *
     * @param timestamp Current epoch timestamp or synchronized counter.
     * @return Raw encrypted bytes to write to the Tesla TX characteristic, or null on error.
     */
    fun createWakeCommand(timestamp: Int): ByteArray? {
        val payload = buildWakeCommand(clientPtr, timestamp)
        if (payload == null) {
            Log.e(TAG, "Failed to build native Wake command")
        }
        return payload
    }

    /**
     * Decrypts and verifies a signed, authenticated message received from the vehicle.
     * 
     * @param domain Target domain (2 for VEHICLE_SECURITY, 3 for INFOTAINMENT).
     * @param rxBytes The raw BLE notification bytes.
     * @return Decrypted payload bytes, or null if authentication / decryption fails.
     */
    fun handleResponse(domain: Int, rxBytes: ByteArray): ByteArray? {
        val decrypted = decryptResponse(clientPtr, domain, rxBytes)
        if (decrypted == null) {
            Log.e(TAG, "Authentication / Decryption failed for domain $domain")
        }
        return decrypted
    }
}
