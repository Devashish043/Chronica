#pragma once

#include <string>

namespace CryptoUtils {

    // Generates a 6-digit cryptographically secure OTP (bias-free rejection sampling)
    std::string GenerateSecureOTP();

    // Hashes a string using SHA-256, returns lowercase hex string.
    // Uses the EVP digest API (OpenSSL 3.x compatible).
    std::string HashData(const std::string& input);

    // Encrypts plaintext using AES-256-GCM (authenticated encryption).
    //
    // - key  : must be exactly 32 bytes.
    // - A random 12-byte IV (nonce) is generated internally per call.
    // - A 16-byte GCM authentication tag is appended automatically.
    //
    // Returned format (single base64 token):
    //   Base64( IV[12] || Ciphertext[N] || Tag[16] )
    //
    // GCM provides both confidentiality AND integrity/authenticity, making it
    // immune to padding-oracle attacks and ciphertext tampering.
    std::string EncryptAES256GCM(const std::string& plaintext, const std::string& key);

    // Decrypts and authenticates a blob produced by EncryptAES256GCM.
    // Throws std::runtime_error immediately if GCM tag verification fails,
    // meaning any tampering with the ciphertext is detected before any
    // plaintext is returned.
    // key must be exactly 32 bytes.
    std::string DecryptAES256GCM(const std::string& ciphertext_b64, const std::string& key);

    // Base64 helpers (used internally; exposed for convenience)
    std::string Base64Encode(const unsigned char* buffer, size_t length);
    std::string Base64Decode(const std::string& input);

} // namespace CryptoUtils