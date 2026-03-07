#include "CryptoUtils.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <memory>
#include <cstring>
#include <cstdint>

namespace CryptoUtils {

// =============================================================================
//  Internal constants
// =============================================================================
static constexpr int GCM_IV_LEN  = 12;   // 96-bit nonce — NIST recommended for GCM
static constexpr int GCM_TAG_LEN = 16;   // 128-bit authentication tag

// =============================================================================
//  GenerateSecureOTP
//
//  FIX: Rejection sampling eliminates modulo bias.
//  UINT32_MAX is not evenly divisible by 1,000,000, so naive `val % 1000000`
//  makes lower OTP values slightly more probable. We discard samples that fall
//  in the uneven remainder region so every value in [0, 1000000) is equally
//  likely.
// =============================================================================
std::string GenerateSecureOTP() {
    unsigned char buffer[4];
    uint32_t val;

    // Largest multiple of 1,000,000 that fits in uint32_t.
    // Any sample >= limit is discarded.
    const uint32_t limit = (0xFFFFFFFFu / 1000000u) * 1000000u;

    do {
        if (RAND_bytes(buffer, sizeof(buffer)) != 1) {
            throw std::runtime_error("GenerateSecureOTP: RAND_bytes failed");
        }
        std::memcpy(&val, buffer, sizeof(val));
    } while (val >= limit);

    val = val % 1000000u;

    std::ostringstream ss;
    ss << std::setw(6) << std::setfill('0') << val;
    return ss.str();
}

// =============================================================================
//  HashData
//
//  FIX: Replaced deprecated SHA256_CTX / SHA256_Init / SHA256_Update /
//  SHA256_Final (removed in OpenSSL 3.x) with the EVP digest API.
//  EVP_MD_CTX is RAII-managed via unique_ptr — no leaks on exceptions.
// =============================================================================
std::string HashData(const std::string& input) {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>
        ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);

    if (!ctx) {
        throw std::runtime_error("HashData: EVP_MD_CTX_new failed");
    }
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("HashData: EVP_DigestInit_ex failed");
    }
    // FIX (c_str -> data): input may contain embedded nulls; data() expresses
    // raw binary buffer intent more accurately than c_str().
    if (EVP_DigestUpdate(ctx.get(), input.data(), input.size()) != 1) {
        throw std::runtime_error("HashData: EVP_DigestUpdate failed");
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int  hashLen = 0;
    if (EVP_DigestFinal_ex(ctx.get(), hash, &hashLen) != 1) {
        throw std::runtime_error("HashData: EVP_DigestFinal_ex failed");
    }

    std::ostringstream ss;
    for (unsigned int i = 0; i < hashLen; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(hash[i]);
    }
    return ss.str();
}

// =============================================================================
//  Base64Encode
//
//  FIX: Added null checks on BIO_new() return values.
//  If either allocation fails the previous code would crash immediately on the
//  next BIO_set_flags / BIO_push call (null dereference).  We now throw a
//  descriptive exception instead, and free any already-allocated BIO to avoid
//  a leak.
// =============================================================================
std::string Base64Encode(const unsigned char* buffer, size_t length) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());

    // FIX: guard both allocations before touching either pointer.
    if (!b64 || !mem) {
        BIO_free(b64);   // safe to call on nullptr
        BIO_free(mem);
        throw std::runtime_error("Base64Encode: BIO allocation failed");
    }

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* bio = BIO_push(b64, mem);   // b64 now owns mem; free via BIO_free_all(bio)

    BIO_write(bio, buffer, static_cast<int>(length));
    BIO_flush(bio);

    BUF_MEM* bufPtr = nullptr;
    BIO_get_mem_ptr(bio, &bufPtr);

    std::string result(bufPtr->data, bufPtr->length);
    BIO_free_all(bio);
    return result;
}

// =============================================================================
//  Base64Decode
//
//  FIX: Replaced raw malloc (no null check, manual free) with std::vector.
//  Added null checks on BIO allocations consistent with Base64Encode.
//  data() used instead of c_str() for the binary input buffer.
// =============================================================================
std::string Base64Decode(const std::string& input) {
    std::vector<unsigned char> buf(input.size());   // decoded length <= input length

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(input.data(), static_cast<int>(input.size()));

    // FIX: guard both allocations.
    if (!b64 || !mem) {
        BIO_free(b64);
        BIO_free(mem);
        throw std::runtime_error("Base64Decode: BIO allocation failed");
    }

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* bio = BIO_push(b64, mem);

    int finalLen = BIO_read(bio, buf.data(), static_cast<int>(input.size()));
    BIO_free_all(bio);

    if (finalLen < 0) {
        throw std::runtime_error("Base64Decode: BIO_read failed");
    }

    return std::string(reinterpret_cast<char*>(buf.data()),
                       static_cast<size_t>(finalLen));
}

// =============================================================================
//  EncryptAES256GCM
//
//  CRITICAL FIX: Replaced AES-256-CBC with AES-256-GCM.
//
//  Why CBC was dangerous:
//    - CBC provides NO integrity protection.  An attacker who can submit
//      modified ciphertexts and observe whether decryption succeeds can mount
//      a padding-oracle attack to recover the plaintext byte-by-byte.
//    - Bit-flipping attacks allow predictable changes to plaintext.
//
//  Why GCM is correct:
//    - GCM is Authenticated Encryption with Associated Data (AEAD).
//    - It produces a 128-bit authentication tag over the ciphertext.
//    - Any single-bit modification to the ciphertext, IV, or tag causes
//      EVP_DecryptFinal_ex to return failure BEFORE any plaintext is exposed.
//    - No padding is used, so padding-oracle attacks are structurally impossible.
//
//  Wire format (all packed into one base64 token):
//    Base64( IV[12] || Ciphertext[N] || Tag[16] )
//
//  Additional fixes applied here:
//    - Key validated to exactly 32 bytes before use.
//    - EVP_CIPHER_CTX wrapped in unique_ptr (RAII) — no ctx leak on exception.
//    - key.data() / plaintext.data() used instead of c_str() for binary safety.
// =============================================================================
std::string EncryptAES256GCM(const std::string& plaintext, const std::string& key) {
    if (key.size() != 32) {
        throw std::invalid_argument(
            "EncryptAES256GCM: key must be exactly 32 bytes for AES-256");
    }

    // Generate a fresh 12-byte (96-bit) random nonce — mandatory for GCM security.
    // Reusing a (key, nonce) pair completely breaks GCM confidentiality and authenticity.
    unsigned char iv[GCM_IV_LEN];
    if (RAND_bytes(iv, GCM_IV_LEN) != 1) {
        throw std::runtime_error("EncryptAES256GCM: RAND_bytes failed for IV");
    }

    // RAII context — freed automatically even if a throw occurs below.
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>
        ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        throw std::runtime_error("EncryptAES256GCM: EVP_CIPHER_CTX_new failed");
    }

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw std::runtime_error("EncryptAES256GCM: EVP_EncryptInit_ex (cipher) failed");
    }

    // Set IV length explicitly (OpenSSL default is 12 bytes, but being explicit
    // is safer if this code is ever adapted for non-standard nonce lengths).
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, nullptr) != 1) {
        throw std::runtime_error("EncryptAES256GCM: setting IV length failed");
    }

    // FIX (c_str -> data): key and iv are raw binary buffers, not C strings.
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
                           reinterpret_cast<const unsigned char*>(key.data()),
                           iv) != 1) {
        throw std::runtime_error("EncryptAES256GCM: EVP_EncryptInit_ex (key/IV) failed");
    }

    // Ciphertext is the same length as plaintext in GCM (stream cipher mode — no padding).
    std::vector<unsigned char> ciphertext(plaintext.size());
    int len = 0;

    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len,
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          static_cast<int>(plaintext.size())) != 1) {
        throw std::runtime_error("EncryptAES256GCM: EVP_EncryptUpdate failed");
    }
    int ciphertext_len = len;

    // Finalise — for GCM this writes 0 extra bytes but generates the tag.
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len) != 1) {
        throw std::runtime_error("EncryptAES256GCM: EVP_EncryptFinal_ex failed");
    }
    ciphertext_len += len;   // len == 0 for GCM, but we add it for correctness

    // Retrieve the 16-byte authentication tag.
    unsigned char tag[GCM_TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1) {
        throw std::runtime_error("EncryptAES256GCM: retrieving GCM tag failed");
    }

    // Pack: IV || Ciphertext || Tag into a single buffer, then base64-encode it.
    std::vector<unsigned char> payload;
    payload.reserve(GCM_IV_LEN + ciphertext_len + GCM_TAG_LEN);
    payload.insert(payload.end(), iv,                        iv + GCM_IV_LEN);
    payload.insert(payload.end(), ciphertext.data(),         ciphertext.data() + ciphertext_len);
    payload.insert(payload.end(), tag,                       tag + GCM_TAG_LEN);

    return Base64Encode(payload.data(), payload.size());
}

// =============================================================================
//  DecryptAES256GCM
//
//  Decodes and verifies the blob produced by EncryptAES256GCM.
//
//  The GCM tag is verified by EVP_DecryptFinal_ex BEFORE any plaintext is
//  returned to the caller.  If verification fails the function throws
//  immediately — the caller never sees potentially forged plaintext.
//
//  Additional fixes applied here:
//    - Key validated to exactly 32 bytes.
//    - EVP_CIPHER_CTX is RAII-managed.
//    - key.data() used instead of key.c_str() for binary correctness.
// =============================================================================
std::string DecryptAES256GCM(const std::string& ciphertext_b64, const std::string& key) {
    if (key.size() != 32) {
        throw std::invalid_argument(
            "DecryptAES256GCM: key must be exactly 32 bytes for AES-256");
    }

    // Decode the base64 payload.
    const std::string payload = Base64Decode(ciphertext_b64);

    // Minimum valid payload: IV (12) + at least 0 bytes of ciphertext + Tag (16).
    if (payload.size() < static_cast<size_t>(GCM_IV_LEN + GCM_TAG_LEN)) {
        throw std::invalid_argument("DecryptAES256GCM: payload too short to be valid");
    }

    // Unpack IV || Ciphertext || Tag from the payload.
    const unsigned char* raw            = reinterpret_cast<const unsigned char*>(payload.data());
    const unsigned char* iv             = raw;
    const size_t         ciphertext_len = payload.size() - GCM_IV_LEN - GCM_TAG_LEN;
    const unsigned char* ciphertext_ptr = raw  + GCM_IV_LEN;
    const unsigned char* tag_ptr        = ciphertext_ptr + ciphertext_len;

    // Copy tag into a mutable buffer (EVP_CIPHER_CTX_ctrl requires non-const void*).
    unsigned char tag[GCM_TAG_LEN];
    std::memcpy(tag, tag_ptr, GCM_TAG_LEN);

    // RAII context.
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>
        ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        throw std::runtime_error("DecryptAES256GCM: EVP_CIPHER_CTX_new failed");
    }

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw std::runtime_error("DecryptAES256GCM: EVP_DecryptInit_ex (cipher) failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, nullptr) != 1) {
        throw std::runtime_error("DecryptAES256GCM: setting IV length failed");
    }

    // FIX (c_str -> data): raw binary key/IV — not null-terminated C strings.
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr,
                           reinterpret_cast<const unsigned char*>(key.data()),
                           iv) != 1) {
        throw std::runtime_error("DecryptAES256GCM: EVP_DecryptInit_ex (key/IV) failed");
    }

    std::vector<unsigned char> plaintext(ciphertext_len);
    int len = 0;

    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len,
                          ciphertext_ptr, static_cast<int>(ciphertext_len)) != 1) {
        throw std::runtime_error("DecryptAES256GCM: EVP_DecryptUpdate failed");
    }
    int plaintext_len = len;

    // Provide the expected tag BEFORE calling Final so OpenSSL can verify it.
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag) != 1) {
        throw std::runtime_error("DecryptAES256GCM: setting GCM tag failed");
    }

    // EVP_DecryptFinal_ex returns <= 0 if tag verification fails.
    // This is the authentication step — no plaintext is released on failure.
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len) <= 0) {
        throw std::runtime_error(
            "DecryptAES256GCM: authentication tag mismatch — "
            "ciphertext has been tampered with or the key is wrong");
    }
    plaintext_len += len;

    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}

} // namespace CryptoUtils