#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdint.h>
#include <time.h>


#define ROTLEFT(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

void sha1_expand_block(const uint8_t* block_64bytes, uint32_t* W) {

    for (int i = 0; i < 16; i++) {

        W[i] = ((uint32_t)block_64bytes[i * 4]     << 24) |
               ((uint32_t)block_64bytes[i * 4 + 1] << 16) |
               ((uint32_t)block_64bytes[i * 4 + 2] << 8)  |
               ((uint32_t)block_64bytes[i * 4 + 3]);
    }

    for (int i = 16; i < 80; i++) {

        uint32_t temp = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
        W[i] = ROTLEFT(temp, 1);
    }
}

void sha1_compress_cycle(uint32_t* W, uint32_t* state) {
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f, k, temp;
    for (int i = 0; i < 80; i++) {
        if (i <= 19) {
            f = (b & c) | ((~b) & d); 
            k = 0x5A827999;
        } 
        else if (i <= 39) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } 
        else if (i <= 59) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } 
        else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        temp = ROTLEFT(a, 5) + f + e + k + W[i];

        e = d;
        d = c;
        c = ROTLEFT(b, 30); 
        b = a;
        a = temp;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}


void sha1(const uint8_t *message, size_t len, uint8_t *digest) {
    uint32_t state[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    uint32_t W[80];
    uint8_t buffer[64];
    
    // Calculate full padded length (Msg + 0x80 + Zeros + 8-byte Length)
    size_t full_len = len + 1 + 8;
    size_t padded_len = (full_len + 63) / 64 * 64; 

    for (size_t i = 0; i < padded_len; i += 64) {
        memset(buffer, 0, 64);
        
        // Copy Message
        if (i < len) {
            size_t bytes_to_copy = (len - i) < 64 ? (len - i) : 64;
            memcpy(buffer, message + i, bytes_to_copy);
        }

        // Add 0x80 Byte (Padding Start)
        if (i <= len && len < i + 64) {
            buffer[len - i] = 0x80;
        }

        // Add Length in Bits (Big Endian) at the end of the last block
        if (i + 64 >= padded_len) {
            uint64_t bit_len = (uint64_t)len * 8;
            for(int j=0; j<8; j++) {
                buffer[63-j] = (bit_len >> (j*8)) & 0xFF;
            }
        }
        sha1_expand_block(buffer, W);
        sha1_compress_cycle(W, state);
    }

    for (int i = 0; i < 5; i++) {
        digest[i*4]     = (state[i] >> 24) & 0xFF;
        digest[i*4 + 1] = (state[i] >> 16) & 0xFF;
        digest[i*4 + 2] = (state[i] >> 8)  & 0xFF;
        digest[i*4 + 3] = state[i] & 0xFF;
    }
}

// --- 2. HMAC-SHA1 ---
void hmac_sha1(const uint8_t *key, size_t key_len, 
               const uint8_t *message, size_t msg_len, 
               uint8_t *output) {
    
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    uint8_t tk[20];
    uint8_t buffer[1024]; // Temp buffer

    // Prepare Key
    memset(k_ipad, 0, 64);
    memset(k_opad, 0, 64);
    
    if (key_len > 64) {
        sha1(key, key_len, tk);
        memcpy(k_ipad, tk, 20);
        memcpy(k_opad, tk, 20);
    } else {
        memcpy(k_ipad, key, key_len);
        memcpy(k_opad, key, key_len);
    }

    // XOR Constants (The Inner/Outer Pad logic)
    for (int i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5C;
    }

    // Inner Hash: SHA1(K_ipad + Message)
    memcpy(buffer, k_ipad, 64);
    memcpy(buffer + 64, message, msg_len);
    uint8_t inner_hash[20];
    sha1(buffer, 64 + msg_len, inner_hash);

    // Outer Hash: SHA1(K_opad + InnerHash)
    memcpy(buffer, k_opad, 64);
    memcpy(buffer + 64, inner_hash, 20);
    sha1(buffer, 64 + 20, output);
}

// --- 3. TOTP GENERATOR ---
int generate_totp(const uint8_t *secret, size_t secret_len, uint64_t time_step) {
    uint8_t hmac_result[20];
    
    // Convert Time to Bytes (Big Endian)
    uint8_t counter_bytes[8];
    for(int i=7; i>=0; i--) {
        counter_bytes[i] = time_step & 0xFF;
        time_step >>= 8;
    }

    // Generate HMAC
    hmac_sha1(secret, secret_len, counter_bytes, 8, hmac_result);

    // Truncate (Dynamic Offset)
    int offset = hmac_result[19] & 0x0F;
    uint32_t binary_code = 
          ((hmac_result[offset] & 0x7F) << 24)
        | ((hmac_result[offset + 1] & 0xFF) << 16)
        | ((hmac_result[offset + 2] & 0xFF) << 8)
        | (hmac_result[offset + 3] & 0xFF);

    // Modulo 10^6
    return binary_code % 1000000;
}


int main() {
    // 1. Get Current Unix Time
    time_t now = time(NULL);
    
    // 2. Calculate the "Step" (Integer Division by 30)
    uint64_t time_step = now / 30;
    
    // 3. Use the Secret Key (Same as before)
    uint8_t key[] = "12345678901234567890";
    
    // 4. Generate Code
    int code = generate_totp(key, 20, time_step);
    
    printf("Current Unix Time: %ld\n", now);
    printf("Current 30s Step:  %ld\n", time_step);
    printf("-------------------------\n");
    printf("YOUR TOTP CODE:    %06d\n", code);
    printf("-------------------------\n");
    
    return 0;
}