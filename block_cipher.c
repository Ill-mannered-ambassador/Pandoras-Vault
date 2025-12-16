#include <stdio.h>
#include <stdint.h>
#include <string.h>


#define NUM_ROUNDS 16

static uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

uint32_t feistel_function(uint32_t R, uint32_t key, int mfa_status) {
    uint32_t t = R ^ key;
    
    // MFA Valid (1) -> Multiplier 31337 (Odd/Invertible)
    // MFA Fail  (0) -> Multiplier 31336 (Even/Destructive)
    uint32_t multiplier = (mfa_status == 1) ? 31337 : 31336;
    
    t = (t * multiplier) + 0x12345678; 
    return rotl32(t, 5);
}

void generate_keys(const char *password, uint32_t *keys) {
    uint32_t seed = 0;
    while (*password) {
        seed = ((seed << 5) + seed) + *password++;
    }
    for(int i=0; i<NUM_ROUNDS; i++) {
        keys[i] = seed + (i * 0x9E3779B9); 
        seed = rotl32(seed, 3); 
    }
}

void feistel_block_operate(uint32_t *left, uint32_t *right, uint32_t *keys, int mfa_status) {
    uint32_t temp;
    for (int i = 0; i < NUM_ROUNDS; i++) {
        uint32_t old_right = *right;
        uint32_t f_out = feistel_function(*right, keys[i], mfa_status);
        *right = *left ^ f_out;
        *left = old_right;
    }
    temp = *left; *left = *right; *right = temp;
}


void print_output_as_text(uint32_t L, uint32_t R) {
    char buf[9];
    memcpy(buf, &L, 4);
    memcpy(buf + 4, &R, 4);
    buf[8] = '\0'; 
    
    printf(" -> Text: \"");
    for(int i=0; i<8; i++) {
        unsigned char c = buf[i];
        if (c >= 32 && c <= 126) printf("%c", c);
        else printf("\\x%02X", c); 
    }
    printf("\"");
}

/*
int main() {
    
    uint32_t L_orig = 0x62656369; // "iceb"
    uint32_t R_orig = 0x73677265; // "ergs"
    
    uint32_t keys[NUM_ROUNDS];
    generate_keys("Hunter2", keys);
    
    uint32_t decrypt_keys[NUM_ROUNDS];
    for(int i=0; i<NUM_ROUNDS; i++) decrypt_keys[i] = keys[NUM_ROUNDS - 1 - i];

    //ENCRYPTION PHASE (Simulated Upload)
    uint32_t L = L_orig, R = R_orig;
    
    // MFA is always valid (1) during encryption/upload
    feistel_block_operate(&L, &R, keys, 1); 
    

    // DECRYPTION PHASE (Simulated Download)
    int entered_otp;
    printf("\nEnter OTP to Decrypt: ");
    scanf("%d", &entered_otp);

    int mfa_status = (entered_otp == TARGET_OTP) ? 1 : 0;
    
    feistel_block_operate(&L, &R, decrypt_keys, mfa_status);


    printf("  Hex Output: %08X %08X", L, R);
    print_output_as_text(L, R);
    printf("\n");
    

    return 0;
}

*/

// 1. ENCRYPT EXPORT


void wasm_encrypt_file(uint8_t* data, int length, char* password) {
    uint32_t keys[NUM_ROUNDS];
    generate_keys(password, keys);

    uint32_t* blocks = (uint32_t*)data;
    int block_count = length / 8;

    for (int i = 0; i < block_count; i++) {
        feistel_block_operate(&blocks[i*2], &blocks[i*2 + 1], keys, 1);
    }
}

// 2. DECRYPT EXPORT

void wasm_decrypt_file(uint8_t* data, int length, char* password, int mode) {
    uint32_t keys[NUM_ROUNDS];
    generate_keys(password, keys);
    
    uint32_t decrypt_keys[NUM_ROUNDS];
    for(int i=0; i<NUM_ROUNDS; i++) decrypt_keys[i] = keys[NUM_ROUNDS - 1 - i];

    int mfa_status = mode;

    uint32_t* blocks = (uint32_t*)data;
    int block_count = length / 8;

    for (int i = 0; i < block_count; i++) {
        feistel_block_operate(&blocks[i*2], &blocks[i*2 + 1], decrypt_keys, mfa_status);
    }
}