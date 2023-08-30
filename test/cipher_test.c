#include "jssl.h"
#include "cipher.h"

//TODO: Non-multiples of 16 fail with padding=NONE
#define INPUT_SIZE 32 
static byte input[] = { 0x1, 0x10, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                        0x2, 0x20, 0x2f, 0x2e, 0x2d, 0x2c, 0x2b, 0x2a,
                        0x3, 0x30, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                        0x4, 0x40, 0x4f, 0x4e, 0x4d, 0x4c, 0x4b, 0x4a };

static int array_equals(byte a1[], int l1, byte a2[], int l2) {
    if (l1 != l2) return 0;

    for (int i = 0; i < l1; i++) {
        if (a1[i] != a2[i]) return 0;
    }

    return 1;
}

int test_round_trip(const char *cipher_type, const char *padding_name) {
    unsigned char *key = "FEDCBA9876543210";
    unsigned char *iv = "1234567887654321";

    byte encrypted_output[1024], decrypted_output[1024];
    int enc_out_len = 0, dec_out_len = 0, tmplen = 0; 
 
    cipher_context *context = create_cipher_context(cipher_type, padding_name);
    if (IS_NULL(context)) {
        return 0;
    }

    cipher_init(context, ENCRYPT, key, iv);
    cipher_update(context, input, 0, INPUT_SIZE, encrypted_output, 0, &enc_out_len);
    cipher_do_final(context, encrypted_output + enc_out_len, &tmplen);
    enc_out_len += tmplen;

    tmplen = 0;
    cipher_init(context, DECRYPT, key, iv);
    cipher_update(context, encrypted_output, 0, enc_out_len, decrypted_output, 0, &dec_out_len);
    cipher_do_final(context, decrypted_output + dec_out_len, &tmplen);
    dec_out_len += tmplen;

    if (array_equals(decrypted_output, dec_out_len, input, INPUT_SIZE)) {
        return 1;
    } else {
        return 0;
    }
}

int main(int argc, char ** argv) {
    char *cipher_type[] = {
        "AES-128-ECB",
	"AES-256-ECB",
        "AES-128-CBC",
        "AES-256-CBC",
        "AES-128-CFB1",
        "AES-256-CFB1",
        "AES-192-CFB1",
        "AES-128-CFB8",
        "AES-192-CFB8",
        "AES-256-CFB8",
        "AES-128-CFB128",
        "AES-192-CFB128",
        "AES-256-CFB128",
        "AES-128-CTR",
        "AES-192-CTR",
        "AES-256-CTR",
        "AES-128-CCM",
        "AES-256-CCM",
        "AES-192-CCM",
        "AES-128-GCM",
        "AES-192-GCM",
        "AES-256-GCM"
    };

    char *padding_type[] = {
        "NONE",
        "PKCS7",
        "PKCS5",
        "ISO10126-2",
        "X9.23",
        "ISO7816-4"
    }; 

    int n_cipher_types  = 19;
    int n_padding_types = 6;

    for (int i = 0; i < n_cipher_types; i++) {
        for(int j = 0; j < n_padding_types; j++) {
            if(!test_round_trip(cipher_type[i], padding_type[j])) {
                printf("FAILED: test_round_trip(%s, %s)\n", cipher_type[i], padding_type[j]);
            } else {
                printf("PASSED: test_round_trip(%s, %s)\n", cipher_type[i], padding_type[j]);
            }
        }
    }

    return 0;
}
