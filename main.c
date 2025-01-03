#include <stdio.h>
#include <stdint.h>

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>


#define MAX_PRINT_STRING_LEN 1024
static char temp_hex_string[MAX_PRINT_STRING_LEN + 1];

const char *hex_string(const uint8_t *src, size_t length)
{
    memset(temp_hex_string, 0, sizeof(temp_hex_string));
    for (size_t i = 0; i < length; i++) {
        sprintf(temp_hex_string + (i*2), "%02x", src[i]);
    }
    return temp_hex_string;
}


static int test()
{
    uint8_t key[16] = {
        0xc6, 0x1e, 0x7a, 0x93, 0x74, 0x4f, 0x39, 0xee,
        0x10, 0x73, 0x4a, 0xfe, 0x3f, 0xf7, 0xa0, 0x87
    };

    uint8_t iv_0[16] = {
        0x30, 0xcb, 0xbc, 0x08, 0x4c, 0xc3, 0x36, 0x3b,
        0xd4, 0x9d, 0xb3, 0x4a, 0x88, 0xd4, 0x00, 0x00
    };

    uint8_t src_0[] = {
        0x51, 0x00, 0x02, 0x00, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab
    };
    size_t src_0_len = sizeof(src_0);

    uint8_t ref_0[] = {
        0xeb, 0x92, 0x36, 0x52, 0x51, 0xc3, 0xe0, 0x36,
        0xf8, 0xde, 0x27, 0xe9, 0xc2, 0x7e, 0xe3, 0xe0,
        0xb4, 0x65, 0x1d, 0x9f
    };

    uint8_t iv_1[16] = {
        0x30, 0xcb, 0xbc, 0x08, 0x4c, 0xc3, 0x36, 0x3b,
        0xd4, 0x9d, 0xb3, 0x4a, 0x88, 0xd7, 0x00, 0x00
    };

    uint8_t src_1[] = {
        0x05, 0x02, 0x00, 0x02, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab
    };
    size_t src_1_len = sizeof(src_1);

    uint8_t ref_1[] = {
        0x4e, 0xd9, 0xcc, 0x4e, 0x6a, 0x71, 0x2b, 0x30,
        0x96, 0xc5, 0xca, 0x77, 0x33, 0x9d, 0x42, 0x04,
        0xce, 0x0d, 0x77, 0x39
    };

    printf("init\n");

    Aes aes;
    int err = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (err < 0) {
        printf("init failed wolfSSL error code: %d\n", err);
        return 1;
    }

    printf("key: %s\n", hex_string(key, sizeof(key)));

    err = wc_AesSetKey(&aes, key, sizeof(key), NULL, AES_ENCRYPTION);
    if (err < 0) {
        printf("set key, wolfSSL error code: %d", err);
        return 1;
    }

    printf("iv_0: %s\n", hex_string(iv_0, sizeof(iv_0)));

    err = wc_AesSetIV(&aes, iv_0);
    if (err < 0) {
        printf("set IV 0, wolfSSL error code: %d", err);
        return 1;
    }

    printf("src_0: %s\n", hex_string(src_0, src_0_len));

    err = wc_AesCtrEncrypt(&aes, src_0, src_0, src_0_len);
    if (err < 0) {
        printf("encrypt 0, wolfSSL encrypt error: %d", err);
        return 1;
    }

    printf("enc_0: %s\n", hex_string(src_0, src_0_len));

    if (memcmp(src_0, ref_0, sizeof(src_0)) != 0) {
        printf("encrypt 0 failed, not equal\n");
        printf("ref_0: %s\n", hex_string(ref_0, sizeof(ref_0)));
        return 1;
    }

    printf("iv_1 : %s\n", hex_string(iv_1, sizeof(iv_1)));

    err = wc_AesSetIV(&aes, iv_1);
    if (err < 0) {
        printf("set IV 1, wolfSSL error code: %d", err);
        return 1;
    }

    printf("src_1: %s\n", hex_string(src_1, src_1_len));

    err = wc_AesCtrEncrypt(&aes, src_1, src_1, src_1_len);
    if (err < 0) {
        printf("encrypt 1, wolfSSL encrypt error: %d", err);
        return 1;
    }

    printf("enc_1: %s\n", hex_string(src_1, src_1_len));

    if (memcmp(src_1, ref_1, src_1_len) != 0) {
        printf("encrypt 1 failed, not equal\n");
        printf("ref_1: %s\n", hex_string(ref_1, sizeof(ref_1)));
        return 1;
    }

    wc_AesFree(&aes);

    return 0;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    printf("Wolfssl Test\n");
    if (test() != 0) {
        return 1;
    }
    printf("Passed\n");
    return 0;
}