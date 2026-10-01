/* Validate aligned raw AES-128 key candidates against an existing page.
 * No keys, addresses, or memory are printed or written by this library.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/aes.h>

int find_key(const unsigned char *memory, size_t length,
             const unsigned char *page, const unsigned char *iv,
             unsigned char *output) {
    unsigned char input[24], digest[16], block[16], plain[16];
    memcpy(input + 16, "\x01\x00\x00\x00sAlT", 8);
    memcpy(block, page + 8, 8);
    memcpy(block + 8, page + 24, 8);
    for (size_t offset = 0; offset + 16 <= length; offset += 4) {
        const unsigned char *candidate = memory + offset;
        unsigned char nonzero = 0;
        for (int j = 0; j < 16; j++) nonzero |= candidate[j];
        if (!nonzero) continue;
        memcpy(input, candidate, 16);
        MD5(input, sizeof(input), digest);
        AES_KEY key;
        if (AES_set_decrypt_key(digest, 128, &key)) return -1;
        AES_decrypt(block, plain, &key);
        for (int j = 0; j < 8; j++) plain[j] ^= iv[j];
        if (!memcmp(plain, page + 16, 8)) {
            memcpy(output, candidate, 16);
            return 1;
        }
    }
    return 0;
}
