/* Reproduce the public fixture with SQLite3 Multiple Ciphers 2.5.1.
 * Place beside the upstream sqlite3mc_amalgamation.c and compile with:
 * cc -O2 generate.c -lm -lpthread -ldl -o generate
 * Run with a new plaintext path and output path: ./generate plain.db fixture.enc
 */
#include "sqlite3mc_amalgamation.c"

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    sqlite3 *db = 0;
    if (sqlite3_open(argv[1], &db)) return 3;
    if (sqlite3_exec(db,
        "PRAGMA page_size=4096; CREATE TABLE sample(id INTEGER PRIMARY KEY, body TEXT);"
        "INSERT INTO sample VALUES(1,'中文、换行测试 ✅');"
        "INSERT INTO sample VALUES(2, printf('%.*c',9000,'x'));", 0, 0, 0)) return 4;
    sqlite3_close(db);
    AES128Cipher ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.m_keyLength = 16;
    for (int i = 0; i < 16; i++) ctx.m_key[i] = i;
    ctx.m_aes = malloc(sizeof(Rijndael));
    if (!ctx.m_aes) return 5;
    RijndaelCreate(ctx.m_aes);
    FILE *input = fopen(argv[1], "rb"), *output = fopen(argv[2], "wb");
    if (!input || !output) return 6;
    unsigned char page[4096];
    int number = 1;
    size_t count;
    while ((count = fread(page, 1, sizeof(page), input))) {
        if (count != sizeof(page) || EncryptPageAES128Cipher(&ctx, number++, page, sizeof(page), 0) != SQLITE_OK) return 7;
        if (fwrite(page, 1, sizeof(page), output) != sizeof(page)) return 8;
    }
    int result = ferror(input) || fclose(output);
    fclose(input);
    free(ctx.m_aes);
    return result ? 9 : 0;
}
