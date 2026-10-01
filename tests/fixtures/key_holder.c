/* Wine integration fixture; never an actual WeCom client.
 * Build with i686-w64-mingw32-gcc -O2 key_holder.c -o WXWork.exe.
 * Launch from a temporary fixture directory, never replacing the real client.
 * Its process name exercises
 * exact executable-path selection, while the data/key are public test values.
 */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
    unsigned char *memory = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!memory) return 2;
    /* Cipher-shaped data straddles a 64 KiB scan boundary in the separate
     * larger allocation, exercising overlap without reading beyond a region.
     */
    unsigned char *large = VirtualAlloc(NULL, 131072, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!large) return 3;
    uint32_t *context = (uint32_t *)(large + 65524);
    context[0] = 0;
    context[1] = 0;
    context[2] = 16;
    unsigned char *key = (unsigned char *)(context + 3);
    for (int i = 0; i < 16; ++i) key[i] = (unsigned char)i;
    memory[0] = 1;
    puts("public key fixture ready");
    fflush(stdout);
    Sleep(20000);
    SecureZeroMemory(large, 131072);
    VirtualFree(large, 0, MEM_RELEASE);
    VirtualFree(memory, 0, MEM_RELEASE);
    return 0;
}
