/* Read-only probe for the owner's selected WXWork process inside Wine.
 * Build: i686-w64-mingw32-gcc -O2 -municode client_probe.c -o client_probe.exe
 */
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>
#include <stdint.h>

/* Candidates stay in the caller's private file; stdout never contains keys
 * or process memory. A candidate is only a heuristic, not a verified key.
 * The caller must validate decrypted pages and SQLite integrity separately.
 */
static int collect_candidates(HANDLE process, const wchar_t *output,
                              ULONGLONG *scanned, DWORD *count, BOOL *complete) {
    HANDLE file = CreateFileW(output, GENERIC_WRITE, 0, NULL, TRUNCATE_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 0;
    unsigned char *buffer = malloc(65536 + 32);
    if (!buffer) { CloseHandle(file); return 0; }
    const ULONGLONG byte_limit = 512ULL * 1024 * 1024;
    ULONGLONG started = GetTickCount64();
    uintptr_t cursor = 0;
    MEMORY_BASIC_INFORMATION region;
    *complete = TRUE;
    int ok = 1;
    while (VirtualQueryEx(process, (LPCVOID)cursor, &region, sizeof(region))) {
        uintptr_t next = (uintptr_t)region.BaseAddress + region.RegionSize;
        if (next <= cursor) break;
        DWORD protection = region.Protect & 0xff;
        if (region.State == MEM_COMMIT && region.Type == MEM_PRIVATE &&
            !(region.Protect & PAGE_GUARD) &&
            (protection == PAGE_READWRITE || protection == PAGE_WRITECOPY)) {
            for (SIZE_T offset = 0; offset < region.RegionSize; offset += 65536) {
                if (*scanned >= byte_limit || *count >= 65536 || GetTickCount64() - started > 30000) {
                    *complete = FALSE;
                    goto done;
                }
                SIZE_T length = region.RegionSize - offset;
                if (length > 65536 + 32) length = 65536 + 32;
                SIZE_T received = 0;
                if (!ReadProcessMemory(process, (unsigned char *)region.BaseAddress + offset,
                                       buffer, length, &received)) continue;
                *scanned += received;
                for (SIZE_T i = 0; i + 20 <= received && i < 65536; i += 4) {
                    /* wxSQLite3 stores a little-endian key length immediately
                     * before the 16-byte derived cipher key. Confirm the
                     * surrounding cipher layout in the verifier, not here.
                     */
                    if (buffer[i] != 16 || buffer[i+1] || buffer[i+2] || buffer[i+3]) continue;
                    DWORD written = 0;
                    if (!WriteFile(file, buffer + i + 4, 16, &written, NULL) || written != 16) {
                        ok = 0;
                        goto done;
                    }
                    if (++*count >= 65536) { *complete = FALSE; goto done; }
                }
            }
        }
        cursor = next;
    }
done:
    SecureZeroMemory(buffer, 65536 + 32);
    free(buffer);
    if (!FlushFileBuffers(file)) ok = 0;
    CloseHandle(file);
    return ok;
}

int wmain(int argc, wchar_t **argv) {
    if (argc != 2 && argc != 5) {
        puts("{\"ok\":false,\"code\":\"EXACT_CLIENT_PATH_REQUIRED\"}");
        return 2;
    }
    HANDLE list = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (list == INVALID_HANDLE_VALUE) return 3;
    PROCESSENTRY32W entry = {0};
    entry.dwSize = sizeof(entry);
    int found = 0;
    for (BOOL more = Process32FirstW(list, &entry); more; more = Process32NextW(list, &entry)) {
        if (_wcsicmp(entry.szExeFile, L"WXWork.exe")) continue;
        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                     FALSE, entry.th32ProcessID);
        if (!process) continue;
        wchar_t path[32768];
        DWORD length = 32768;
        if (!QueryFullProcessImageNameW(process, 0, path, &length) || _wcsicmp(path, argv[1])) {
            CloseHandle(process);
            continue;
        }
        FILETIME created = {0}, exited = {0}, kernel = {0}, user = {0};
        BOOL identity = GetProcessTimes(process, &created, &exited, &kernel, &user);
        ULONGLONG time = ((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime;
        if (argc == 5) {
            /* Scan only the previously probed PID and creation time. */
            if (!identity || entry.th32ProcessID != wcstoul(argv[2], NULL, 10) ||
                time != _wcstoui64(argv[3], NULL, 10)) {
                CloseHandle(process);
                continue;
            }
            ULONGLONG scanned = 0;
            DWORD candidates = 0;
            BOOL complete = FALSE;
            int ok = collect_candidates(process, argv[4], &scanned, &candidates, &complete);
            DWORD exit_code = 0;
            FILETIME after = {0};
            BOOL unchanged = GetProcessTimes(process, &after, &exited, &kernel, &user)
                && CompareFileTime(&created, &after) == 0
                && GetExitCodeProcess(process, &exit_code) && exit_code == STILL_ACTIVE;
            printf("{\"ok\":%s,\"windows_pid\":%lu,\"identity_unchanged\":%s,"
                   "\"scanned_bytes\":%llu,\"candidate_count\":%lu,\"scan_complete\":%s,"
                   "\"native_call_performed\":false}\n",
                   ok && unchanged ? "true" : "false", entry.th32ProcessID,
                   unchanged ? "true" : "false", scanned, candidates, complete ? "true" : "false");
            CloseHandle(process);
            ++found;
            break;
        }
        HANDLE modules = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, entry.th32ProcessID);
        MODULEENTRY32W module = {0};
        module.dwSize = sizeof(module);
        BOOL readable = FALSE;
        if (modules != INVALID_HANDLE_VALUE) {
            if (Module32FirstW(modules, &module)) {
                unsigned char header[2] = {0};
                SIZE_T count = 0;
                readable = ReadProcessMemory(process, module.modBaseAddr, header,
                                             sizeof(header), &count) && count == 2
                           && header[0] == 'M' && header[1] == 'Z';
            }
            CloseHandle(modules);
        }
        printf("{\"ok\":%s,\"windows_pid\":%lu,\"creation_filetime\":%llu,"
               "\"executable_header_read_verified\":%s,\"native_call_performed\":false}\n",
               identity && readable ? "true" : "false", entry.th32ProcessID,
               identity ? time : 0, readable ? "true" : "false");
        CloseHandle(process);
        ++found;
    }
    CloseHandle(list);
    if (!found) puts("{\"ok\":false,\"code\":\"CLIENT_NOT_FOUND\"}");
    return found ? 0 : 1;
}
