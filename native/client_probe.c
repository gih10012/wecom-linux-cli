/* Read-only probe for the owner's selected WXWork process inside Wine.
 * Build: i686-w64-mingw32-gcc -O2 -municode client_probe.c -o client_probe.exe
 */
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>

int wmain(int argc, wchar_t **argv) {
    if (argc != 2) {
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
        ULONGLONG time = ((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime;
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
