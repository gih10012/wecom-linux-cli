/* Read-only bounded lookup; no hooks or native calls. */
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
static DWORD expected_pid,window_count,window_tid;static HWND window;
static BOOL CALLBACK candidate(HWND h,LPARAM ignored) {
 (void)ignored;DWORD pid=0,tid=GetWindowThreadProcessId(h,&pid);wchar_t cls[128]={0};
 if(pid==expected_pid && !GetParent(h) && GetClassNameW(h,cls,128) && !wcscmp(cls,L"WeWorkWindow")) {window=h;window_tid=tid;window_count++;}
 return TRUE;
}
static BOOL read(HANDLE h,DWORD p,void *out,unsigned n) {SIZE_T got=0;return p && ReadProcessMemory(h,(LPCVOID)(uintptr_t)p,out,n,&got) && got==n;}
static BOOL owner(HANDLE h,DWORD env,ULONGLONG wanted) {
 DWORD a=0,b=0,c=0;ULONGLONG uid=0;
 return read(h,env+0x44,&a,4) && read(h,a+8,&b,4) && read(h,b+4,&c,4) && read(h,c+0x70,&uid,8) && uid==wanted;
}
int wmain(int argc,wchar_t **argv) {
 if(argc!=6)return 2;
 DWORD pid=wcstoul(argv[2],NULL,10);ULONGLONG expected=_wcstoui64(argv[3],NULL,10),uid=_wcstoui64(argv[5],NULL,10);
 HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pid);if(!h)return 3;
 wchar_t path[512];DWORD n=512;FILETIME create,e,k,u;BOOL traced=TRUE;
 if(!QueryFullProcessImageNameW(h,0,path,&n) || _wcsicmp(path,argv[1]) || !GetProcessTimes(h,&create,&e,&k,&u) ||
 (((ULONGLONG)create.dwHighDateTime<<32)|create.dwLowDateTime)!=expected || !CheckRemoteDebuggerPresent(h,&traced) || traced) {CloseHandle(h);return 4;}
 HANDLE modules=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pid);MODULEENTRY32W module={0};module.dwSize=sizeof(module);
 if(modules==INVALID_HANDLE_VALUE || !Module32FirstW(modules,&module)) {if(modules!=INVALID_HANDLE_VALUE)CloseHandle(modules);CloseHandle(h);return 5;}
 DWORD base=(DWORD)(uintptr_t)module.modBaseAddr;CloseHandle(modules);
 if(wcscmp(argv[4],L"-")) {HDESK d=OpenDesktopW(argv[4],0,FALSE,DESKTOP_ENUMERATE|DESKTOP_READOBJECTS|DESKTOP_WRITEOBJECTS|DESKTOP_HOOKCONTROL);if(!d || !SetThreadDesktop(d)) {CloseHandle(h);return 6;}}
 expected_pid=pid;EnumWindows(candidate,0);if(window_count!=1) {CloseHandle(h);return 7;}
 DWORD vtable=base+0xba31f50,environment_vtable=base+0xba318e4,found=0,manager=0;
 unsigned char *buffer=malloc(65536+32);if(!buffer) {CloseHandle(h);return 8;}
 uintptr_t cursor=0;MEMORY_BASIC_INFORMATION region;ULONGLONG bytes=0,started=GetTickCount64();BOOL complete=TRUE;
 while(VirtualQueryEx(h,(LPCVOID)cursor,&region,sizeof(region))) {
  uintptr_t next=(uintptr_t)region.BaseAddress+region.RegionSize;if(next<=cursor)break;
  DWORD protection=region.Protect&255;
  if(region.State==MEM_COMMIT && region.Type==MEM_PRIVATE && !(region.Protect&PAGE_GUARD) && (protection==PAGE_READWRITE || protection==PAGE_WRITECOPY)) {
   for(SIZE_T offset=0;offset<region.RegionSize;offset+=65536) {
    if(bytes>=512ULL*1024*1024 || GetTickCount64()-started>15000) {complete=FALSE;goto done;}
    SIZE_T length=region.RegionSize-offset;if(length>65536+32)length=65536+32;SIZE_T got=0;
    if(!ReadProcessMemory(h,(unsigned char*)region.BaseAddress+offset,buffer,length,&got))continue;
    bytes+=got;
    for(SIZE_T i=0;i+32<=got && i<65536;i+=4) {
     DWORD *a=(DWORD*)(buffer+i);if(a[0]!=vtable || !a[1] || a[1]>1000000 || !a[2] || a[2]>1000000)continue;
     DWORD control=(DWORD)(uintptr_t)region.BaseAddress+(DWORD)offset+(DWORD)i,m=control+12,vt=0;
     if(a[3]!=m || a[4]!=control || !read(h,a[5],&vt,4) || vt!=environment_vtable || !owner(h,a[5],uid))continue;
     if(manager!=m) {manager=m;found++;}
    }
   }
  }
  cursor=next;
 }
done:
 SecureZeroMemory(buffer,65536+32);free(buffer);
 FILETIME after;DWORD exitcode=0;BOOL unchanged=GetProcessTimes(h,&after,&e,&k,&u) && CompareFileTime(&create,&after)==0 && GetExitCodeProcess(h,&exitcode) && exitcode==STILL_ACTIVE;
 printf("{\"ok\":%s,\"manager\":\"%lx\",\"manager_count\":%lu,\"hwnd\":\"%lx\",\"tid\":%lu,\"scanned_bytes\":%llu,\"scan_complete\":%s,\"identity_unchanged\":%s,\"account_matches\":%s,\"native_call_performed\":false}\n",complete && unchanged && found==1?"true":"false",manager,found,(DWORD)(uintptr_t)window,window_tid,bytes,complete?"true":"false",unchanged?"true":"false",found==1?"true":"false");
 CloseHandle(h);return complete && unchanged && found==1?0:1;
}
