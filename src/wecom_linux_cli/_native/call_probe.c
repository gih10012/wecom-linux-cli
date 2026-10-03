/* Read only the exact requested chat's typed UI model. Never call native code. */
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
static BOOL read_bytes(HANDLE p,DWORD address,void *out,unsigned size) {
 SIZE_T got=0;return address&&ReadProcessMemory(p,(LPCVOID)(uintptr_t)address,out,size,&got)&&got==size;
}
static BOOL exact_chat(HANDLE p,DWORD view,DWORD base,const char *chat,DWORD *context) {
 DWORD head[12],again[12],ctx[3],string[6],after[6];char body[256]={0};unsigned length=(unsigned)strlen(chat);
 if(!read_bytes(p,view,head,sizeof(head))||head[0]!=base+0xb547fd0||head[4]!=base+0xb547fe0||!head[2])return FALSE;
 if(!read_bytes(p,head[2],ctx,sizeof(ctx))||!ctx[1]||!read_bytes(p,ctx[1],string,sizeof(string)))return FALSE;
 if(string[4]!=length||string[5]<length||string[5]>1048576)return FALSE;
 if(string[5]<=15){if(string[5]!=15||length>15)return FALSE;memcpy(body,string,length);}
 else if(!read_bytes(p,string[0],body,length+1))return FALSE;
 if(memcmp(body,chat,length)||body[length])return FALSE;
 if(!read_bytes(p,view,again,sizeof(again))||memcmp(head,again,sizeof(head))||
    !read_bytes(p,ctx[1],after,sizeof(after))||memcmp(string,after,sizeof(string)))return FALSE;
 *context=head[2];return TRUE;
}
static HANDLE owner_process;static DWORD owner_pid,main_window;
static BOOL CALLBACK window_item(HWND h,LPARAM unused) {
 (void)unused;DWORD pid=0,tid=GetWindowThreadProcessId(h,&pid);WCHAR cls[128]={0},title[128]={0};
 if(pid!=owner_pid||!IsWindowVisible(h)||(DWORD)(uintptr_t)h==main_window||!GetClassNameW(h,cls,128))return TRUE;
 BOOL voice=!wcscmp(cls,L"WXworkWindow - 语音通话")&&GetWindowTextW(h,title,128)&&!wcscmp(title,L"语音通话");
 if(!voice&&wcscmp(cls,L"WXworkWindow"))return TRUE;
 if(!voice&&GetWindowTextW(h,title,128))return TRUE;
 DWORD root=(DWORD)(uintptr_t)GetWindowLongPtrW(h,GWLP_USERDATA),head[2]={0},col=0,meta[5]={0};
 if(!read_bytes(owner_process,root,head,sizeof(head))||head[1]!=(DWORD)(uintptr_t)h||!read_bytes(owner_process,head[0]-4,&col,4)||!read_bytes(owner_process,col,meta,sizeof(meta))||meta[0]||meta[1])return TRUE;
 printf("{\"kind\":\"%s\",\"hwnd\":\"%lx\",\"tid\":%lu,\"root\":\"%lx\"}\n",voice?"voice":"possible_invitation",(DWORD)(uintptr_t)h,tid,root);
 return TRUE;
}
int wmain(int argc,wchar_t **argv) {
 if(argc!=6)return 2;
 DWORD pid=wcstoul(argv[1],NULL,10);ULONGLONG wanted=_wcstoui64(argv[2],NULL,10);
 char chat[256]={0};if(!WideCharToMultiByte(CP_UTF8,0,argv[4],-1,chat,sizeof(chat),NULL,NULL)||!chat[0])return 2;
 HANDLE p=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pid);if(!p)return 3;
 WCHAR path[1024]={0};DWORD n=1024;FILETIME created,a,b,c;BOOL traced=TRUE;
 if(!QueryFullProcessImageNameW(p,0,path,&n)||_wcsicmp(path,argv[3])||!GetProcessTimes(p,&created,&a,&b,&c)||
    (((ULONGLONG)created.dwHighDateTime<<32)|created.dwLowDateTime)!=wanted||!CheckRemoteDebuggerPresent(p,&traced)||traced)return 4;
 HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pid);MODULEENTRY32W module={0};module.dwSize=sizeof(module);
 if(snap==INVALID_HANDLE_VALUE||!Module32FirstW(snap,&module))return 5;
 DWORD base=(DWORD)(uintptr_t)module.modBaseAddr;CloseHandle(snap);
 unsigned char prologue[12],expected[]={0x66,0x90,0x55,0x8b,0xec,0x6a,0xff,0x68,0x63,0x4f,0xad,0x0a};
 /* Absolute SEH immediate is relocated. Verify the stable first eight bytes. */
 if(!read_bytes(p,base+0x5a25690,prologue,sizeof(prologue))||memcmp(prologue,expected,8))return 6;
 DWORD vt[2];if(!read_bytes(p,base+0xb547fd0,vt,sizeof(vt))||vt[0]!=base+0x5a1e640||vt[1]!=base+0x5a3f9c0)return 7;
 WCHAR desktop[128]={0};DWORD length=GetEnvironmentVariableW(L"WECOM_CLI_DESKTOP",desktop,128);
 if(length>=128)return 9;
 if(length){HDESK desk=OpenDesktopW(desktop,0,FALSE,DESKTOP_ENUMERATE|DESKTOP_READOBJECTS);if(!desk||!SetThreadDesktop(desk))return 9;}
 owner_process=p;owner_pid=pid;main_window=wcstoul(argv[5],NULL,16);EnumWindows(window_item,0);
 if(!strcmp(chat,"-")){
  FILETIME after;DWORD exitcode=0;BOOL unchanged=GetProcessTimes(p,&after,&a,&b,&c)&&CompareFileTime(&created,&after)==0&&GetExitCodeProcess(p,&exitcode)&&exitcode==STILL_ACTIVE;
  CloseHandle(p);printf("{\"read_only\":true,\"identity_unchanged\":%s}\n",unchanged?"true":"false");return unchanged?0:1;
 }
 unsigned char *buffer=malloc(65536+48);if(!buffer)return 8;
 uintptr_t cursor=0;MEMORY_BASIC_INFORMATION region;ULONGLONG bytes=0,started=GetTickCount64();BOOL complete=TRUE;
 DWORD matched=0,typed=0;
 while(VirtualQueryEx(p,(LPCVOID)cursor,&region,sizeof(region))) {
  uintptr_t next=(uintptr_t)region.BaseAddress+region.RegionSize;if(next<=cursor)break;
  DWORD protection=region.Protect&255;
  if(region.State==MEM_COMMIT&&region.Type==MEM_PRIVATE&&!(region.Protect&PAGE_GUARD)&&
     (protection==PAGE_READWRITE||protection==PAGE_WRITECOPY)) {
   for(SIZE_T offset=0;offset<region.RegionSize;offset+=65536) {
    if(bytes>=512ULL*1024*1024||GetTickCount64()-started>10000){complete=FALSE;goto done;}
    SIZE_T size=region.RegionSize-offset;if(size>65536+48)size=65536+48;SIZE_T got=0;
    if(!ReadProcessMemory(p,(unsigned char*)region.BaseAddress+offset,buffer,size,&got))continue;
    bytes+=got;
    for(SIZE_T i=0;i+48<=got&&i<65536;i+=4) {
     DWORD *head=(DWORD*)(buffer+i);if(head[0]!=base+0xb547fd0||head[4]!=base+0xb547fe0)continue;
     typed++;DWORD view=(DWORD)(uintptr_t)region.BaseAddress+(DWORD)offset+(DWORD)i,context=0;
     if(exact_chat(p,view,base,chat,&context)){matched++;printf("{\"view\":\"%lx\",\"context\":\"%lx\",\"exact_requested_chat_matches\":true}\n",view,context);}
    }
   }
  }
  cursor=next;
 }
done:
 SecureZeroMemory(buffer,65536+48);free(buffer);
 FILETIME after;DWORD exitcode=0;BOOL unchanged=GetProcessTimes(p,&after,&a,&b,&c)&&CompareFileTime(&created,&after)==0&&GetExitCodeProcess(p,&exitcode)&&exitcode==STILL_ACTIVE;
 printf("{\"read_only\":true,\"native_call_performed\":false,\"typed_views\":%lu,\"matching_views\":%lu,\"scan_complete\":%s,\"scanned_bytes\":%llu,\"identity_unchanged\":%s,\"snapshot_atomic\":false}\n",typed,matched,complete?"true":"false",bytes,unchanged?"true":"false");
 CloseHandle(p);return complete&&unchanged?0:1;
}
