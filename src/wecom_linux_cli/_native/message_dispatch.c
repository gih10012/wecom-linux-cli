#include "message_hook.h"

/* The mapped state remains held by an executing callback after a timeout.
 * Its DLL pins itself before calling native code. Never unload/terminate the
 * client's thread, or interpret an incomplete callback as permission to retry. */
int wmain(int argc,wchar_t **argv) {
 if(argc!=13)return 2;
 DWORD pid=wcstoul(argv[2],NULL,10),tid=wcstoul(argv[4],NULL,10);
 DWORD nonce=wcstoul(argv[7],NULL,16),mode=wcstoul(argv[8],NULL,10);
 ULONGLONG expected=_wcstoui64(argv[3],NULL,10);
 HWND hwnd=(HWND)(uintptr_t)wcstoul(argv[5],NULL,16);
 HANDLE process=NULL,mapping=NULL;HDESK desk=NULL;HMODULE dll=NULL;
 Trial *t=NULL;HHOOK hook=NULL;int result=1;
 BOOL delivered=FALSE,removed=FALSE,alive=FALSE,traced=TRUE;
 DWORD error=0,wpid=0,n=512,exitcode=0;
 FILETIME c,e,k,u;wchar_t path[512],desktop[128]={0},name[80];
 FILE *input=NULL,*output=NULL;
 if(!pid || !tid || !nonce || (mode!=1 && mode!=2))return 2;
 process=OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,pid);
 if(!process)goto cleanup;
 if(!QueryFullProcessImageNameW(process,0,path,&n) || _wcsicmp(path,argv[1]) ||
    !GetProcessTimes(process,&c,&e,&k,&u) ||
    (((ULONGLONG)c.dwHighDateTime<<32)|c.dwLowDateTime)!=expected ||
    !CheckRemoteDebuggerPresent(process,&traced) || traced ||
    GetWindowThreadProcessId(hwnd,&wpid)!=tid || wpid!=pid)goto cleanup;
 DWORD length=GetEnvironmentVariableW(L"WECOM_CLI_DESKTOP",desktop,128);
 if(length>=128)goto cleanup;
 if(length) {
  desk=OpenDesktopW(desktop,0,FALSE,DESKTOP_ENUMERATE|DESKTOP_READOBJECTS|DESKTOP_WRITEOBJECTS|DESKTOP_HOOKCONTROL);
  if(!desk || !SetThreadDesktop(desk))goto cleanup;
 }
 map_name(name,nonce);
 mapping=CreateFileMappingW(INVALID_HANDLE_VALUE,NULL,PAGE_READWRITE,0,sizeof(Trial),name);
 if(!mapping || GetLastError()==ERROR_ALREADY_EXISTS)goto cleanup;
 t=MapViewOfFile(mapping,FILE_MAP_ALL_ACCESS,0,0,sizeof(Trial));
 if(!t)goto cleanup;
 memset(t,0,sizeof(*t));t->magic=MAGIC;t->pid=pid;t->tid=tid;t->nonce=nonce;
 t->creation=expected;t->mode=mode;t->expected_self_id=_wcstoui64(argv[12],NULL,10);
 wcsncpy(t->executable,path,511);
 input=_wfopen(argv[9],L"rb");if(!input)goto cleanup;
 if(fread(t->chat,1,256,input)!=256 || fread(t->text,1,TEXT_MAX,input)!=TEXT_MAX || fgetc(input)!=EOF)goto cleanup;
 fclose(input);input=NULL;t->manager=wcstoul(argv[10],NULL,16);
 dll=LoadLibraryW(argv[6]);FARPROC proc=dll?GetProcAddress(dll,"wecom_hook"):NULL;
 HOOKPROC callback=NULL;memcpy(&callback,&proc,sizeof(callback));
 hook=callback?SetWindowsHookExW(WH_CALLWNDPROC,callback,dll,tid):NULL;
 if(!hook)goto cleanup;
 DWORD_PTR response=0;
 SetLastError(0);
 delivered=SendMessageTimeoutW(hwnd,RegisterWindowMessageW(MESSAGE_NAME),nonce,0,
                             SMTO_ABORTIFHUNG|SMTO_BLOCK,10000,&response)!=0;
 error=GetLastError();
 removed=UnhookWindowsHookEx(hook);hook=NULL;
 alive=GetExitCodeProcess(process,&exitcode) && exitcode==STILL_ACTIVE &&
       CheckRemoteDebuggerPresent(process,&traced) && !traced;
 if(t->state==2 && t->rich_size<TEXT_MAX) {
  output=_wfopen(argv[11],L"wb");
  if(output) {fwrite(t->serialized,1,t->rich_size,output);fclose(output);output=NULL;}
 }
 if(delivered && removed && t->state==2 && !t->failure && alive)result=0;
cleanup:
 if(hook)removed=UnhookWindowsHookEx(hook);
 if(result==0)error=0;
 else if(!error)error=GetLastError();
 printf("{\"ok\":%s,\"delivered\":%s,\"hook_removed\":%s,\"state\":%ld,\"failure\":%lu,\"win32_error\":%lu,\"client_running_untraced\":%s,\"native_send_entered\":%s,\"send_returned\":%s,\"model_constructed\":%lu,\"info_constructed\":%lu,\"model_released\":%lu,\"info_released\":%lu,\"manager_verified\":%lu,\"rich_size\":%lu,\"ids\":[%lu,%lu,%lu,%lu]}\n",
 result==0?"true":"false",delivered?"true":"false",removed?"true":"false",
 t?t->state:0,t?t->failure:0,error,alive?"true":"false",
 t&&t->send_entered?"true":"false",t&&t->returned?"true":"false",
 t?t->model_constructed:0,t?t->info_constructed:0,t?t->model_released:0,t?t->info_released:0,
 t?t->manager_verified:0,t?t->rich_size:0,t?t->ids[0]:0,t?t->ids[1]:0,t?t->ids[2]:0,t?t->ids[3]:0);
 if(input)fclose(input);
 if(output)fclose(output);
 if(dll)FreeLibrary(dll);
 if(t)UnmapViewOfFile(t);
 if(mapping)CloseHandle(mapping);
 if(process)CloseHandle(process);
 /* SetThreadDesktop makes this handle current: the helper's normal exit
  * releases it. Closing a current desktop handle is invalid on Windows. */
 return result;
}
