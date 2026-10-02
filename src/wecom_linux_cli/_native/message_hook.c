/* Owner-authorized native text dispatch, pinned to the supported binary by Python. */
#include "message_hook.h"
static BOOL identity(Trial *t) {
 wchar_t path[512];DWORD length=512;FILETIME c,e,k,u;
 return GetCurrentProcessId()==t->pid && GetCurrentThreadId()==t->tid &&
 QueryFullProcessImageNameW(GetCurrentProcess(),0,path,&length) && !_wcsicmp(path,t->executable) &&
 GetProcessTimes(GetCurrentProcess(),&c,&e,&k,&u) && (((ULONGLONG)c.dwHighDateTime<<32)|c.dwLowDateTime)==t->creation;
}

typedef struct {unsigned char bytes[16];DWORD length,capacity;} String;
typedef struct {void *pointer,*control;} Shared;
typedef void *(__cdecl *Allocate)(unsigned);
typedef Shared *(__cdecl *Factory)(Shared*,const String*);
typedef void *(__thiscall *Constructor)(void*);
typedef String *(__thiscall *Assign)(void*,const char*,unsigned);
typedef void (__thiscall *Release)(Shared*);
typedef DWORD *(__thiscall *Send)(void*,DWORD*,const Shared*,const void*,const void*);
#ifndef WECOM_ENABLE_SEND
#define WECOM_ENABLE_SEND 0
#endif
static BOOL valid(void *address,unsigned length) {
 MEMORY_BASIC_INFORMATION m;
 return VirtualQuery(address,&m,sizeof(m))==sizeof(m) && m.State==MEM_COMMIT &&
 !(m.Protect&(PAGE_NOACCESS|PAGE_GUARD)) && (uintptr_t)address>= (uintptr_t)m.BaseAddress &&
 (uintptr_t)address+length<=(uintptr_t)m.BaseAddress+m.RegionSize;
}
static BOOL code_valid(unsigned char *base) {
 if (memcmp(base+0x8145200,(unsigned char[]){0x66,0x90,0x55,0x8b,0xec,0x6a,0xff,0x68},8))return FALSE;
 if (memcmp(base+0xa01edf4,(unsigned char[]){0x55,0x8b,0xec,0xeb,0x0d,0xff,0x75,0x08},8))return FALSE;
 if (memcmp(base+0x2693b50,(unsigned char[]){0x8b,0xd1,0x0f,0x57,0xc0,0x0f,0x11,0x02},8))return FALSE;
 if (memcmp(base+0x1f768a,(unsigned char[]){0x55,0x8b,0xec,0x51,0x56,0x8b,0xf1,0x57},8))return FALSE;
 if (memcmp(base+0x26c5a0,(unsigned char[]){0x56,0x8b,0x71,0x04,0x85,0xf6,0x74,0x25},8))return FALSE;
 return TRUE;
}
/* Resolve only the configured owner account, again on the native UI thread. */
static BOOL account_matches(unsigned char *env,ULONGLONG expected) {
 unsigned char *a,*b,*c;
 if(!expected || !valid(env,0x48))return FALSE;
 a=*(unsigned char**)(env+0x44);if(!valid(a,12))return FALSE;
 b=*(unsigned char**)(a+8);if(!valid(b,8))return FALSE;
 c=*(unsigned char**)(b+4);if(!valid(c,0x78))return FALSE;
 return *(ULONGLONG*)(c+0x70)==expected;
}
static void preflight(Trial *t) {
 unsigned char *base=(unsigned char*)GetModuleHandleW(NULL);
 if(!code_valid(base)) {t->failure=10;return;}
 #define ADDRESS(va) (base+((va)-0x400000))
 unsigned char *manager=(unsigned char*)(uintptr_t)t->manager;
 if(valid(manager,32) && *(DWORD*)manager==(DWORD)(uintptr_t)manager) {
  unsigned char *env=*(unsigned char**)(manager+8);
  unsigned char *control=*(unsigned char**)(manager+4);
  if(valid(control,12) && *(DWORD*)control==(DWORD)(uintptr_t)ADDRESS(0xbe31f50) &&
     *(DWORD*)(control+4)>0 && valid(env,0x48) &&
     *(DWORD*)env==(DWORD)(uintptr_t)ADDRESS(0xbe318e4) && account_matches(env,t->expected_self_id))t->manager_verified=1;
 }
 if(!t->manager_verified) {t->failure=11;return;}

 unsigned n=strnlen(t->text,TEXT_MAX);
 if(!n || n>=TEXT_MAX || !t->chat[0] || strnlen(t->chat,256)==256 ||
    (t->input_kind!=2 && t->input_kind!=7 && t->input_kind!=8 && t->input_kind!=29)) {t->failure=12;return;}
 Shared model={0},info={0};Shared *rich=NULL;
 Factory make;Allocate allocate;Constructor construct;Assign assign;Release release;
 void *ptr=ADDRESS(0x8545200);memcpy(&make,&ptr,4);
 ptr=ADDRESS(0xa41edf4);memcpy(&allocate,&ptr,4);
 ptr=ADDRESS(0x2a93b50);memcpy(&construct,&ptr,4);
 ptr=ADDRESS(0x5f768a);memcpy(&assign,&ptr,4);
 ptr=ADDRESS(0x66c5a0);memcpy(&release,&ptr,4);
 String text={0};text.length=n;
 if(n<=15) {memcpy(text.bytes,t->text,n);text.capacity=15;}
 else {memcpy(text.bytes,&(char*){t->text},4);text.capacity=n;}
 if(t->input_kind==2) {
  make(&model,&text);
  if(!valid(model.pointer,0x268) || !valid(model.control,12) || *(DWORD*)model.control!=(DWORD)(uintptr_t)ADDRESS(0xb365c90)) {t->failure=13;return;}
  t->model_constructed=1;
  unsigned char *m=(unsigned char*)model.pointer;t->message_type=*(DWORD*)(m+0x50);
  rich=(Shared*)(m+0x208);
  if(valid(rich->control,12) && valid(rich->pointer,32) && *(DWORD*)rich->pointer==(DWORD)(uintptr_t)ADDRESS(0xb372328))t->rich_present=1;
  String *content=(String*)(m+0x1b8);char *body=content->capacity>15?*(char**)content->bytes:(char*)content->bytes;
  if(content->length<TEXT_MAX && valid(body,content->length)) {t->rich_size=content->length;memcpy(t->serialized,body,content->length);}
 } else if(t->input_kind==29) {
  /* EmotionMessage is a 0x50 protobuf, with its own shared control block.
   * GUI local-GIF capture has all 14 presence bits set, source in field1,
   * dimensions in fields7/8 and both enum fields2/11 set to 2. */
  if(!t->width || !t->height || t->width>32768 || t->height>32768 ||
     (strncmp(t->text,"Z:\\",3) && strncmp(t->text,"C:\\",3))) {t->failure=12;return;}
  if(memcmp(ADDRESS(0x1e6b650),(unsigned char[]){0x66,0x90,0x55,0x8b,0xec,0x6a,0xff,0x68},8) ||
     memcmp(ADDRESS(0x802c00),(unsigned char[]){0x55,0x8b,0xec,0x6a,0xff,0x68,0x34,0xbf},8) ||
     memcmp(ADDRESS(0xa1900b0),(unsigned char[]){0x55,0x8b,0xec,0x6a,0xff,0x68,0x3e,0xa4},8) ||
     memcmp(ADDRESS(0x5f79e0),(unsigned char[]){0xe9,0xc2,0xff,0xff,0xff,0xcc,0xcc,0xcc},8)) {t->failure=18;return;}
  typedef void *(__thiscall *CopyString)(void*,const String*);
  typedef String *(__thiscall *Serialize)(void*,String*);
  typedef void (__thiscall *DestroyString)(String*);
  CopyString copy;Serialize serialize;DestroyString destroy;Constructor emotion_construct;
  ptr=ADDRESS(0x802c00);memcpy(&copy,&ptr,4);
  ptr=ADDRESS(0xa1900b0);memcpy(&serialize,&ptr,4);
  ptr=ADDRESS(0x5f79e0);memcpy(&destroy,&ptr,4);
  ptr=ADDRESS(0x1e6b650);memcpy(&emotion_construct,&ptr,4);
  DWORD *emotion_block=(DWORD*)allocate(0x60);if(!emotion_block) {t->failure=14;return;}
  memset(emotion_block,0,0x60);emotion_block[0]=(DWORD)(uintptr_t)ADDRESS(0xb965234);emotion_block[1]=1;emotion_block[2]=1;
  model.pointer=(unsigned char*)emotion_block+0x10;model.control=emotion_block;
  emotion_construct(model.pointer);t->model_constructed=1;rich=&model;
  unsigned char *emotion=(unsigned char*)model.pointer;
  if(*(DWORD*)emotion!=(DWORD)(uintptr_t)ADDRESS(0xb39dc14)) {t->failure=13;release(&model);t->model_released=1;return;}
  copy(emotion+0x10,&text);*(DWORD*)(emotion+0x8)=0x3fff;
  *(DWORD*)(emotion+0x40)=t->width;*(DWORD*)(emotion+0x44)=t->height;
  *(DWORD*)(emotion+0x48)=2;*(DWORD*)(emotion+0x4c)=2;
  t->message_type=29;t->rich_present=1;String encoded={0};
  serialize(emotion,&encoded);char *body=encoded.capacity>15?*(char**)encoded.bytes:(char*)encoded.bytes;
  if(encoded.length && encoded.length<TEXT_MAX && valid(body,encoded.length)) {t->rich_size=encoded.length;memcpy(t->serialized,body,encoded.length);}
  destroy(&encoded);
 } else {
  if((t->input_kind==7 && (!t->width || !t->height || t->width>32768 || t->height>32768)) ||
     (t->input_kind==8 && (!t->width || t->width>10*1024*1024 || t->height)) ||
     !t->filename[0] || strnlen(t->filename,1024)==1024 ||
     (strncmp(t->text,"Z:\\",3) && strncmp(t->text,"C:\\",3))) {t->failure=12;return;}
  if(memcmp(ADDRESS(0x1ae65a0),(unsigned char[]){0x66,0x90,0x55,0x8b,0xec,0x6a,0xff,0x68},8) ||
     memcmp(ADDRESS(0x802c00),(unsigned char[]){0x55,0x8b,0xec,0x6a,0xff,0x68,0x34,0xbf},8) ||
     memcmp(ADDRESS(0xa1900b0),(unsigned char[]){0x55,0x8b,0xec,0x6a,0xff,0x68,0x3e,0xa4},8) ||
     memcmp(ADDRESS(0x5f79e0),(unsigned char[]){0xe9,0xc2,0xff,0xff,0xff,0xcc,0xcc,0xcc},8)) {t->failure=18;return;}
  typedef void *(__thiscall *CopyString)(void*,const String*);
  typedef String *(__thiscall *Serialize)(void*,String*);
  typedef void (__thiscall *DestroyString)(String*);
  CopyString copy;Serialize serialize;DestroyString destroy;Constructor file_construct;
  ptr=ADDRESS(0x802c00);memcpy(&copy,&ptr,4);
  ptr=ADDRESS(0xa1900b0);memcpy(&serialize,&ptr,4);
  ptr=ADDRESS(0x5f79e0);memcpy(&destroy,&ptr,4);
  ptr=ADDRESS(0x1ae65a0);memcpy(&file_construct,&ptr,4);
  DWORD *file_block=(DWORD*)allocate(0xe0);if(!file_block) {t->failure=14;return;}
  memset(file_block,0,0xe0);file_block[0]=(DWORD)(uintptr_t)ADDRESS(0xb4047dc);file_block[1]=1;file_block[2]=1;
  model.pointer=(unsigned char*)file_block+0x10;model.control=file_block;
  file_construct(model.pointer);t->model_constructed=1;rich=&model;
  unsigned char *file=(unsigned char*)model.pointer;
  if(*(DWORD*)file!=(DWORD)(uintptr_t)ADDRESS(0xb3721e8)) {t->failure=13;release(&model);t->model_released=1;return;}
  String filename={0},encoded={0};unsigned size=(unsigned)strlen(t->filename);filename.length=size;
  if(size<=15){memcpy(filename.bytes,t->filename,size);filename.capacity=15;}
  else{memcpy(filename.bytes,&(char*){t->filename},4);filename.capacity=size;}
  copy(file+0x24,&filename);copy(file+0x80,&text);
  if(t->input_kind==7) {
   *(DWORD*)(file+0x14)=0x61000002;*(DWORD*)(file+0x98)=t->width;*(DWORD*)(file+0x9c)=t->height;
  } else {
   *(DWORD*)(file+0x14)=0x11000002;*(ULONGLONG*)(file+0x90)=t->width;
  }
  t->message_type=t->input_kind;t->rich_present=1;
  serialize(file,&encoded);char *body=encoded.capacity>15?*(char**)encoded.bytes:(char*)encoded.bytes;
  if(encoded.length && encoded.length<TEXT_MAX && valid(body,encoded.length)) {t->rich_size=encoded.length;memcpy(t->serialized,body,encoded.length);}
  destroy(&encoded);
 }
 if(t->message_type!=t->input_kind || !t->rich_present || !t->rich_size) {
  t->failure=15;release(&model);t->model_released=1;return;
 }
 DWORD *block=(DWORD*)allocate(0x138);
 if(!block) {t->failure=14;release(&model);t->model_released=1;return;}
 memset(block,0,0x138);block[0]=(DWORD)(uintptr_t)ADDRESS(0xb47ff54);block[1]=1;block[2]=1;
 info.pointer=(unsigned char*)block+0x10;info.control=block;
 construct(info.pointer);
 assign(info.pointer,t->chat,(unsigned)strlen(t->chat));
 *(DWORD*)((unsigned char*)info.pointer+0x18)=t->message_type;
 Shared *destination=(Shared*)((unsigned char*)info.pointer+0x1c);*destination=*rich;
 if(rich->control)InterlockedIncrement((LONG*)((unsigned char*)rich->control+4));
 t->info_constructed=1;
 if(t->message_type!=t->input_kind || !t->rich_present || !t->rich_size)t->failure=15;
 if(t->mode==2 && !t->failure) {
#if WECOM_ENABLE_SEND
  const unsigned char signature[8]={0x66,0x90,0x55,0x8b,0xec,0x6a,0xff,0x68};
  if(memcmp(ADDRESS(0x9a07990),signature,8))t->failure=16;
  else {Send send;void *entry=ADDRESS(0x9a07990);memcpy(&send,&entry,4);unsigned char progress[40]={0},callback[40]={0};
   InterlockedExchange((LONG*)&t->send_entered,1);
   send(manager,t->ids,&info,progress,callback);t->returned=1;
   if(t->input_kind==7 || t->input_kind==8 || t->input_kind==29) {
    t->info_references=*(DWORD*)((unsigned char*)info.control+4);
    t->rich_references=*(DWORD*)((unsigned char*)model.control+4);
    /* Native async owners hold the attachment after these temporary references
     * are dropped. Otherwise retain the two small handles until client exit. */
    if(t->info_references<=1 && t->rich_references<=2) {t->handles_retained=1;return;}
   }
  }
#else
  t->failure=17;
#endif
 }
 release(&info);t->info_released=1;
 release(&model);t->model_released=1;
}

__declspec(dllexport) LRESULT CALLBACK wecom_hook(int code,WPARAM wparam,LPARAM lparam) {
 if (code>=0 && lparam) {
  CWPSTRUCT *m=(CWPSTRUCT*)lparam;
  if(m->message==RegisterWindowMessageW(MESSAGE_NAME) && m->wParam && !m->lParam) {
   wchar_t name[80];map_name(name,(DWORD)m->wParam);
   HANDLE h=OpenFileMappingW(FILE_MAP_ALL_ACCESS,FALSE,name);
   Trial *t=h?MapViewOfFile(h,FILE_MAP_ALL_ACCESS,0,0,sizeof(Trial)):NULL;
   if(t && t->magic==MAGIC && t->nonce==(DWORD)m->wParam && identity(t) && InterlockedCompareExchange(&t->state,1,0)==0) {
    HMODULE pinned=NULL;
    if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,(LPCWSTR)(uintptr_t)&wecom_hook,&pinned))t->failure=1;
    else {
     t->callback_pid=GetCurrentProcessId();t->callback_tid=GetCurrentThreadId();
     if(t->mode==1 || t->mode==2)preflight(t);else if(t->mode!=0)t->failure=2;
    }
    InterlockedExchange(&t->state,2);
   }
   if(t)UnmapViewOfFile(t);
   if(h)CloseHandle(h);
  }
 }
 return CallNextHookEx(NULL,code,wparam,lparam);
}
BOOL WINAPI DllMain(HINSTANCE h,DWORD why,LPVOID unused) {(void)unused;if(why==DLL_PROCESS_ATTACH)DisableThreadLibraryCalls(h);return TRUE;}
