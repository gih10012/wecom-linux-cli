/* Version-bound normal UI voice controls, executed on the verified owner UI thread.
 * Operations: 0 inspect/hangup, 1 answer, 2 private-call start,
 * 3 cancel an exact normal member picker, 4 local CRT warmup,
 * 5 toggle one exact local member checkbox, 6 open an exact group picker.
 * No private VoIP-engine ABI, fixed coordinates, or native message submission. */
#include "message_hook.h"
#include "selection_snapshot.h"
static BOOL valid(void *address,unsigned length) {
 MEMORY_BASIC_INFORMATION m;uintptr_t p=(uintptr_t)address;
 return p&&VirtualQuery(address,&m,sizeof(m))==sizeof(m)&&m.State==MEM_COMMIT&&
  !(m.Protect&(PAGE_NOACCESS|PAGE_GUARD))&&p>=(uintptr_t)m.BaseAddress&&p+length>=p&&p+length<=(uintptr_t)m.BaseAddress+m.RegionSize;
}
static int selection_read(uint32_t address,void *out,unsigned length) {
 if(!valid((void*)(uintptr_t)address,length))return 0;
 memcpy(out,(void*)(uintptr_t)address,length);return 1;
}
static DWORD *type_locator(void *control) {
 if(!valid(control,0x130))return NULL;
 DWORD *table=*(DWORD**)control;uintptr_t p=(uintptr_t)table;
 if(p<4||(p&3)||!valid((void*)(p-4),4))return NULL;
 DWORD *locator=(DWORD*)(uintptr_t)table[-1];
 if(!valid(locator,20)||locator[0]!=0||locator[1]>4096||locator[2]!=0)return NULL;
 return locator;
}
static BOOL complete_type_is(void *object,const char *wanted) {
 DWORD *locator=type_locator(object);if(!locator||locator[1])return FALSE;
 char *name=(char*)(uintptr_t)(locator[3]+8);
 return valid(name,128)&&strnlen(name,128)<128&&!strcmp(name,wanted);
}
static BOOL type_has(void *control,const char *wanted) {
 DWORD *locator=type_locator(control);if(!locator)return FALSE;
 DWORD *hierarchy=(DWORD*)(uintptr_t)locator[4];
 if(!valid(hierarchy,16)||!hierarchy[2]||hierarchy[2]>128)return FALSE;
 DWORD *bases=(DWORD*)(uintptr_t)hierarchy[3];if(!valid(bases,hierarchy[2]*4))return FALSE;
 for(DWORD i=0;i<hierarchy[2];i++) {
  DWORD *b=(DWORD*)(uintptr_t)bases[i];if(!valid(b,24))return FALSE;
  char *name=(char*)(uintptr_t)(b[0]+8);if(!valid(name,128)||strnlen(name,128)==128)return FALSE;
  /* A CControlUI interface can be a nonvirtual base at a nonzero offset.
   * Match its PMD to this vtable's complete-object locator; do not accept
   * virtual inheritance or an unrelated base from the same hierarchy. */
  if(b[2]==locator[1]&&b[3]==0xffffffff&&b[4]==0&&!strcmp(name,wanted))return TRUE;
 }
 return FALSE;
}
static BOOL control_matches(void *c){return type_has(c,".?AVCContainerUI@DuiLib@@")&&type_has(c,".?AVCControlUI@DuiLib@@");}
typedef void* (__thiscall *PointerGetter)(void*);
typedef int (__thiscall *CountGetter)(void*);
typedef void* (__thiscall *ItemGetter)(void*,int);
typedef const WCHAR* (__thiscall *StringGetter)(void*);
typedef unsigned char (__thiscall *BooleanGetter)(void*);
static PointerGetter tree_parent,tree_paint,tree_pos;
static CountGetter tree_count;static ItemGetter tree_item;
static StringGetter string_data;static BooleanGetter tree_visible;
static PointerGetter checkbox_data;static BooleanGetter checkbox_selected;
static BOOL reading_selector;
static void *requested_checkbox;static unsigned requested_checkbox_count;
static Trial *trial;static HWND tree_window;static unsigned nodes;static size_t used;static BOOL complete;static RECT viewport;
static void *hang_outer,*hang_inner;static unsigned outer_count,inner_count;static int button_kind;static void *answer_button;static unsigned answer_count;static int answer_kind;static void *inviter_name,*invite_tips;static unsigned inviter_count,tips_count,reject_count;
static void *cancel_button,*selector_title;static unsigned cancel_count,selector_title_count,cancel_caption_count;
static BOOL named(void *node,const WCHAR *expected) {
 const WCHAR *n=string_data((unsigned char*)node+0x78);size_t len=wcslen(expected);
 return valid((void*)n,(unsigned)(len+1)*2)&&!memcmp(n,expected,(len+1)*2);
}
static BOOL below(void *node,void *ancestor) {
 for(unsigned i=0;i<30&&node;i++){if(node==ancestor)return TRUE;node=tree_parent(node);}
 return FALSE;
}

static void append_string(const WCHAR *value) {
 char utf8[1500]={0};
 if(value) {unsigned n=0;while(n<180&&valid((void*)(value+n),2)&&value[n])n++;
  if(n<180)WideCharToMultiByte(CP_UTF8,0,value,(int)n,utf8,sizeof(utf8)-1,NULL,NULL);
 }
 if(used+4>=CARD_MAX){complete=FALSE;return;}
 trial->serialized[used++]='"';
 for(unsigned char *p=(unsigned char*)utf8;*p&&used+8<CARD_MAX;p++) {
  if(*p=='"'||*p=='\\')trial->serialized[used++]='\\';
  if(*p<32)used+=(size_t)snprintf(trial->serialized+used,CARD_MAX-used,"\\u%04x",*p);
  else trial->serialized[used++]=(char)*p;
 }
 trial->serialized[used++]='"';trial->serialized[used]=0;
}
static void walk(void *control,void *parent,unsigned depth) {
 /* A selector node adds a third bounded string for its native metadata. */
 if(depth>30||nodes>=1000||used+4500>=CARD_MAX){complete=FALSE;return;}
 if(!type_has(control,".?AVCControlUI@DuiLib@@")||tree_parent(control)!=parent||tree_paint(control)!=tree_window){complete=FALSE;return;}
 nodes++;
 if(!tree_visible(control))return;
 if(named(control,L"inviter_name")){inviter_name=control;inviter_count++;}
 if(named(control,L"single_voip_tips")){invite_tips=control;tips_count++;}
 if(named(control,L"reject_btn"))reject_count++;
 if(named(control,L"selectedtitle")){selector_title=control;selector_title_count++;}
 if(named(control,L"cancelbtn")&&complete_type_is(control,".?AVWButton@ui@wework@@")&&type_has(control,".?AVCButtonLayoutUI@DuiLib@@")){cancel_button=control;cancel_count++;}
 if(cancel_button&&named(control,L"ww_btn_text")&&below(control,cancel_button)) {
  const WCHAR *caption=string_data((unsigned char*)control+0x11c);
  if(valid((void*)caption,sizeof(L"取消"))&&!memcmp(caption,L"取消",sizeof(L"取消")))cancel_caption_count++;
 }

 if(named(control,L"accept_btn")) {
  if(type_has(control,".?AVCButtonUI@DuiLib@@")){answer_button=control;answer_count++;answer_kind=1;}
  else if(type_has(control,".?AVCButtonLayoutUI@DuiLib@@")){answer_button=control;answer_count++;answer_kind=2;}
 }
 if(named(control,L"hang_up_btn")){hang_outer=control;outer_count++;}
 if(hang_outer&&named(control,L"main_btn")&&below(control,hang_outer)) {
  if(type_has(control,".?AVCButtonUI@DuiLib@@")){hang_inner=control;inner_count++;button_kind=1;}
  else if(type_has(control,".?AVCButtonLayoutUI@DuiLib@@")){hang_inner=control;inner_count++;button_kind=2;}
 }

 RECT *bound=(RECT*)tree_pos(control);if(!valid(bound,sizeof(*bound))){complete=FALSE;return;}
 if(bound->right>bound->left&&bound->bottom>bound->top&&(bound->right<=0||bound->bottom<=0||bound->left>=viewport.right||bound->top>=viewport.bottom))return;
 {
  RECT *r=(RECT*)tree_pos(control);if(!valid(r,sizeof(*r))){complete=FALSE;return;}
  used+=(size_t)snprintf(trial->serialized+used,CARD_MAX-used,"%s{\"pointer\":\"%lx\",\"parent\":\"%lx\",\"depth\":%u,\"rect\":[%ld,%ld,%ld,%ld],\"name\":",used>10?",":"",(DWORD)(uintptr_t)control,(DWORD)(uintptr_t)parent,depth,r->left,r->top,r->right,r->bottom);
  append_string(string_data((unsigned char*)control+0x78));
  used+=(size_t)snprintf(trial->serialized+used,CARD_MAX-used,",\"text\":");append_string(string_data((unsigned char*)control+0x11c));
  if(reading_selector&&complete_type_is(control,".?AVWCheckbox@ui@wework@@")&&type_has(control,".?AVCOptionUI@DuiLib@@")) {
   if(!valid(control,0x3b2)){complete=FALSE;return;}
   const WCHAR *data=string_data(checkbox_data(control));unsigned length=0;
   while(length<180&&valid((void*)(data+length),2)&&data[length])length++;
   if(length==180||!valid((void*)(data+length),2)){complete=FALSE;return;}
   used+=(size_t)snprintf(trial->serialized+used,CARD_MAX-used,",\"control_type\":\"WCheckbox\",\"user_data\":");append_string(data);
   used+=(size_t)snprintf(trial->serialized+used,CARD_MAX-used,",\"self_selected\":%s",checkbox_selected(control)?"true":"false");
   if(trial->input_kind==5&&trial->payload_size>=18) {
    DWORD wanted=0;memcpy(&wanted,trial->payload+4,4);
    if(wanted==(DWORD)(uintptr_t)control){requested_checkbox=control;requested_checkbox_count++;}
   }
  }
  used+=(size_t)snprintf(trial->serialized+used,CARD_MAX-used,"}");
 }
 if(control_matches(control)) {
  int count=tree_count(control);if(count<0||count>1000){complete=FALSE;return;}
  for(int i=0;i<count&&complete;i++)walk(tree_item(control,i),control,depth+1);
 }
}
static BOOL identity(Trial *t) {
 WCHAR exe[512];DWORD n=512;FILETIME a,b,c,d;
 return GetCurrentProcessId()==t->pid&&GetCurrentThreadId()==t->tid&&
  QueryFullProcessImageNameW(GetCurrentProcess(),0,exe,&n)&&!_wcsicmp(exe,t->executable)&&
  GetProcessTimes(GetCurrentProcess(),&a,&b,&c,&d)&&(((ULONGLONG)a.dwHighDateTime<<32)|a.dwLowDateTime)==t->creation;
}
static BOOL account_matches(unsigned char *env,ULONGLONG expected) {
 unsigned char *a,*b,*c;if(!expected||!valid(env,0x48))return FALSE;
 a=*(unsigned char**)(env+0x44);if(!valid(a,12))return FALSE;
 b=*(unsigned char**)(a+8);if(!valid(b,8))return FALSE;
 c=*(unsigned char**)(b+4);return valid(c,0x78)&&*(ULONGLONG*)(c+0x70)==expected;
}
static BOOL view_matches(Trial *t,unsigned char *base) {
 DWORD *view=(DWORD*)(uintptr_t)t->width;
 if(!valid(view,48)||view[0]!=(DWORD)(uintptr_t)(base+0xb547fd0)||view[4]!=(DWORD)(uintptr_t)(base+0xb547fe0))return FALSE;
 DWORD *ctx=(DWORD*)(uintptr_t)view[2];if(!valid(ctx,12))return FALSE;
 DWORD *string=(DWORD*)(uintptr_t)ctx[1];if(!valid(string,24))return FALSE;
 unsigned n=(unsigned)strnlen(t->chat,256);if(!n||n>=256||string[4]!=n||string[5]<n||string[5]>1048576)return FALSE;
 char *body=string[5]>15?(char*)(uintptr_t)string[0]:(char*)string;
 return valid(body,n+1)&&!memcmp(body,t->chat,n)&&!body[n];
}
static BOOL group_id(const char *value) {
 unsigned n=(unsigned)strnlen(value,128);
 if(n<3||n>22||value[0]!='R'||value[1]!=':')return FALSE;
 for(unsigned i=2;i<n;i++)if(value[i]<'0'||value[i]>'9')return FALSE;
 return TRUE;
}
static BOOL read_group_string(void *frame,unsigned offset,char out[128]) {
 DWORD before[6],after[6];unsigned char *field=(unsigned char*)frame+offset;
 if(!valid(field,sizeof(before)))return FALSE;
 memcpy(before,field,sizeof(before));unsigned n=before[4],capacity=before[5];
 if(n>=128||capacity<n||capacity>1048576)return FALSE;
 const char *body=capacity==15?(const char*)field:(const char*)(uintptr_t)before[0];
 if(capacity<15||!valid((void*)body,n+1)||body[n])return FALSE;
 memcpy(out,body,n+1);memcpy(after,field,sizeof(after));
 return !memcmp(before,after,sizeof(before))&&group_id(out);
}
static BOOL CALLBACK visible_voice(HWND h,LPARAM flag) {
 DWORD pid=0;GetWindowThreadProcessId(h,&pid);WCHAR cls[128]={0},title[128]={0};
 if(pid!=GetCurrentProcessId()||!IsWindowVisible(h)||!GetClassNameW(h,cls,128))return TRUE;
 if(!wcscmp(cls,L"WXworkWindow - 语音通话")&&GetWindowTextW(h,title,128)&&!wcscmp(title,L"语音通话"))*(BOOL*)flag=TRUE;
 if(!wcscmp(cls,L"weWorkSelectUser")) {
  void *root=(void*)(uintptr_t)GetWindowLongPtrW(h,GWLP_USERDATA);
  if(complete_type_is(root,".?AVCSelectUserFrame@ui@wework@@")||complete_type_is(root,".?AVCSelectUserFrame2@ui@wework@@"))*(BOOL*)flag=TRUE;
 }
 return TRUE;
}
static void verify(Trial *t) {
 if((t->mode!=1&&t->mode!=2)||t->input_kind>6){t->failure=80;return;}
 unsigned char *base=(unsigned char*)GetModuleHandleW(NULL);
 const unsigned char prologue[]={0x66,0x90,0x55,0x8b,0xec,0x6a,0xff,0x68};
 if(memcmp(base+0x5a25690,prologue,sizeof(prologue))){t->failure=81;return;}
 unsigned char *manager=(unsigned char*)(uintptr_t)t->manager;
 if(!valid(manager,32)||*(DWORD*)manager!=(DWORD)(uintptr_t)manager){t->failure=82;return;}
 unsigned char *manager_control=*(unsigned char**)(manager+4),*env=*(unsigned char**)(manager+8);
 if(!valid(manager_control,12)||*(DWORD*)manager_control!=(DWORD)(uintptr_t)(base+0xba31f50)||!valid(env,0x48)||
    *(DWORD*)env!=(DWORD)(uintptr_t)(base+0xba318e4)||!account_matches(env,t->expected_self_id)){t->failure=83;return;}
 t->manager_verified=1;
 if((t->input_kind==2||t->input_kind==6)&&!view_matches(t,base)){t->failure=84;return;}
 if(t->input_kind==6&&!group_id(t->chat)){t->failure=117;return;}
 if(t->input_kind==4) {
  if(t->mode!=1){t->failure=103;return;}
  unsigned char *owl=(unsigned char*)GetModuleHandleW(L"owl.dll");
  unsigned char signature[]={0x8b,0xff,0x55,0x8b,0xec,0x51,0x53,0x56,0x57,0x8b,0x7d,0x08};
  if(!owl||memcmp(owl+0x7b39a,signature,sizeof(signature))){t->failure=104;return;}
  typedef HMODULE (__cdecl *ResolveSystemDll)(const DWORD*,const DWORD*);
  ResolveSystemDll resolve=NULL;void *entry=owl+0x7b39a;memcpy(&resolve,&entry,sizeof(entry));
  unsigned loaded=0;for(DWORD i=0;i<19;i++){DWORD index=i;if(resolve(&index,&index+1))loaded++;}
  t->rich_size=(DWORD)snprintf(t->serialized,CARD_MAX,"{\"system_modules_resolved\":%u,\"voice_call_performed\":false}",loaded);t->returned=1;return;
 }

 HMODULE dui=GetModuleHandleW(L"DuiLib.dll");
 if(!dui){t->failure=86;return;}
 typedef void* (__thiscall *PointerGetter)(void*);
 PointerGetter get_manager=NULL,get_parent=NULL,get_paint=NULL,get_pos=NULL;
 FARPROC address=GetProcAddress(dui,"?GetManager@CControlUI@DuiLib@@UBEPAVCPaintManagerUI@2@XZ");memcpy(&get_manager,&address,sizeof(address));
 address=GetProcAddress(dui,"?GetParent@CControlUI@DuiLib@@UBEPAV12@XZ");memcpy(&get_parent,&address,sizeof(address));
 address=GetProcAddress(dui,"?GetPaintWindow@CControlUI@DuiLib@@UBEPAUHWND__@@XZ");memcpy(&get_paint,&address,sizeof(address));
 address=GetProcAddress(dui,"?GetPos@CControlUI@DuiLib@@UBEABUtagRECT@@XZ");memcpy(&get_pos,&address,sizeof(address));
 unsigned char expected[]={0x8b,0x41,0x4c,0xc3};
 if(!get_manager||!get_parent||!get_paint||!get_pos||memcmp((void*)get_manager,expected,sizeof(expected))){t->failure=87;return;}
 void *ui_manager=NULL;HWND paint=NULL;BOOL selector_window=FALSE;
 PointerGetter get_root=NULL;
 FARPROC root_fn=GetProcAddress(dui,"?GetRoot@CPaintManagerUI@DuiLib@@QBEPAVCControlUI@2@XZ");memcpy(&get_root,&root_fn,sizeof(root_fn));
 root_fn=GetProcAddress(dui,"?DUISpiderGetCount@CContainerUI@DuiLib@@QBEHXZ");memcpy(&tree_count,&root_fn,sizeof(root_fn));
 root_fn=GetProcAddress(dui,"?DUISpiderGetItemAt@CContainerUI@DuiLib@@QBEPAVCControlUI@2@H@Z");memcpy(&tree_item,&root_fn,sizeof(root_fn));
 root_fn=GetProcAddress(dui,"?GetData@CDuiString@DuiLib@@QBEPB_WXZ");memcpy(&string_data,&root_fn,sizeof(root_fn));
 root_fn=GetProcAddress(dui,"?IsVisible@CControlUI@DuiLib@@UBE_NXZ");memcpy(&tree_visible,&root_fn,sizeof(root_fn));
 unsigned char root_code[]={0x8b,0x81,0xa0,0,0,0,0xc3};unsigned char data_code[]={0x8b,0x01,0xc3};
 if(!get_root||!tree_count||!tree_item||!string_data||!tree_visible||memcmp((void*)get_root,root_code,sizeof(root_code))||memcmp((void*)string_data,data_code,sizeof(data_code))){t->failure=91;return;}
 if(t->input_kind==2||t->input_kind==6) {
  unsigned char init_store[]={0x89,0xb7,0xf0,0,0,0};
  void *view=(void*)(uintptr_t)t->width;
  if(memcmp(base+0x5a3fa04,init_store,sizeof(init_store))||!valid(view,0xf4)){t->failure=89;return;}
  void *control=*(void**)((unsigned char*)view+0xf0);
  if(!control_matches(control)){t->failure=90;return;}
  HWND attached=(HWND)get_paint(control);DWORD pid=0;DWORD thread=GetWindowThreadProcessId(attached,&pid);
  if(pid!=t->pid||thread!=t->tid||attached!=(HWND)(uintptr_t)t->height||!get_manager(control)||!tree_visible(control)){t->failure=88;return;}
  void *ancestor=control;unsigned depth=0;
  while(ancestor&&depth++<30){if(!tree_visible(ancestor)){t->failure=88;return;}ancestor=get_parent(ancestor);}
  if(ancestor){t->failure=88;return;}
  BOOL active=FALSE;EnumWindows(visible_voice,(LPARAM)&active);if(active){t->failure=85;return;}
  if(t->mode==1){t->rich_size=(DWORD)snprintf(t->serialized,CARD_MAX,"{\"exact_chat_view_verified\":true,\"attached_view_verified\":true,\"voice_call_performed\":false}");t->returned=1;return;}
  typedef void (__thiscall *NormalVoiceButton)(void*);
  NormalVoiceButton start=NULL;void *entry=base+0x5a25690;memcpy(&start,&entry,sizeof(entry));
  t->send_entered=1;start(view);t->returned=1;
  t->rich_size=(DWORD)snprintf(t->serialized,CARD_MAX,"{\"normal_voice_button_returned\":true,\"invitation_observed\":false,\"automatic_retry_allowed\":false}");return;
 }
 if(t->height) {
  HWND candidate=(HWND)(uintptr_t)t->height;DWORD pid=0;
  DWORD thread=GetWindowThreadProcessId(candidate,&pid);WCHAR cls[128]={0};
  void *window=(void*)(uintptr_t)GetWindowLongPtrW(candidate,GWLP_USERDATA);
  if(pid!=t->pid||thread!=t->tid||!IsWindowVisible(candidate)||!GetClassNameW(candidate,cls,128)||!valid(window,0x200)||!type_has(window,".?AVWindowImplBase@DuiLib@@")||*(HWND*)((unsigned char*)window+4)!=candidate){t->failure=94;return;}
  if(!wcscmp(cls,L"weWorkSelectUser")) {
   if((!complete_type_is(window,".?AVCSelectUserFrame@ui@wework@@")&&!complete_type_is(window,".?AVCSelectUserFrame2@ui@wework@@"))||(t->mode!=1&&t->input_kind!=3&&t->input_kind!=5)){t->failure=107;return;}
   selector_window=TRUE;
  } else if(wcsncmp(cls,L"WXworkWindow",12)&&wcsncmp(cls,L"WeWorkWindow",12)){t->failure=94;return;}
  ui_manager=(unsigned char*)window+0x44;
  if(!type_has(ui_manager,".?AVCPaintManagerUI@DuiLib@@")){t->failure=95;return;}
  paint=candidate;
 }
 if(!valid(ui_manager,0xa4)){t->failure=92;return;}
 if(selector_window) {
  FARPROC fn=GetProcAddress(dui,"?GetUserData@CControlUI@DuiLib@@UAEABVCDuiString@2@XZ");memcpy(&checkbox_data,&fn,sizeof(fn));
  fn=GetProcAddress(dui,"?IsSelfSelected@CControlUI@DuiLib@@UBE_NXZ");memcpy(&checkbox_selected,&fn,sizeof(fn));
  unsigned char self_code[]={0x8a,0x81,0xb1,0x03,0,0,0xc3};
  if(!checkbox_data||!checkbox_selected||memcmp((void*)checkbox_selected,self_code,sizeof(self_code))){t->failure=113;return;}
 }
 reading_selector=selector_window;requested_checkbox=NULL;requested_checkbox_count=0;
 tree_parent=get_parent;tree_paint=get_paint;tree_pos=get_pos;trial=t;tree_window=paint;nodes=0;used=0;complete=TRUE;hang_outer=NULL;hang_inner=NULL;outer_count=0;inner_count=0;button_kind=0;answer_button=NULL;answer_count=0;answer_kind=0;inviter_name=NULL;invite_tips=NULL;inviter_count=0;tips_count=0;reject_count=0;
 cancel_button=NULL;selector_title=NULL;cancel_count=0;selector_title_count=0;cancel_caption_count=0;
 if(!GetClientRect(paint,&viewport)){t->failure=93;return;}
 used+=(size_t)snprintf(t->serialized,CARD_MAX,"{\"nodes\":[");
 void *root=get_root(ui_manager);walk(root,NULL,0);
 used+=(size_t)snprintf(t->serialized+used,CARD_MAX-used,"],\"node_count\":%u,\"complete\":%s,\"paint_window\":\"%lx\",\"native_ui_action_performed\":false}",nodes,complete?"true":"false",(DWORD)(uintptr_t)paint);
 if(used&&t->serialized[used-1]=='}') {
  used--;used+=(size_t)snprintf(t->serialized+used,CARD_MAX-used,",\"hang_outer\":\"%lx\",\"hang_inner\":\"%lx\",\"outer_count\":%u,\"inner_count\":%u,\"button_kind\":%d}",(DWORD)(uintptr_t)hang_outer,(DWORD)(uintptr_t)hang_inner,outer_count,inner_count,button_kind);
 }
 if(used&&t->serialized[used-1]=='}') {
  used--;used+=(size_t)snprintf(t->serialized+used,CARD_MAX-used,",\"window_root\":\"%lx\",\"accept_button\":\"%lx\",\"accept_count\":%u,\"accept_kind\":%d}",(DWORD)(uintptr_t)GetWindowLongPtrW(paint,GWLP_USERDATA),(DWORD)(uintptr_t)answer_button,answer_count,answer_kind);
 }
 if(used&&t->serialized[used-1]=='}') {
  used--;used+=(size_t)snprintf(t->serialized+used,CARD_MAX-used,",\"cancel_button\":\"%lx\",\"cancel_count\":%u,\"cancel_caption_count\":%u}",(DWORD)(uintptr_t)cancel_button,cancel_count,cancel_caption_count);
 }
 if(selector_window&&complete_type_is((void*)(uintptr_t)GetWindowLongPtrW(paint,GWLP_USERDATA),".?AVCSelectUserFrame@ui@wework@@")) {
  /* The version-bound constructor copies its 0x550-byte configuration to
   * frame+0x6f8. Two independently populated strings retain the exact chat. */
  char first[128]={0},second[128]={0};void *frame=(void*)(uintptr_t)GetWindowLongPtrW(paint,GWLP_USERDATA);
  if(read_group_string(frame,0x7f8,first)&&read_group_string(frame,0x938,second)&&!strcmp(first,second)&&used+200<CARD_MAX&&t->serialized[used-1]=='}') {
   used--;used+=(size_t)snprintf(t->serialized+used,CARD_MAX-used,",\"bound_group_chat\":\"%s\",\"group_binding_verified\":true}",first);
  }
  /* This is a snapshot of the final getter's version-bound input vectors,
   * not a call to that getter, a confirmation action, or proof of voice use. */
  SelectionSnapshot selected;const unsigned char getter_code[]={0x8b,0x98,0xb4,0x06,0,0,0x8b,0xb0,0xb0,0x06,0,0};
  BOOL model_ok=!memcmp(base+0x6f07e7b,getter_code,sizeof(getter_code))&&
   selection_snapshot_read((uint32_t)(uintptr_t)frame,selection_read,&selected);
  if(used+7000<CARD_MAX&&t->serialized[used-1]=='}') {
   used--;used+=(size_t)snprintf(t->serialized+used,CARD_MAX-used,",\"selected_member_model\":{\"verified\":%s",model_ok?"true":"false");
   if(model_ok) {
    used+=(size_t)snprintf(t->serialized+used,CARD_MAX-used,",\"source\":\"classic_final_selection_vectors\",\"count\":%u,\"object_count\":%u,\"additional_count\":%u,\"ids\":[",selected.count,selected.object_count,selected.additional_count);
    for(unsigned i=0;i<selected.count;i++)used+=(size_t)snprintf(t->serialized+used,CARD_MAX-used,"%s\"%llu\"",i?",":"",(unsigned long long)selected.ids[i]);
    used+=(size_t)snprintf(t->serialized+used,CARD_MAX-used,"]");
   }
   used+=(size_t)snprintf(t->serialized+used,CARD_MAX-used,"}}");
  }
 }
 t->rich_size=(DWORD)used;
 if(t->mode==1){t->returned=1;return;}
 if(t->input_kind==5) {
  if(!selector_window||!complete||requested_checkbox_count!=1||t->payload_size<18||t->payload_size>376||((t->payload_size-16)&1)||selector_title_count!=1){t->failure=114;return;}
  DWORD bound[4];memcpy(bound,t->payload,16);
  const WCHAR *data=string_data(checkbox_data(requested_checkbox));unsigned bytes=t->payload_size-16;
  const WCHAR *title=string_data((unsigned char*)selector_title+0x11c);
  BOOL classic=complete_type_is((void*)(uintptr_t)GetWindowLongPtrW(paint,GWLP_USERDATA),".?AVCSelectUserFrame@ui@wework@@");
  const WCHAR *expected_title=classic?L"选择联系人":L"发起群聊";unsigned title_bytes=(unsigned)(wcslen(expected_title)+1)*2;
  if(bound[0]!=(DWORD)(uintptr_t)GetWindowLongPtrW(paint,GWLP_USERDATA)||bound[1]!=(DWORD)(uintptr_t)requested_checkbox||bound[2]>1||bound[3]>1||!valid((void*)data,bytes)||t->payload[t->payload_size-1]||t->payload[t->payload_size-2]||memcmp(data,t->payload+16,bytes)||wcslen(data)*2+2!=bytes||!valid((void*)title,title_bytes)||memcmp(title,expected_title,title_bytes)||tree_paint(requested_checkbox)!=paint||!tree_visible(requested_checkbox)||checkbox_selected(requested_checkbox)!=bound[2]){t->failure=115;return;}
  BooleanGetter enabled=NULL,activate=NULL;FARPROC fn=GetProcAddress(dui,"?IsEnabled@CControlUI@DuiLib@@UBE_NXZ");memcpy(&enabled,&fn,sizeof(fn));
  fn=GetProcAddress(dui,"?Activate@COptionUI@DuiLib@@UAE_NXZ");memcpy(&activate,&fn,sizeof(fn));
  if(!enabled||!activate||!enabled(requested_checkbox)){t->failure=116;return;}
  if(bound[2]==bound[3]) {
   t->returned=1;t->rich_size=(DWORD)snprintf(t->serialized,CARD_MAX,"{\"already_selected_state\":true,\"invitation_performed\":false}");return;
  }
  t->send_entered=1;unsigned char activated=activate(requested_checkbox);t->returned=1;
  t->rich_size=(DWORD)snprintf(t->serialized,CARD_MAX,"{\"normal_checkbox_activate_returned\":true,\"activated\":%s,\"invitation_performed\":false,\"automatic_retry_allowed\":false}",activated?"true":"false");return;
 }
 if(t->input_kind==3) {
  if(!selector_window||t->payload_size!=12||!complete||cancel_count!=1||cancel_caption_count!=1||selector_title_count!=1){t->failure=109;return;}
  DWORD bound[3];memcpy(bound,t->payload,12);
  const WCHAR *title=string_data((unsigned char*)selector_title+0x11c);
  BOOL classic=complete_type_is((void*)(uintptr_t)GetWindowLongPtrW(paint,GWLP_USERDATA),".?AVCSelectUserFrame@ui@wework@@");
  const WCHAR *expected_title=classic?L"选择联系人":L"发起群聊";unsigned title_bytes=(unsigned)(wcslen(expected_title)+1)*2;
  if(bound[0]!=(DWORD)(uintptr_t)GetWindowLongPtrW(paint,GWLP_USERDATA)||bound[1]!=(DWORD)(uintptr_t)cancel_button||bound[2]||!valid((void*)title,title_bytes)||memcmp(title,expected_title,title_bytes)||tree_paint(cancel_button)!=paint||!tree_visible(cancel_button)||!named(cancel_button,L"cancelbtn")){t->failure=110;return;}
  BooleanGetter enabled=NULL,activate=NULL;FARPROC fn=GetProcAddress(dui,"?IsEnabled@CControlUI@DuiLib@@UBE_NXZ");memcpy(&enabled,&fn,sizeof(fn));
  fn=GetProcAddress(dui,"?Activate@CButtonLayoutUI@DuiLib@@UAE_NXZ");memcpy(&activate,&fn,sizeof(fn));
  if(!enabled||!activate||!enabled(cancel_button)){t->failure=111;return;}
  t->send_entered=1;unsigned char activated=activate(cancel_button);t->returned=1;
  t->rich_size=(DWORD)snprintf(t->serialized,CARD_MAX,"{\"normal_cancel_button_returned\":true,\"activated\":%s,\"invitation_performed\":false,\"automatic_retry_allowed\":false}",activated?"true":"false");return;
 }
 if(t->input_kind==1) {
  if(!t->height||t->payload_size!=12||!complete||answer_count!=1){t->failure=100;return;}
  DWORD expected_answer[3];memcpy(expected_answer,t->payload,12);
  if(inviter_count!=1||tips_count!=1||reject_count!=1){t->failure=105;return;}
  const WCHAR *caption=string_data((unsigned char*)inviter_name+0x11c),*tips=string_data((unsigned char*)invite_tips+0x11c);
  unsigned n=0;while(n<180&&valid((void*)(caption+n),2)&&caption[n])n++;
  char label[1500]={0};if(n>=180||!WideCharToMultiByte(CP_UTF8,0,caption,(int)n,label,sizeof(label)-1,NULL,NULL)||strcmp(label,t->text)||!valid((void*)tips,sizeof(L"邀请你语音通话"))||memcmp(tips,L"邀请你语音通话",sizeof(L"邀请你语音通话"))){t->failure=106;return;}

  if(expected_answer[0]!=(DWORD)(uintptr_t)GetWindowLongPtrW(paint,GWLP_USERDATA)||expected_answer[1]!=(DWORD)(uintptr_t)answer_button||expected_answer[2]!=0||tree_paint(answer_button)!=paint||!named(answer_button,L"accept_btn")){t->failure=101;return;}
  BooleanGetter activate_answer=NULL;FARPROC fn=GetProcAddress(dui,answer_kind==1?"?Activate@CButtonUI@DuiLib@@UAE_NXZ":"?Activate@CButtonLayoutUI@DuiLib@@UAE_NXZ");memcpy(&activate_answer,&fn,sizeof(fn));
  if(!activate_answer){t->failure=102;return;}
  BOOL busy=FALSE;EnumWindows(visible_voice,(LPARAM)&busy);if(busy){t->failure=108;return;}
  t->send_entered=1;unsigned char activated=activate_answer(answer_button);t->returned=1;
  t->rich_size=(DWORD)snprintf(t->serialized,CARD_MAX,"{\"normal_accept_button_returned\":true,\"activated\":%s,\"answer_button_type\":%d,\"connection_observed\":false,\"automatic_retry_allowed\":false}",activated?"true":"false",answer_kind);
  return;
 }
 if(!t->height||t->payload_size!=12||!complete||outer_count!=1||inner_count!=1){t->failure=96;return;}
 DWORD expected_handle[3];memcpy(expected_handle,t->payload,12);
 void *root_window=(void*)(uintptr_t)GetWindowLongPtrW(paint,GWLP_USERDATA);
 if(expected_handle[0]!=(DWORD)(uintptr_t)root_window||expected_handle[1]!=(DWORD)(uintptr_t)hang_outer||expected_handle[2]!=(DWORD)(uintptr_t)hang_inner||tree_paint(hang_inner)!=paint){t->failure=97;return;}
 if(!named(hang_outer,L"hang_up_btn")||!named(hang_inner,L"main_btn")||!below(hang_inner,hang_outer)||!tree_visible(hang_inner)){t->failure=98;return;}
 const char *activation_name=button_kind==1?"?Activate@CButtonUI@DuiLib@@UAE_NXZ":"?Activate@CButtonLayoutUI@DuiLib@@UAE_NXZ";
 BooleanGetter activate=NULL;FARPROC a=GetProcAddress(dui,activation_name);memcpy(&activate,&a,sizeof(a));
 if(!activate){t->failure=99;return;}
 t->send_entered=1;unsigned char activated=activate(hang_inner);t->returned=1;
 t->rich_size=(DWORD)snprintf(t->serialized,CARD_MAX,"{\"normal_button_activate_returned\":true,\"activated\":%s,\"hangup_button_type\":%d,\"hangup_observed\":false,\"automatic_retry_allowed\":false}",activated?"true":"false",button_kind);


}
__declspec(dllexport) LRESULT CALLBACK wecom_hook(int code,WPARAM wparam,LPARAM lparam) {
 if(code>=0&&lparam){CWPSTRUCT *m=(CWPSTRUCT*)lparam;
  if(m->message==RegisterWindowMessageW(MESSAGE_NAME)&&m->wParam&&!m->lParam){
   WCHAR name[80];map_name(name,(DWORD)m->wParam);HANDLE mapping=OpenFileMappingW(FILE_MAP_ALL_ACCESS,FALSE,name);
   Trial *t=mapping?MapViewOfFile(mapping,FILE_MAP_ALL_ACCESS,0,0,sizeof(Trial)):NULL;
   if(t&&t->magic==MAGIC&&t->nonce==(DWORD)m->wParam&&identity(t)&&InterlockedCompareExchange(&t->state,1,0)==0){
    HMODULE pinned=NULL;
    if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,(LPCWSTR)(uintptr_t)&wecom_hook,&pinned))t->failure=1;
    else {t->callback_pid=GetCurrentProcessId();t->callback_tid=GetCurrentThreadId();verify(t);}
    InterlockedExchange(&t->state,2);
   }
   if(t)UnmapViewOfFile(t);
   if(mapping)CloseHandle(mapping);
  }
 }
 return CallNextHookEx(NULL,code,wparam,lparam);
}
BOOL WINAPI DllMain(HINSTANCE h,DWORD why,LPVOID unused){(void)unused;if(why==DLL_PROCESS_ATTACH)DisableThreadLibraryCalls(h);return TRUE;}
