#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>
#define MAGIC 0x57434c31
#define TEXT_MAX 4096
#define MESSAGE_NAME L"WecomLinuxCliText.v1"
typedef struct {
 DWORD magic,pid,tid,nonce,mode,manager;
 ULONGLONG creation,expected_self_id;
 volatile LONG state;
 DWORD callback_pid,callback_tid,failure,model_constructed,info_constructed,send_entered,returned,model_released,info_released;
 DWORD message_type,rich_present,rich_size,manager_verified;
 DWORD ids[4];
 wchar_t executable[512];
 char chat[256],text[TEXT_MAX];
 char serialized[TEXT_MAX];
} Trial;
static inline void map_name(wchar_t *out,DWORD nonce) {swprintf(out,80,L"Local\\WecomCliText_%08lx",nonce);}
