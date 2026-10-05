/* Read-only model used by the pinned classic picker's final selection getter.
 * A viewport tree is not the selected-member model. Unknown row kinds are
 * rejected rather than silently omitted as the client getter would do. */
#ifndef WECOM_SELECTION_SNAPSHOT_H
#define WECOM_SELECTION_SNAPSHOT_H
#include <stdint.h>
#include <string.h>
#define SELECTION_LIMIT 256
typedef int (*SelectionRead)(uint32_t,void*,unsigned);
typedef struct {
 uint64_t ids[SELECTION_LIMIT];
 unsigned count,object_count,additional_count,failure;
} SelectionSnapshot;
static int selection_vector(SelectionRead read,uint32_t field,uint32_t head[3],uint32_t data[SELECTION_LIMIT*2],unsigned *count) {
 if(!read(field,head,12)||head[0]>head[1]||head[1]>head[2]||
    (head[1]-head[0])%8||(head[2]-head[0])%8||head[2]-head[0]>1048576||
    (!head[0]&&(head[1]||head[2])))return 0;
 *count=(head[1]-head[0])/8;
 return *count<=SELECTION_LIMIT&&(!*count||read(head[0],data,*count*8));
}
static int selection_add(SelectionSnapshot *out,uint64_t id,int unique) {
 if(!id)return 0;
 for(unsigned i=0;i<out->count;i++)if(out->ids[i]==id)return !unique;
 if(out->count>=SELECTION_LIMIT)return 0;
 out->ids[out->count++]=id;return 1;
}
static int selection_snapshot_read(uint32_t frame,SelectionRead read,SelectionSnapshot *out) {
 uint32_t heads[2][3]={{0}},entries[2][SELECTION_LIMIT*2]={{0}},again[SELECTION_LIMIT*2]={0};
 uint32_t member_ids[SELECTION_LIMIT][2]={{0}},kinds[SELECTION_LIMIT]={0};
 unsigned counts[2]={0},failure=1;memset(out,0,sizeof(*out));
 if(!frame||frame>UINT32_MAX-0xcf4)return 0;
 for(unsigned i=0;i<2;i++)if(!selection_vector(read,frame+(i?0xce8:0x6b0),heads[i],entries[i],counts+i))goto failed;
 failure=2;
 for(unsigned i=0;i<counts[0];i++) {
  uint32_t object=entries[0][i*2];
  if(!object||object>UINT32_MAX-0x54||!read(object,member_ids[i],8)||!read(object+0x50,kinds+i,4)||
     (kinds[i]!=2&&kinds[i]!=6)||!selection_add(out,((uint64_t)member_ids[i][1]<<32)|member_ids[i][0],1))goto failed;
 }
 /* The real getter deduplicates the additional UID vector against its output. */
 for(unsigned i=0;i<counts[1];i++)if(!selection_add(out,((uint64_t)entries[1][i*2+1]<<32)|entries[1][i*2],0))goto failed;
 failure=3;
 for(unsigned i=0;i<2;i++) {
  uint32_t header[3];
  if(!read(frame+(i?0xce8:0x6b0),header,12)||memcmp(header,heads[i],12)||
     (counts[i]&&(!read(heads[i][0],again,counts[i]*8)||memcmp(again,entries[i],counts[i]*8))))goto failed;
 }
 for(unsigned i=0;i<counts[0];i++) {
  uint32_t uid[2],kind,object=entries[0][i*2];
  if(!read(object,uid,8)||!read(object+0x50,&kind,4)||memcmp(uid,member_ids[i],8)||kind!=kinds[i])goto failed;
 }
 out->object_count=counts[0];out->additional_count=counts[1];return 1;
failed:
 memset(out,0,sizeof(*out));out->failure=failure;return 0;
}
#endif
