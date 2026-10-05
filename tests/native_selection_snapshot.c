#include <stdio.h>
#include <stdlib.h>
#include "../src/wecom_linux_cli/_native/selection_snapshot.h"
static unsigned char memory[65536];
static unsigned vector_reads;static int change_vector;
static int read_memory(uint32_t address,void *out,unsigned length) {
 if(!address||address>sizeof(memory)||length>sizeof(memory)-address)return 0;
 if(address==0x3000&&++vector_reads==2&&change_vector)memory[address]^=8;
 memcpy(out,memory+address,length);return 1;
}
static void put(uint32_t address,uint32_t value){memcpy(memory+address,&value,4);}
static void uid(uint32_t address,uint64_t value){memcpy(memory+address,&value,8);}
static void setup(void) {
 memset(memory,0,sizeof(memory));vector_reads=0;change_vector=0;
 put(0x16b0,0x3000);put(0x16b4,0x3010);put(0x16b8,0x3010);
 put(0x3000,0x4000);put(0x3004,0x4200);put(0x3008,0x4300);put(0x300c,0x4400);
 uid(0x4000,9007199254741111ULL);put(0x4050,2);
 uid(0x4300,9007199254742222ULL);put(0x4350,6);
 put(0x1ce8,0x5000);put(0x1cec,0x5010);put(0x1cf0,0x5010);
 uid(0x5000,9007199254741111ULL);uid(0x5008,1234);
}
static void check(int result,const char *name){if(!result){fprintf(stderr,"%s\n",name);exit(1);}}
int main(void) {
 SelectionSnapshot out;
 memset(memory,0,sizeof(memory));
 check(selection_snapshot_read(0x1000,read_memory,&out)&&out.count==0,"empty model");
 setup();
 check(selection_snapshot_read(0x1000,read_memory,&out)&&out.count==3&&out.object_count==2&&out.additional_count==2&&
       out.ids[0]==9007199254741111ULL&&out.ids[1]==9007199254742222ULL&&out.ids[2]==1234,
       "entire model includes off-screen members and deduplicates additional IDs");
 setup();put(0x4350,7);
 check(!selection_snapshot_read(0x1000,read_memory,&out)&&out.count==0,"unknown row kind must not be silently skipped");
 setup();uid(0x4300,9007199254741111ULL);
 check(!selection_snapshot_read(0x1000,read_memory,&out)&&out.count==0,"duplicate selected objects rejected");
 setup();uid(0x4000,0);
 check(!selection_snapshot_read(0x1000,read_memory,&out)&&out.count==0,"zero user identity rejected");
 setup();put(0x16b4,0x3004);
 check(!selection_snapshot_read(0x1000,read_memory,&out)&&out.count==0,"partial shared pointer rejected");
 setup();put(0x16b4,0x3000+257*8);put(0x16b8,0x3000+257*8);
 check(!selection_snapshot_read(0x1000,read_memory,&out)&&out.count==0,"bounded snapshot refuses oversized model");
 setup();put(0x3000,0xfffffff0);
 check(!selection_snapshot_read(0x1000,read_memory,&out)&&out.count==0,"wrapped member pointer rejected");
 setup();change_vector=1;
 check(!selection_snapshot_read(0x1000,read_memory,&out)&&out.count==0,"changed shared pointer vector rejected");
 check(!selection_snapshot_read(0xfffffff0,read_memory,&out),"wrapped frame rejected");
 return 0;
}
