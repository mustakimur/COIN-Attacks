#include "Enclave_t.h"
#include <string.h>
#include <stdio.h>
#include "../eType.h"

struct eObj *obj;

void ecall_create(const char* name){
  if(strlen(name)  > 3 && name[0] == 'U' && name[1] == 'A' && name[2] == 'F'){
    obj = (struct eObj*) malloc(sizeof(struct eObj));
    obj->flag = 1;
    memcpy(obj->ch, "uaf", 3);
  } else {
    obj = 0;
  }
}

void ecall_use(int flag){
  if (obj == 0){
    return;
  }
  if(obj->flag == flag){
    ocall_print_string(obj->ch);
  } else {
    ocall_print_int(obj->flag);
  }
}

void ecall_destroy(){
  if(obj == 0)
    return;
  free(obj);
}
