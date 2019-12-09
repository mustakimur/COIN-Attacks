#include "Enclave_t.h"
#include <string.h>
#include <stdio.h>
#include "../eType.h"

void local_copy_and_sum(char *arr, int num){
  char buf[10];
  if(num > 10){
    ocall_print_string("Throw error.");
    return;
  }
  for(int i = 0; i < strlen(arr); i++){
    buf[i]= arr[i];
  }
}

void ecall_process(struct eObj *obj)
{
  if(obj){
    local_copy_and_sum(obj->in_arr, obj->num);
  }
  ocall_print_string("Process finished.");
}