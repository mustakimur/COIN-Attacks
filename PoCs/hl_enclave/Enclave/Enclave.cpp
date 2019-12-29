#include "Enclave_t.h"
#include <string.h>
#include <stdio.h>
#include "../eType.h"

void ecall_heap_leak(struct eData* data){
	char temp[] = "kioasdinkadssasdkjhsdaklj";
  char *buf;
  int ret;

  data->msg = (char*) malloc(strlen(temp));
  memcpy(data->msg, temp, strlen(temp));
  data->len = strlen(temp);
  data->left = strlen(temp);

  while(data->left > 0){
    buf = data->msg + data->len - data->left;
    ocall_write_out(&ret, buf, data->left);

    if(ret <= 0)
    return;

    data->left -= ret;
  }
}