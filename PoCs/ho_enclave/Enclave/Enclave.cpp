#include "../eType.h"
#include "Enclave_t.h"
#include <stdio.h>
#include <string.h>

void ecall_hob() {
  char *heapStr;
  struct eData data;
  ocall_readData(&data);
  if (data.len > 0) {
    heapStr = (char *)malloc(data.len);
  } else {
    heapStr = (char *)malloc(strlen(data.msg));
  }
  memcpy(heapStr, data.msg, strlen(data.msg));
}