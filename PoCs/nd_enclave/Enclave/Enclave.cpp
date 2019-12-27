#include "../eType.h"
#include "Enclave_t.h"
#include <stdio.h>
#include <string.h>

void ecall_ask(char *in_msg, char *out_msg) {
  char tmp[10000];
  if (in_msg) {
    int cnt = 0, j = 0;
    for (int i = 0; i < strlen(in_msg); i++) {
      if (in_msg[i] >= '0' && in_msg[i] <= '9') {
        cnt++;
      } else {
        tmp[j] = in_msg[i];
        j++;
      }
    }
    ocall_print_int(cnt);
    memcpy(out_msg, tmp, sizeof(tmp));
  }
}