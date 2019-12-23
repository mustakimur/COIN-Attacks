#include "../eType.h"
#include "Enclave_t.h"
#include <stdio.h>
#include <string.h>

void ecall_set_password(char *password) {
  if (!strlen(password))
    return;
  if (password[0] >= '0' && password[0] <= '9') {
    return;
  }
  ocall_store_password(password);
  ocall_print_string("Password set.");
}

void ecall_change_password(char *old_password, char *new_password) {
  char *load_password = (char *)malloc(1000);
  bool fail = false;
  ocall_load_password(load_password);
  if (strcmp(old_password, load_password) == 0) {
    if (!strlen(new_password))
      return;
    if (new_password[0] >= '0' && new_password[0] <= '9') {
      fail = true;
    } else {
      ocall_store_password(new_password);
      ocall_print_string("Password changed.");
    }
    free(load_password);

    if (fail) {
      free(load_password);
    }
  }
}