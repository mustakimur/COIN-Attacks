#include "../eType.h"
#include "Enclave_u.h"
#include "sgx_urts.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define MAX_PATH FILENAME_MAX
#define ENCLAVE_FILENAME "enclave.signed.so"

using namespace std;

void ocall_print_int(int code) { printf("Error Code: %d\n", code); }

void ocall_print_string(char *msg) { printf("%s\n", msg); }

void ocall_pdt(struct eData *pdt, int size) {
  pdt->nn = 5;
  for (int i = 0; i < pdt->nn; i++) {
    pdt->date_time[i] = rand() % 100;
  }
}

int main() {
  sgx_enclave_id_t eid = 0;
  char token_path[MAX_PATH] = {'\0'};
  sgx_launch_token_t token = {0};
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  int updated = 0;

  struct eData *est = (struct eData *)malloc(sizeof(struct eData));

  est->nn = 5;
  for (int i = 0; i < est->nn; i++) {
    est->date_time[i] = rand() % 100;
  }

  srand(time(NULL));

  ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated,
                           &eid, NULL);

  if (ret != SGX_SUCCESS) {
    printf("Error: creating enclave\n");
    return -1;
  }

  ret = ecall_compare(eid, est, sizeof(est));
  if (ret != SGX_SUCCESS) {
    printf("Error: Making an ecall_compare()\n");
    return -1;
  }

  ret = sgx_destroy_enclave(eid);
  if (ret != SGX_SUCCESS) {
    printf("Error: destroying enclave\n");
    return -1;
  }

  return 0;
}
