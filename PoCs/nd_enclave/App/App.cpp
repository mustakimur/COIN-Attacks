#include "../eType.h"
#include "Enclave_u.h"
#include "sgx_urts.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define MAX_PATH FILENAME_MAX
#define ENCLAVE_FILENAME "enclave.signed.so"

using namespace std;

void ocall_print_int(int n) { printf("Removed: %d\n", n); }

int main() {
  sgx_enclave_id_t eid = 0;
  char token_path[MAX_PATH] = {'\0'};
  sgx_launch_token_t token = {0};
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  int updated = 0;
  char in_msg[1000], out_msg[1000];

  ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated,
                           &eid, NULL);

  if (ret != SGX_SUCCESS) {
    printf("Error: creating enclave\n");
    return -1;
  }

  ret = ecall_ask(eid, in_msg, out_msg);
  if (ret != SGX_SUCCESS) {
    printf("Error: Making an ecall_hob()\n");
    return -1;
  }

  ret = sgx_destroy_enclave(eid);
  if (ret != SGX_SUCCESS) {
    printf("Error: destroying enclave\n");
    return -1;
  }

  return 0;
}
