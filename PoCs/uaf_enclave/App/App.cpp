#include "Enclave_u.h"
#include "sgx_urts.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define MAX_PATH FILENAME_MAX
#define ENCLAVE_FILENAME "enclave.signed.so"

using namespace std;

void ocall_print_int(int flag) { printf("Flag does not match: %d\n", flag); }

void ocall_print_string(const char *msg) { printf("Flag matches: %s\n", msg); }

int main()
{
  sgx_enclave_id_t eid = 0;
  char token_path[MAX_PATH] = {'\0'};
  sgx_launch_token_t token = {0};
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  int updated = 0;
  char name[20] = "uaf_hello";

  ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated,
                           &eid, NULL);

  if (ret != SGX_SUCCESS)
  {
    printf("Error: creating enclave\n");
    return -1;
  }

  ret = ecall_create(eid, name);
  if (ret != SGX_SUCCESS)
  {
    printf("Error: Making an ecall_create()\n");
    return -1;
  }

  ret = ecall_use(eid, 1);
  if (ret != SGX_SUCCESS)
  {
    printf("Error: Making an ecall_use()\n");
    return -1;
  }

  ret = ecall_destroy(eid);
  if (ret != SGX_SUCCESS)
  {
    printf("Error: Making an ecall_destroy()\n");
    return -1;
  }

  ret = sgx_destroy_enclave(eid);
  if (ret != SGX_SUCCESS)
  {
    printf("Error: destroying enclave\n");
    return -1;
  }

  return 0;
}
