#include "Enclave_u.h"
#include "sgx_urts.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include "../eType.h"

#define MAX_PATH FILENAME_MAX
#define ENCLAVE_FILENAME "enclave.signed.so"

using namespace std;

void ocall_ask(char* msg, int len, int* msg_len)
{
  strcpy(msg, "hello");
  *msg_len = 5;
}

int main()
{
  sgx_enclave_id_t eid = 0;
  char token_path[MAX_PATH] = {'\0'};
  sgx_launch_token_t token = {0};
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  int updated = 0;

  ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated,
                           &eid, NULL);

  if (ret != SGX_SUCCESS)
  {
    printf("Error: creating enclave\n");
    return -1;
  }

  ret = ecall_start(eid);
  if (ret != SGX_SUCCESS)
  {
    printf("Error: Making an ecall_hob()\n");
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
