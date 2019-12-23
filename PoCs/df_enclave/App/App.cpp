#include "Enclave_u.h"
#include "sgx_urts.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <fstream>
#include <string>
#include <unistd.h>
#include "../eType.h"

#define MAX_PATH FILENAME_MAX
#define ENCLAVE_FILENAME "enclave.signed.so"

using namespace std;

void ocall_print_int(int out) { printf("The integer: %d\n", out); }

void ocall_print_string(char *msg) { printf("The message %s\n", msg); }

void ocall_load_password(char *buf)
{
  string line;
  ifstream myfile ("saved");
  if (myfile.is_open())
  {
    while ( getline (myfile,line) )
    {
      strcpy(buf, line.c_str());
    }
    myfile.close();
  }
}

void ocall_store_password(char *buf)
{
  ofstream myfile;
  myfile.open ("saved");
  myfile << buf;
  myfile.close();
}

int main()
{
  sgx_enclave_id_t eid = 0;
  char token_path[MAX_PATH] = {'\0'};
  sgx_launch_token_t token = {0};
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  int updated = 0;
  char old_password[10], new_password[10];

  ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated,
                           &eid, NULL);

  if (ret != SGX_SUCCESS)
  {
    printf("Error: creating enclave\n");
    return -1;
  }

  ret = ecall_set_password(eid, old_password);
  if (ret != SGX_SUCCESS)
  {
    printf("Error: Making an ecall_set_password()\n");
    return -1;
  }

  ret = ecall_change_password(eid, old_password, new_password);
  if (ret != SGX_SUCCESS)
  {
    printf("Error: Making an ecall_change_password()\n");
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
