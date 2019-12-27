#include "../eType.h"
#include "Enclave_t.h"
#include <stdio.h>
#include <string.h>

void ecall_compare(struct eData *est, int size) {
  int ERR = 0;
  struct eData *pdt = (struct eData *)malloc(sizeof(struct eData));
  ocall_pdt(pdt, sizeof(pdt));

  int nn = est->nn < pdt->nn ? est->nn : pdt->nn;
  for (int i = 0; i < nn; i++) {
    if (est->date_time[i] > pdt->date_time[i]) {
      ERR = -1;
      goto error;
    }
  }

  ocall_print_string("Success.");
  free(pdt);

error:
  ocall_print_int(ERR);
  return;
}