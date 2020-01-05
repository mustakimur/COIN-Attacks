# Experiment

## Background
To experiment of COIN Attacks framework, we deliver 8 micro-benchmark for 8 security sensitive policy. The micro-benchmarks are each a seperate SGX project. The experiment also includes SGX_SQLite project cloned from https://github.com/yerzhan7/SGX_SQLite (because original repository has pending pull request from us for the patches that could be merged in the meantime). Note, we are working on to include the other experimented projects.

## Usage
To experiment the micro-benchmark, follow the instructions:
```
export PROJECT_ROOT=path_to_repository_head
# if you are using the docker image, it would be
# export PROJECT_ROOT=/home/COIN-Attacks/

cd $PROJECT_ROOT/scripts/PoCs/
./run.sh

# Following will be on your screen
Select your benchmark:
1)use-after-free
2)double-free
3)stack overflow
4)heap overflow
5)stack memory leak
6)heap memory leak
7)null pointer dereference
8)ineffectual condition

# use the number to test one of the stack memory leak benchmark
5

# The will trigger the benchmark compilation and run the analysis.
# The report will be available in the current direct as coin_report<benchmark_id>
```

## Description
We are going to describe the reports for each of the micro-benchmark.

### Stack Memory Leak
The report would look like following:

```
[EMULATION] attempted sequence:  ('ecall_start', 'ecall_start')
[SL-REPORT] potential stack memory leak at 0xd42 for stack memory at 0x9ffeffd7
Recent 200 emulated instructions: 
0xdd0: push rbp
0xdd1: mov rbp, rsp
0xdd4: sub rsp, 0x50
0xdd8: mov rax, qword ptr fs:[0x28]
...
0xd27: call 0x82c5
0xd2c: mov rcx, qword ptr [rbp - 8]
0xd30: mov qword ptr [rcx], rax
0xd33: mov rax, qword ptr [rbp - 8]
0xd37: mov rdi, qword ptr [rax]
0xd3a: mov rsi, qword ptr [rbp - 0x10]
0xd3e: movsxd rdx, dword ptr [rbp - 0x14]
0xd42: call 0xa47c
```

We have couple of information here about a stack memory leak. First of the ECALL sequence is `ecall_start, ecall_start`. The memory leak is caused at `0xd42` instruction address in `enclave.so`. The leaked stack memory address is at `0x9ffeffd7`. The last 200 emulated instructions are following.

The `objdump` could help us understand the issue. Move to PoC directory `cd /home/COIN-Attacks/PoCs/sl_enclave`, `objdump -d -Mintel enclave.so > enclave.so.asm` and check out the `enclave.so.asm`. Look for the stack memory leak instruction at `0xd42` and we could find following:

```
0000000000000d10 <_Z11send_it_vfnP5eDataPci>:
     d10:	55                   	push   rbp
     d11:	48 89 e5             	mov    rbp,rsp
     d14:	48 83 ec 20          	sub    rsp,0x20
     d18:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
     d1c:	48 89 75 f0          	mov    QWORD PTR [rbp-0x10],rsi
     d20:	89 55 ec             	mov    DWORD PTR [rbp-0x14],edx
     d23:	48 63 7d ec          	movsxd rdi,DWORD PTR [rbp-0x14]
     d27:	e8 99 75 00 00       	call   82c5 <dlmalloc>
     d2c:	48 8b 4d f8          	mov    rcx,QWORD PTR [rbp-0x8]
     d30:	48 89 01             	mov    QWORD PTR [rcx],rax
     d33:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
     d37:	48 8b 38             	mov    rdi,QWORD PTR [rax]
     d3a:	48 8b 75 f0          	mov    rsi,QWORD PTR [rbp-0x10]
     d3e:	48 63 55 ec          	movsxd rdx,DWORD PTR [rbp-0x14]
     d42:	e8 35 97 00 00       	call   a47c <memcpy>
```

The `c++filt _Z11send_it_vfnP5eDataPci` will return `send_it_vfn(eData*, char*, int)` i.e. the function name of the vulnerable code. It is a `memcpy()` in `sent_it_vfn()`.

Check out the `Enclave/Enclave.cpp` which look like following:

```c++
void send_it_vfn(struct eData* data, char *msg, int len){
  data->msg = (char*) malloc(len);
  memcpy(data->msg, msg, len);
  data->len = len;
}

void send_it_cfn(struct eData* data, char *msg, int len){
  data->msg = (char*) malloc(strlen(msg));
  memcpy(data->msg, msg, strlen(msg));
  data->len = strlen(msg);
}

void ecall_start(struct eData* cdata, struct eData* vdata) {
  char local_msg[16] = {0};
  int local_msg_len;

  ocall_ask(local_msg, sizeof(local_msg), &local_msg_len);

  send_it_vfn(vdata, local_msg, local_msg_len);

  send_it_cfn(cdata, local_msg, local_msg_len);
}
```

Although there are similar code in `send_it_vfn()` and `send_it_cfn()`, our analysis report only `send_it_vfn()` have a vulnerable `memcpy()` because the function uses a symbolic variable i.e. `len` to determine how many bytes to copy from a stack buffer i.e. `msg` aka `local_msg` to a heap buffer i.e. `data->msg`. The other `memcpy()` is safe because that uses `strlen(src)`.

### Ineffectual condition
The report would like following:

```
[EMULATION] attempted sequence:  ('ecall_compare', 'ecall_compare')
[IE-REPORT] Potential ineffectual conditional statement at 0xdbd
The Error code is at 0xdca
Recent 200 emulated instructions: 
0xd64: mov rdi, qword ptr [rbp - 0x18]
0xd68: mov esi, 8
0xd6d: call 0xa70
0xd72: mov rcx, qword ptr [rbp - 8]
0xd76: mov edx, dword ptr [rcx]
0xd78: mov rcx, qword ptr [rbp - 0x18]
...
0xdd7: jmp 0xda1
0xda1: mov eax, dword ptr [rbp - 0x20]
0xda4: cmp eax, dword ptr [rbp - 0x1c]
0xdb9: movsxd rcx, dword ptr [rbp - 0x20]
0xdbd: cmp edx, dword ptr [rax + rcx*4 + 4]
Seed information: 
0x30000000 [ 0x0 ]  0x30000001 [ 0x0 ]  0x30000002 [ 0x0 ]  0x30000003 [ 0x80 ]  0x30000004 [ 0x0 ]  0x30000005 [ 0x0 ]  0x30000006 [ 0x0 ]
...
```

First, disassemble the `enclave.so` using objdump and look into the assembly:

```
...
0000000000000d40 <ecall_compare>:
d40:	55                   	push   rbp
d41:	48 89 e5             	mov    rbp,rsp
d44:	48 83 ec 30          	sub    rsp,0x30
d48:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
...
da9:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
dad:	48 63 4d e0          	movsxd rcx,DWORD PTR [rbp-0x20]
db1:	8b 54 88 04          	mov    edx,DWORD PTR [rax+rcx*4+0x4]
db5:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
db9:	48 63 4d e0          	movsxd rcx,DWORD PTR [rbp-0x20]
dbd:	3b 54 88 04          	cmp    edx,DWORD PTR [rax+rcx*4+0x4]
...
0000000000000e02 <sgx_is_within_enclave>:
e02:	55                   	push   rbp
e03:	48 89 e5             	mov    rbp,rsp
e06:	48 89 7d d8          	mov    QWORD PTR [rbp-0x28],rdi
...
```

The `Potential ineffectual conditional statement at 0xdbd` statement indicates there is conditional statement in instruction address `0xdbd` which is in `ecall_compare()` according to `objdump`. The `cmp` is the third conditional statement in that function. Let's look into the enclave.cpp:

```c++
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
```

The first compare here is the ternary operator, the second is the loop constraint check, and the third on is the only if condition. The if condition is a symbolic conditional statement because both sides of it are from outside enclave (left side is from ECALL and right side is from OCALL). Following the condition check, there is a basic block that assign an error code and immediately jump out the box. Our policy searches all this criteria to detect if a conditional statement is ineffectual i.e. an attacker could manipulate the behavior of execution to bypass validation or authentication.

### Use-after-free

### Double-free

### Stack Overflow

### Heap Overflow

### Heap Memory Leak
