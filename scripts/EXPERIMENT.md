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
The report would like following:

```
[EMULATION] attempted sequence:  ('ecall_create', 'ecall_use', 'ecall_destroy', 'ecall_create', 'ecall_use', 'ecall_destroy')
[LIMITATION] number of seeds attempted exceed ...
[EMULATION] attempted sequence:  ('ecall_create', 'ecall_use', 'ecall_destroy', 'ecall_create', 'ecall_destroy', 'ecall_use')
[UAF-REPORT] Potential Use-after-free (UAF) at 0xd2e: mov ecx, dword ptr [rax]
Try to use memory at 0x30000064 - 0x30000067
Allocated memory range is 0x30000064 - 0x30000070
Allocated memory at 0xcc6 and Freed at 0xd7a

Recent 200 emulated instructions: 
0xaace: mov rax, qword ptr [rbp - 8]
0xaad2: mov rdi, rax
0xaad5: call 0x12fa0
0x12fa0: push rsi
0x12fa1: mov rdx, rdi
...
0xd18: mov dword ptr [rbp - 4], edi
0xd1b: cmp qword ptr [rip + 0x2256fd], 0
0xd23: jne 0xd27
0xd27: mov rax, qword ptr [rip + 0x2256f2]
0xd2e: mov ecx, dword ptr [rax]
Seed information: 
0x30000000 [ 0x55 ]  0x30000001 [ 0x41 ]  0x30000002 [ 0x46 ]  0x30000003 [ 0xff ]
...
```

This report indicates there is an use-after-free at instruction address `0xd2e`. The memories that are accessed after freed are from `0x30000064 - 0x30000067` and the memory was allocated at instruction address `0xcc6` and freed at instruction address `0xd7a`. It also shows the ECALL sequence that has been used to trigger this vulnerability is: `ecall_create', 'ecall_use', 'ecall_destroy', 'ecall_create', 'ecall_destroy', 'ecall_use'`.

If we use `objdump` to disassemble the enclave binary, we would see:

```
0000000000000c80 <ecall_create>:
     c80:	55                   	push   rbp
     c81:	48 89 e5             	mov    rbp,rsp
     c84:	48 83 ec 10          	sub    rsp,0x10
     c88:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
     c8c:	48 8b 7d f8          	mov    rdi,QWORD PTR [rbp-0x8]
     c90:	e8 2d 9e 00 00       	call   aac2 <strlen>
     c95:	48 83 f8 03          	cmp    rax,0x3
     c99:	76 61                	jbe    cfc <ecall_create+0x7c>
     c9b:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
     c9f:	0f be 08             	movsx  ecx,BYTE PTR [rax]
     ca2:	83 f9 55             	cmp    ecx,0x55
     ca5:	75 55                	jne    cfc <ecall_create+0x7c>
     ca7:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
     cab:	0f be 48 01          	movsx  ecx,BYTE PTR [rax+0x1]
     caf:	83 f9 41             	cmp    ecx,0x41
     cb2:	75 48                	jne    cfc <ecall_create+0x7c>
     cb4:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
     cb8:	0f be 48 02          	movsx  ecx,BYTE PTR [rax+0x2]
     cbc:	83 f9 46             	cmp    ecx,0x46
     cbf:	75 3b                	jne    cfc <ecall_create+0x7c>
     cc1:	bf 0c 00 00 00       	mov    edi,0xc
     cc6:	e8 f0 74 00 00       	call   81bb <dlmalloc>
     ...
0000000000000d10 <ecall_use>:
  d10:	55                   	push   rbp
  d11:	48 89 e5             	mov    rbp,rsp
  d14:	48 83 ec 10          	sub    rsp,0x10
  d18:	89 7d fc             	mov    DWORD PTR [rbp-0x4],edi
  d1b:	48 83 3d fd 56 22 00 	cmp    QWORD PTR [rip+0x2256fd],0x0        # 226420 <obj>
  d22:	00 
  d23:	75 02                	jne    d27 <ecall_use+0x17>
  d25:	eb 33                	jmp    d5a <ecall_use+0x4a>
  d27:	48 8b 05 f2 56 22 00 	mov    rax,QWORD PTR [rip+0x2256f2]        # 226420 <obj>
  d2e:	8b 08                	mov    ecx,DWORD PTR [rax]
  ...

0000000000000d60 <ecall_destroy>:
     d60:	55                   	push   rbp
     d61:	48 89 e5             	mov    rbp,rsp
     d64:	48 83 3d b4 56 22 00 	cmp    QWORD PTR [rip+0x2256b4],0x0        # 226420 <obj>
     d6b:	00 
     d6c:	75 02                	jne    d70 <ecall_destroy+0x10>
     d6e:	eb 0f                	jmp    d7f <ecall_destroy+0x1f>
     d70:	48 8b 05 a9 56 22 00 	mov    rax,QWORD PTR [rip+0x2256a9]        # 226420 <obj>
     d77:	48 89 c7             	mov    rdi,rax
     d7a:	e8 33 7f 00 00       	call   8cb2 <dlfree>
```

If we take a close look into the allocation site in `ecall_create()`, we will see there is a very strong constraint to successfully request the allocattion. The code in source looks like:

```c++
void ecall_create(const char* name){
  if(strlen(name)  > 3 && name[0] == 'U' && name[1] == 'A' && name[2] == 'F'){
    obj = (struct eObj*) malloc(sizeof(struct eObj));
    obj->flag = 1;
    memcpy(obj->ch, "uaf", 3);
  } else {
    obj = 0;
  }
}
```

The seed info that has been used here is: `0x30000000 [ 0x55 ]  0x30000001 [ 0x41 ]  0x30000002 [ 0x46 ]  0x30000003 [ 0xff ]` which are exactly the ascii code for `UAF`. The sequence to match the pattern (i.e. allocation -> free -> use) in the UAF report would need to call: `ecall_create() -> ecall_destroy() -> ecall_use()` which is used in that emulation.


### Double-free
The report would like following:

```
[EMULATION] attempted sequence:  ('ecall_set_password', 'ecall_change_password', 'ecall_set_password', 'ecall_change_password')
[DF-REPORT] Potential double free at 0x119a
Trying to free memory (0x30000514 - 0x300008fc)
Originally allocated at 0x1115
Allocation freed before at 0x118b

Recent 200 emulated instructions: 
0xcec: add rsp, 0x50
0xcf0: pop rbp
0xcf1: ret
0x10e0: lea rdi, qword ptr [rip + 0x1f739]
...
0x118b: call 0x90d8
0x1190: test byte ptr [rbp - 0x19], 1
0x1194: je 0x119f
0x1196: mov rdi, qword ptr [rbp - 0x18]
0x119a: call 0x90d8
Seed information: 
0x30000000 [ 0x20 ]  0x30000001 [ 0xff ]  0x30000002 [ 0xff ]
```

The report includes following information:
1. The ECALL sequence is: `ecall_set_password', 'ecall_change_password', 'ecall_set_password', 'ecall_change_password'`.
2. The memory that trigger double is from: `0x30000514 - 0x300008fc`.
3. The allocation site of that memory was at instruction address `0x1115`.
4. The first free request was at instruction address `0x118b` and second free request to same memory before the memory reused at instruction address `0x119a`.

If we `objdump` the enclave binary, we would see:

```
0000000000001100 <ecall_change_password>:
    1100:	55                   	push   rbp
    1101:	48 89 e5             	mov    rbp,rsp
    1104:	48 83 ec 20          	sub    rsp,0x20
    1108:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
    110c:	48 89 75 f0          	mov    QWORD PTR [rbp-0x10],rsi
    1110:	bf e8 03 00 00       	mov    edi,0x3e8
    1115:	e8 b7 74 00 00       	call   85d1 <dlmalloc>
    ...
0000000000001100 <ecall_change_password>:
    1100:	55                   	push   rbp
    1101:	48 89 e5             	mov    rbp,rsp
    1104:	48 83 ec 30          	sub    rsp,0x30
    1108:	48 89 7d f8          	mov    QWORD PTR [rbp-0x8],rdi
    110c:	48 89 75 f0          	mov    QWORD PTR [rbp-0x10],rsi
    ...
    1182:	e8 d9 f6 ff ff       	call   860 <ocall_print_string>
    1187:	48 8b 7d e8          	mov    rdi,QWORD PTR [rbp-0x18]
    118b:	e8 48 7f 00 00       	call   90d8 <dlfree>
    1190:	f6 45 e7 01          	test   BYTE PTR [rbp-0x19],0x1
    1194:	74 09                	je     119f <ecall_change_password+0x9f>
    1196:	48 8b 7d e8          	mov    rdi,QWORD PTR [rbp-0x18]
    119a:	e8 39 7f 00 00       	call   90d8 <dlfree>
    ...
```

So, the double free is reported from `ecall_change_password()` which is source as following"

```c++
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
```

We could see that to trigger the double free, the attacker first need to satisfy `if (strcmp(old_password, load_password) == 0) {` where `load_password` is a malicious input from OCALL `ocall_load_password`. Then it also needs to fail the following: `if (new_password[0] >= '0' && new_password[0] <= '9')` so, now the process will execute two free request for `load_password`.

### Stack Overflow

### Heap Overflow

### Heap Memory Leak
