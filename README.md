# COIN ATTACKS [ASPLOS 2020]
<img align="right" src="images/coins.gif">

## IMPORTANT: Licensing

This project is licensed in GPLv3 with the following additional conditions: 

1. If you plan to benchmark, compare, evaluate this project with intention to publish the results (including in a paper), you must contact us with your real identity, affiliation, and advisors, and a short description of how you will use our source code before using and/or downloading this project. In addition, you will provide an opportunity for us to comment on and help with technical and other issues related to this project you have during the development. Examples include but are not limited to failure to compile or incomplete protection.

2. If you use any part of this project (excluding third-party software) and published a paper about it, you agree to open-source your project within one month of the official paper publication.

If you do not agree to these conditions, please do not use our source code.

**Justfication:** this is a research prototype. Its sole purpose is to demonstrate that the original idea works. It is expected to have implementation flaws. We welcome efforts to re-produce/evaluate our results but request an opportunity to fix implementation flaws. Generally speaking, we value design flaws more but will try to fix implementation issues.
If you plan to use this project in production, we would love to hear about it and provide help if needed. 

COIN attacks demonstrates the weakness in SGX enclave software model. We define three attacks in the enclave interface:
* (C)oncurrent ECALLs
* (O)rder of ECALLs
* (In)put manipulation

We have developed an extensible framework to independently analyze an enclave on the presence of COIN attacks. Our prototype have implemented 8 security policies that could detect:
* Heap memory leak
* Stack memory leak
* Ineffectual condition
* Use-after-free
* Double free
* Stack overflow
* Heap overflow
* Null pointer dereference

**The paper will be appeared in the ASPLOS 2020 conference. This repository is for the framework source code.**

## Prototype
The prototype is built for following system:
* Intel x86-64 machine (64GB memory)
* Linux Distribution (preferably 4.15.0)
* Intel SGX SDK

*Note: It is not required to use a real Intel SGX machine.*

## Source
```
COIN Attack
|
|--src
      |
      |--semantics
                  |
                  |--llvm_src
                             |
                             |--llvm/lib/Transforms/EnclaveSemantics/EnclaveSemantics.cpp
                  |
                  |--pyedl
                          |
                          |--edlParse.py
      |
      |--core
             |
             |--Triton/src/enclaveCoverage/coverage.py
             |
             |--Triton/src/enclaveCoverage/policies.py
|
|--scripts
          |
          |--PoCs
          |
          |--SGX_SQLite
|
|--PoCs
       |
       |--df_enclave
       |
       |--hl_enclave
       |
       |--ho_enclave
       |
       |--ie_enclave
       |
       |--nd_enclave
       |
       |--sl_enclave
       |
       |--so_enclave
       |
       |--uaf_enclave
```

## Build
```
export PROJECT_ROOT=path_to_repository_head
```
### LLVM Tool
1. Install required library for Gold plugin:
```text
sudo apt-get install linux-headers-$(uname -r) csh gawk automake libtool bison flex libncurses5-dev
# Check 'makeinfo -v'. If 'makeinfo' does not exist
sudo apt-get install apt-file texinfo texi2html
sudo apt-file update
sudo apt-file search makeinfo
```

2. Download binutils source code:
```text
cd ~
git clone --depth 1 git://sourceware.org/git/binutils-gdb.git binutils
```

3. Build binutils:
```text
mkdir build
cd build
../binutils/configure --enable-gold --enable-plugins --disable-werror
make
```

4. Build the compiler (use the binutils directory if you already have one):
```text
cd $PROJECT_ROOT/src/semantics/llvm_src/
mkdir build
cd build
cmake -DLLVM_ENABLE_PROJECTS=clang -DLLVM_BINUTILS_INCDIR="path_to_binutils/include" -G "Unix Makefiles" ../llvm
make -j8
```

5. Backup ar, nm, ld and ranlib:
```text
cd ~
mkdir backup
cd /usr/bin/
cp ar ~/backup/
cp nm ~/backup/
cp ld ~/backup/
cp ranlib ~/backup/
```

6. Replace ar, nm, ld and ranlib:
```text
cd /usr/bin/
sudo cp ~/build/binutils/ar ./
sudo rm nm
sudo cp ~/build/binutils/nm-new ./nm
sudo cp ~/build/binutils/ranlib ./
sudo cp ~/build/gold/ld-new ./ld
```

7. Install LLVMgold.so to /usr/lib/bfd-plugins:
```text
cd /usr/lib
sudo mkdir bfd-plugins
cd bfd-plugins
sudo cp $PROJECT_ROOT/src/semantics/llvm_src/build/lib/LLVMgold.so ./
sudo cp $PROJECT_ROOT/src/semantics/llvm_src/build/lib/libLTO.* ./
```

### Triton
Pre-requisite:
```
sudo apt-get install python-pip libcapstone-dev libboost-all-dev libz3-dev
```
1. Python LIEF library install.
```
sudo pip install lief==0.9.0
```
2. Build z3 solver from the source:
```
cd $PROJECT_ROOT/src/core/
git clone https://github.com/Z3Prover/z3.git
cd z3
python scripts/mk_make.py
cd build
make
sudo make install
```
3. Build the Triton symbolic engine.
```text
cd $PROJECT_ROOT/src/core/Triton
mkdir build
cd build
cmake ..
sudo make -j2 install
```
### SGX SDK
Install the Intel SGX SDK (into /opt/intel/sgxsdk/) following the guideline: https://github.com/intel/linux-sgx

## Usage
```
export PROJECT_ROOT=path_to_repository_head
```
There are scripts available to run PoCs and GitHub projects into the system. For example, to test SGX_SQLite projects, use:
```
cd $PROJECT_ROOT/scripts/SGX_SQLite/
./run.sh
```

*Note: Source codes are unmodified but Makefiles to build the projects with CLang/LLVM.*

## Screenshots
<img align="left" width="558px" src="images/so_report.png">
<img align="right" width="585px" src="images/uaf_report.png">


*Note: Some part of this project was developed while I was intern at Baidu X-lab.*
