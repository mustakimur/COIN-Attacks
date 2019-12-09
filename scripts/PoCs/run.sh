export PROJECT_ROOT=/home/mustakim/COIN/asplos_COIN
source /opt/intel/sgxsdk/environment

LLVM_BUILD="$PROJECT_ROOT/coin_project/llvm-project/build"
SEMANTICS_DIR="$PROJECT_ROOT/coin_project/semantic"
SYMEMU="$PROJECT_ROOT/coin_project/core/Triton/src/enclaveCoverage"

# micro-benchmark
UAF_SRC="$PROJECT_ROOT/PoCs/uaf_enclave"
DF_SRC="$PROJECT_ROOT/PoCs/df_enclave"
SO_SRC="$PROJECT_ROOT/PoCs/so_enclave"
HO_SRC="$PROJECT_ROOT/PoCs/ho_enclave"
SL_SRC="$PROJECT_ROOT/PoCs/sl_enclave"
HL_SRC="$PROJECT_ROOT/PoCs/hl_enclave"
IC_SRC="$PROJECT_ROOT/PoCs/ic_enclave"
ND_SRC="$PROJECT_ROOT/PoCs/nd_enclave"

printf "Select your benchmark:\n1)use-after-free\n2)double-free\n3)stack overflow\n4)heap overflow\n5)stack memory leak\n6)heap memory leak\n7)null pointer dereference\n8)ineffectual condition\n"
read choice

if [ $choice -eq 1 ]
then
	PROJECT_DIR=$UAF_SRC
elif [ $choice -eq 2 ]
then
	PROJECT_DIR=$DF_SRC
elif [ $choice -eq 3 ]
then
	PROJECT_DIR=$SO_SRC
elif [ $choice -eq 4 ]
then
	PROJECT_DIR=$HO_SRC
elif [ $choice -eq 5 ]
then
	PROJECT_DIR=$SL_SRC
elif [ $choice -eq 6 ]
then
	PROJECT_DIR=$HL_SRC
elif [ $choice -eq 7 ]
then
	PROJECT_DIR=$ND_SRC
elif [ $choice -eq 8 ]
then
	PROJECT_DIR=$IC_SRC
else
	echo "Wrong choice."
	exit 1
fi

cd $PROJECT_DIR
make clean
make SGX_MODE=SIM
cd "$OLDPWD"

python "$SEMANTICS_DIR/edlParse.py" "$PROJECT_DIR/Enclave/Enclave.edl"
"$LLVM_BUILD/bin/opt" -load "$LLVM_BUILD/lib/LLVMEnclaveSemantic.so" -EnclaveSemantic  < "$PROJECT_DIR/enclave.so.0.4.opt.bc"

python "$SYMEMU/coverage.py" "$PROJECT_DIR/enclave.so" unsafe_input_complete.tmp unsafe_ecall_stat.tmp > "coin_report$choice"
