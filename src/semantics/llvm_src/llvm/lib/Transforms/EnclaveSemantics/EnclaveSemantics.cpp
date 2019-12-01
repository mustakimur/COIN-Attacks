#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include <fstream>
#include <unistd.h>

#define CONST_RET_TYPE 10001
#define CONST_PARAM_TYPE 10002
#define CONST_USER 10003
#define CONST_NON_USER 10004
#define CONST_STRING 10005
#define CONST_NON_STRING 10006

#define POINTER_TY 'P'
#define CHAR_TY 'C'
#define SHORT_TY 'S'
#define INT_TY 'I'
#define LONG_TY 'L'
#define OPEN_TY '['
#define CLOSE_TY ']'

using namespace llvm;

#define DEBUG_TAG "EnclaveSemantic"

namespace {
// tuple<paramKind, paramPos, coParamPos, paramUsr, paramStr>
typedef std::tuple<int, int, int, int, int> tupleParamInfo;
typedef std::vector<tupleParamInfo> listParamInfos;
typedef std::vector<tupleParamInfo>::iterator itParamInfos;
typedef std::map<const std::string, listParamInfos> mapFuncParamInfos;
typedef std::map<const std::string, listParamInfos>::iterator itFuncParamInfos;

typedef std::vector<char> memoryLayoutType;
// tuple<parapmPos, paramMemoryLayout, coParamPos, coParamMemoryLayout, paramUsr,
// paramStr>
typedef std::tuple<int, memoryLayoutType *, int, memoryLayoutType *, int, int>
    tupleParamTypeInfo;
typedef std::vector<tupleParamTypeInfo> listParamTypeInfos;
typedef std::vector<tupleParamTypeInfo>::iterator itParamTypeInfos;
typedef std::map<Function *, listParamTypeInfos> mapFuncParamTypeInfo;
typedef std::map<Function *, listParamTypeInfos>::iterator itFuncParamTypeInfo;

typedef std::map<const std::string, unsigned int> mapFnTParam;
typedef std::map<const std::string, unsigned int>::iterator itFnTParam;
typedef std::map<const std::string, Function *> mapNameFunc;

struct EnclaveSemantic : public ModulePass {
  static char ID;
  mapFuncParamInfos mFnParamInfos;
  mapFnTParam mFnTParam;
  mapFuncParamTypeInfo mFnParamType;
  mapNameFunc mNameFn;
  char mCurDir[PATH_MAX];

  EnclaveSemantic() : ModulePass(ID) {
    if (getcwd(mCurDir, sizeof(mCurDir)) != NULL) {
      std::string unsafe_input_stat =
          std::string(mCurDir) + "/unsafe_input_stat.tmp";
      std::ifstream input_stat_file;

      std::string nameFn;
      int totalParams, paramKind, paramPos, coParamPos, paramUsr, paramStr;

      input_stat_file.open(unsafe_input_stat.c_str());

      if (input_stat_file.is_open()) {
        std::map<std::string, bool> temp;
        while (input_stat_file >> nameFn >> totalParams >> paramKind >>
               paramPos >> coParamPos >> paramUsr >> paramStr) {
          if (mFnTParam.find(nameFn) == mFnTParam.end()) {
            mFnTParam[nameFn] = totalParams;
            temp[nameFn] = false;
          }
          if (paramKind == CONST_RET_TYPE) {
            temp[nameFn] = true;
          }
          mFnParamInfos[nameFn].push_back(std::make_tuple(
              paramKind, temp[nameFn] ? paramPos + 1 : paramPos,
              (temp[nameFn] && coParamPos != -1) ? coParamPos + 1 : coParamPos,
              paramUsr, paramStr));
        }
      } else {
        llvm::errs() << "[BITCODE ERROR] unsafe_input_stat.tmp not found ...\n";
      }

      input_stat_file.close();
    }
  }

  void innerMemoryLayout(memoryLayoutType *memLayout, Type *curType) {
    if (curType) {
      if (curType->isPointerTy()) {
        memLayout->push_back(POINTER_TY);
        innerMemoryLayout(memLayout, curType->getPointerElementType());
      } else if (curType->isStructTy()) {
        StructType *stType = dyn_cast<StructType>(curType);
        memLayout->push_back(OPEN_TY);
        for (StructType::element_iterator it = stType->element_begin();
             it != stType->element_end(); it++) {
          innerMemoryLayout(memLayout, *it);
        }
        memLayout->push_back(CLOSE_TY);
      } else if (curType->isIntegerTy()) {
        if (curType->getIntegerBitWidth() == 8)
          memLayout->push_back(CHAR_TY);
        else if (curType->getIntegerBitWidth() == 16)
          memLayout->push_back(SHORT_TY);
        else if (curType->getIntegerBitWidth() == 32)
          memLayout->push_back(INT_TY);
        else if (curType->getIntegerBitWidth() == 64)
          memLayout->push_back(LONG_TY);
      } else if (curType->isArrayTy()) {
        ArrayType *arrType = dyn_cast<ArrayType>(curType);
        for (unsigned int i = 0; i < arrType->getNumElements(); i++) {
          innerMemoryLayout(memLayout, arrType->getElementType());
        }
      }
    }
  }

  void matchSemantics(Module &M, Function *fn, tupleParamInfo eParam) {
    int eParamPos = std::get<1>(eParam);
    int eCoParamPos = std::get<2>(eParam);
    int eParamUse = std::get<3>(eParam);
    int eParamStr = std::get<4>(eParam);
    Argument *fParam = nullptr;
    Type *fParamType = nullptr;
    Type *coParamType = nullptr;

    int pos = 0;
    for (Function::arg_iterator it = fn->arg_begin(); it != fn->arg_end();
         ++it, ++pos) {
      if (eParamPos == pos && isa<Argument>(it)) {
        fParam = dyn_cast<Argument>(it);
        break;
      }
    }

    memoryLayoutType *paramMemLayout = new memoryLayoutType();
    if(fParam){
    fParamType = fParam->getType();
      innerMemoryLayout(paramMemLayout, fParamType);

      memoryLayoutType *coParamMemLayout = nullptr;
      if (eCoParamPos != -1) {
        coParamMemLayout = new memoryLayoutType();
        int coPos = 0;
        for (Function::arg_iterator it = fn->arg_begin(); it != fn->arg_end();
             ++it, ++coPos) {
          if (eCoParamPos == coPos && isa<Argument>(it)) {
            Argument *coParam = dyn_cast<Argument>(it);
            coParamType = coParam->getType();
            innerMemoryLayout(coParamMemLayout, coParamType);
            break;
          }
        }
      }

      mFnParamType[fn].push_back(
          std::make_tuple(eParamPos, paramMemLayout, eCoParamPos,
                        coParamMemLayout, eParamUse, eParamStr));
    }
  }

  bool runOnModule(Module &M) override {
    for (Function &Fn : M) {
      Function *fn = &Fn;
      std::string nameFn = fn->getName();
      if (mFnTParam.find(nameFn) != mFnTParam.end()) {
        listParamTypeInfos paramTypeInfo;
        mFnParamType[fn] = paramTypeInfo;
        listParamInfos paramInfos = mFnParamInfos[nameFn];
        mNameFn[nameFn] = fn;
        for (tupleParamInfo paramInfo : paramInfos) {
          matchSemantics(M, fn, paramInfo);
        }
      }
    }

    for (itFnTParam it = mFnTParam.begin(); it != mFnTParam.end(); ++it) {
      if (mNameFn.find(it->first) == mNameFn.end()) {
        if (M.getFunction(it->first)) {
          Function *fn = M.getFunction(it->first);
          listParamInfos paramInfos = mFnParamInfos[it->first];
          mNameFn[it->first] = fn;
          for (tupleParamInfo paramInfo : paramInfos) {
            matchSemantics(M, fn, paramInfo);
          }
        }
      }
    }

    /* for (itFuncParamTypeInfo iFpti = mFnParamType.begin();
         iFpti != mFnParamType.end(); iFpti++) {
      llvm::outs() << (iFpti->first)->getName() << "\n";
      for (itParamTypeInfos iPti = iFpti->second.begin();
           iPti != iFpti->second.end(); iPti++) {
        llvm::outs() << std::get<0>(*iPti) << "\t";
        memoryLayoutType *paramMemType = std::get<1>(*iPti);
        for (memoryLayoutType::iterator itc = paramMemType->begin();
             itc != paramMemType->end(); itc++) {
          llvm::outs() << *itc;
        }
        llvm::outs() << "\t" << std::get<2>(*iPti) << "\t";
        if (std::get<3>(*iPti)) {
          memoryLayoutType *coParamMemType = std::get<3>(*iPti);
          for (memoryLayoutType::iterator itc = coParamMemType->begin();
             itc != coParamMemType->end(); itc++) {
            llvm::outs() << *itc;
          }
        }
        llvm::outs() << "\t" << std::get<4>(*iPti) << "\t" << std::get<5>(*iPti)
                     << "\n";
      }
      llvm::outs() << "-----------------------------------------------\n";
    } */

    std::ofstream wrFile;
    wrFile.open("unsafe_input_complete.tmp");

    for (Function &Fn : M) {
      Function *fn = &Fn;
      listParamTypeInfos paramInfos;
      paramInfos = mFnParamType[fn];
      if (paramInfos.size() > 0) {
        for (tupleParamTypeInfo paramInfo : paramInfos) {

          memoryLayoutType *paramMemLayout = std::get<1>(paramInfo);
          std::string paramStr(paramMemLayout->begin(), paramMemLayout->end());

          std::string coParamStr;
          if(std::get<2>(paramInfo) == -1){
            coParamStr = "NULL";
          } else {
            memoryLayoutType *coParamMemLayout = std::get<3>(paramInfo);
            std::transform(coParamMemLayout->begin(), coParamMemLayout->end(), std::back_inserter(coParamStr), [](char c){return c;});
          }

          wrFile << fn->getName().str() << "\t" << std::get<0>(paramInfo) << "\t"
                 << paramStr << "\t" << std::get<2>(paramInfo) << "\t"
                 << coParamStr << "\t" << std::get<4>(paramInfo) << "\t"
                 << std::get<5>(paramInfo) << "\n";
        }
      }
    }
    wrFile.close();

    return true;
  }
};
} // namespace

char EnclaveSemantic::ID = 0;
static RegisterPass<EnclaveSemantic>
    X("EnclaveSemantic", "Extract enclave input params memory layout.");