from __future__ import print_function
from triton import TritonContext, ARCH, MemoryAccess, CPUSIZE, Instruction, OPCODE, MODE
from itertools import permutations

import sys
import string
import random
import re
import lief
import base64
import copy
import policies
import threading

MAX_SEED_ATTEMPT = 1000

# DEBUG Flags
STEP_DEBUG = False                      # CORE modules steps information
INIT_DETAILES_DEBUG = False             # systems loaded information
CONFIG_DEBUG = False                    # systems configuration updates
PRINT_INST_DEBUG = False                # print instruction
MEMORY_DEBUG = False                    # memory information
EMUL_DEBUG = False                      # emulation updates
SYM_DEBUG = False                       # symbolic information
REPORT_DEBUG = True
WARN_DEBUG = False                       # show warning

# constant tag to identify string and user semantics tag
CONST_USER = 10003
CONST_NON_USER = 10004
CONST_STRING = 10005
CONST_NON_STRING = 10006

# constant tag for memory size
POINTER_TY = 'P'
CHAR_TY = 'C'
SHORT_TY = 'S'
INT_TY = 'I'
LONG_TY = 'L'
OPEN_TY = '['
CLOSE_TY = ']'

Triton = TritonContext()
Triton.setArchitecture(ARCH.X86_64)
Triton.setMode(MODE.ALIGNED_MEMORY, True)
Triton.setMode(MODE.TAINT_THROUGH_POINTERS, True)

# memory map information
BASE_PLT = 0x10000000
BASE_STACK = 0x9fffffff
type_mem_size_mem = {OPEN_TY: 0, CLOSE_TY: 0, CHAR_TY: 1, SHORT_TY: 2,
                     INT_TY: 4, LONG_TY: 8, POINTER_TY: 8}

# x86-64 call convention sequence of register for argument
x64_arg_reg_seq = [
    Triton.registers.rdi, Triton.registers.rsi, Triton.registers.rdx,
    Triton.registers.rcx, Triton.registers.r8, Triton.registers.r9
]
x86_arg_reg_seq = [
    Triton.registers.edi, Triton.registers.esi, Triton.registers.edx,
    Triton.registers.ecx
]

interface_hook_fn = []
seed_mem_layout = dict()
fn_param_seed_map = dict()
next_mem_write_flag = dict()
DDoS = dict()
inst_ring_buffer = dict()
# compiler instrumented warning flag in enclave
sgx_warn_tag = {'__stack_chk_fail': 0x0}
emul_thread_lock = threading.Lock()

"""
print_report() prints the vulnerability report in format
"""


def print_report():
    print(policies.get_reported_msg())
    print('Recent 200 emulated instructions: ')
    for inst in policies.get_inst_ring_buffer():
        print(inst)
    if REPORT_DEBUG:
        print('Seed information: ')
        for k, v in seed_mem_layout.iteritems():
            print(hex(k), '[', hex(v), '] ', end =" ")


"""
req_allocate_memory(req_memory_size) allocates req_memory_size in enclave heap memory and return the starting address of the allocated memory
"""


def req_allocate_memory(req_memory_size):
    alloc_addr = policies.get_allocated_mem_addr()
    policies.update_heap_mem_map(alloc_addr, req_memory_size)
    pc = Triton.getConcreteRegisterValue(Triton.registers.rip)
    policies.update_heap_mem_history(alloc_addr, req_memory_size, pc, None)
    if MEMORY_DEBUG:
        print('[MEMORY] allocating %d bytes of heap memory at 0x%x' %
              (req_memory_size, alloc_addr))
    return alloc_addr


"""
init_stack_memory(stack_base_addr) set the stack memory in stack_base_addr beginning of an ECALL
"""


def init_stack_memory(stack_base_addr):
    Triton.concretizeAllRegister()
    Triton.setConcreteRegisterValue(Triton.registers.rbp,
                                    stack_base_addr)
    Triton.setConcreteRegisterValue(Triton.registers.rsp,
                                    stack_base_addr)


"""
sgx_malloc_hook() extracts the requested allocation size from rdi register, process the heap memory allocation, and finally force return from malloc()
"""


def sgx_malloc_hook(instruction):
    req_memory_size = Triton.getConcreteRegisterValue(Triton.registers.rdi)
    allocated_addr = req_allocate_memory(req_memory_size)
    force_return_to_callsite(allocated_addr)


"""
sgx_free_hook() extracts the requested memory range from rdi register, process the heap memory free, and finally force return from free()
Note: use-after-free policy have applied here
"""


def sgx_free_hook(instruction):
    free_mem = Triton.getConcreteRegisterValue(Triton.registers.rdi)
    if (policies.is_mem_allocated(free_mem)):
        if MEMORY_DEBUG:
            print('[MEMORY] free %d bytes of memory at 0x%x' %
                  (policies.get_mem_range_for_addr(free_mem), free_mem))

        pc = Triton.getConcreteRegisterValue(Triton.registers.rip)
        policies.update_heap_mem_history(free_mem,
                                         policies.get_mem_size_at_addr(
                                             free_mem),
                                         policies.get_heap_mem_alloc_at(free_mem), pc)

        policies.remove_mem_entry(free_mem)
    else:
        pc = Triton.getConcreteRegisterValue(Triton.registers.rip)
        msg = '[DF-REPORT] Potential double free at ' + hex(
            pc) + '\nTrying to free memory (' + hex(free_mem) + ' - ' + hex(
                free_mem + policies.get_mem_size_at_addr(free_mem)
        ) + ')\nOriginally allocated at ' + hex(policies.get_heap_mem_alloc_at(
            free_mem)) + '\nAllocation freed before at ' + hex(
            policies.get_freed_info_for_addr(free_mem)) + '\n'
        if (not policies.is_vul_reported(pc)):
            policies.make_report(msg)

    policies.set_thread_locked()
    force_return_to_callsite(0x0)


def sgx_memcpy(instruction):
    dest_mem_addr = Triton.getConcreteRegisterValue(Triton.registers.rdi)
    src_mem_addr = Triton.getConcreteRegisterValue(Triton.registers.rsi)
    mem_cpy_len = Triton.getConcreteRegisterValue(Triton.registers.rdx)
    pc = Triton.getConcreteRegisterValue(Triton.registers.rip)

    policies.is_heap_overflow(
        instruction, dest_mem_addr, src_mem_addr, mem_cpy_len, pc)

    None


# SGX SDK implicit methods to handle memory request
sgx_implicit_fn = {
    'dlmalloc': (0x0, sgx_malloc_hook),
    'dlfree': (0x0, sgx_free_hook),
    'memcpy': (0x0, sgx_memcpy)
}

"""
load_binary(binary_path) loads enclave.so to the QEMU, prepare Triton, and return lief object
"""


def load_binary(binary_path):
    binary = lief.parse(binary_path)
    phdrs = binary.segments
    for phdr in phdrs:
        size = phdr.physical_size
        vaddr = phdr.virtual_address
        Triton.setConcreteMemoryAreaValue(vaddr, phdr.content)
    return binary


"""
load_input_semantics(file_path) extracts contents from unsafe_input_complete.tmp and store them to fn_param_info dictionary
"""


def load_input_semantics(file_path):
    fn_param_info = dict()
    with open(file_path) as f:
        content = f.readlines()

    content = [x.strip() for x in content]

    for line in content:
        item_list = line.split('\t')

        fn_name = item_list[0]
        if (binary.has_symbol(fn_name)):
            if (not fn_name in fn_param_info):
                fn_param_info[fn_name] = []
                interface_hook_fn.append(
                    [fn_name, int(binary.get_function_address(fn_name))])

            # tuple<param_pos, param_mem_layout, rel_param_pos, rel_param_mem_layout, is_string, is_user>
            param_info = (item_list[1], item_list[2], item_list[3],
                          item_list[4], item_list[5], item_list[6])
            fn_param_info[fn_name].append(param_info)
    if INIT_DETAILES_DEBUG:
        print('[INIT-D] interface hook functions: ', interface_hook_fn)
        for fn, info in fn_param_info.iteritems():
            print('[INIT-D] input semantics of %s():' % (fn))
            for item in info:
                print(item)
        print('')

    return fn_param_info


"""
config_hook_table(binary) configures all hook methods to link their target
"""


def config_hook_table(binary):
    for pltIndex in range(len(interface_hook_fn)):
        if (interface_hook_fn[pltIndex][1] == None):
            interface_hook_fn[pltIndex][1] = BASE_PLT + pltIndex

    for pltgot_item in binary.pltgot_relocations:
        pltgot_item_name = pltgot_item.symbol.name
        pltgot_item_addr = pltgot_item.address
        for hook_fn in interface_hook_fn:
            hook_fn_addr = binary.get_function_address(hook_fn[0])
            if (hook_fn_addr == 0x0 and pltgot_item_name == hook_fn[0]):
                Triton.setConcreteMemoryValue(
                    MemoryAccess(pltgot_item_addr, CPUSIZE.QWORD), hook_fn[1])
                if CONFIG_DEBUG:
                    print('[CONFIG-H] relocated %s from %x to %x' %
                          (pltgot_item_name, pltgot_item_addr, hook_fn[1]))
                break

    for sgx_fn in sgx_implicit_fn:
        sgx_fn_addr = binary.get_function_address(sgx_fn)
        sgx_implicit_fn[sgx_fn] = (sgx_fn_addr, sgx_implicit_fn[sgx_fn][1])
        if CONFIG_DEBUG:
            print(
                '[CONFIG-H] create hooker for memory allocated method %s at 0x%x' %
                (sgx_fn, sgx_fn_addr))

    for warn_fn in sgx_warn_tag:
        warn_fn_addr = binary.get_function_address(warn_fn)
        sgx_warn_tag[warn_fn] = warn_fn_addr
        if CONFIG_DEBUG:
            print('[CONFIG-H] create hooker for warning method %s at 0x%x' %
                  (warn_fn, warn_fn_addr))

    return


"""
load_ECALLs(file_path) loads the unsafe_ecall_stat.tmp file contents
"""


def load_ECALLs(file_path):
    ECALLs = []

    with open(file_path) as f:
        content = f.readlines()

    content = [x.strip() for x in content]
    for line in content:
        ECALLs.append(line)

    if INIT_DETAILES_DEBUG:
        print('[INIT-D] loaded ECALLs: ', ECALLs)

    return ECALLs


"""
query_new_seed() returns new seed list generated by z3 solver
"""


def query_new_seed():
    seeds = list()

    pco = Triton.getPathConstraints()
    astCtxt = Triton.getAstContext()

    previousConstraints = astCtxt.equal(astCtxt.bvtrue(), astCtxt.bvtrue())

    for pc in pco:
        if pc.isMultipleBranches():
            branches = pc.getBranchConstraints()
            for branch in branches:
                if branch['isTaken'] == False:
                    models = Triton.getModel(
                        astCtxt.land(
                            [previousConstraints, branch['constraint']]))
                    seed = dict()
                    for k, v in list(models.items()):
                        symVar = Triton.getSymbolicVariable(k)
                        seed.update({symVar.getOrigin(): v.getValue()})
                    if seed:
                        seeds.append(seed)

        previousConstraints = astCtxt.land(
            [previousConstraints,
             pc.getTakenPredicate()])

    Triton.clearPathConstraints()

    if SYM_DEBUG:
        print('[SYMBOLIC] number of new input sets %d' % (len(seeds)))
        cc = 1
        for input in seeds:
            print('input set [%d]:' % (cc))
            for k, v in input.iteritems():
                print(hex(k), ' => ', hex(v))
            cc += 1

    return seeds


"""
prep_next_input(seed) looks into the seed map and prepare the next input
"""


def prep_next_input(seed):
    global seed_mem_layout
    for k, v in seed.iteritems():
        seed_mem_layout[k] = v


"""
force_return_to_callsite(ret_rax_val) accepts a return value to set in rax register on return from a call target
"""


def force_return_to_callsite(ret_rax_val):
    pc = Triton.getConcreteRegisterValue(Triton.registers.rip)
    Triton.concretizeRegister(Triton.registers.rax)
    Triton.setConcreteRegisterValue(Triton.registers.rax, ret_rax_val)

    ret_addr = Triton.getConcreteMemoryValue(
        MemoryAccess(Triton.getConcreteRegisterValue(Triton.registers.rsp),
                     CPUSIZE.QWORD))

    Triton.concretizeRegister(Triton.registers.rip)
    Triton.setConcreteRegisterValue(Triton.registers.rip, ret_addr)

    Triton.concretizeRegister(Triton.registers.rsp)
    Triton.setConcreteRegisterValue(
        Triton.registers.rsp,
        Triton.getConcreteRegisterValue(Triton.registers.rsp) + CPUSIZE.QWORD)

    if EMUL_DEBUG:
        print('[EMULATION] force to return at 0x%x ...' %
              (Triton.getConcreteRegisterValue(Triton.registers.rip)))


"""
is_mem_inst_to_reg(instruction, look_up_reg) returns true if instruction reads from look up register
"""


def is_mem_inst_to_reg(instruction, look_up_reg):
    regs = instruction.getReadRegisters()
    for reg, reg_info in regs:
        if (reg == look_up_reg):
            return True
    return False


"""
cal_padding(mem_allocated, mem_alloc_req) calculates padding bytes before allocate memory request in a compact object
"""


def cal_padding(mem_allocated, mem_alloc_req):
    if(mem_alloc_req == 8):
        mem_allocated += 0 if (mem_allocated %
                               8) == 0 else (8-(mem_allocated % 8))
    else:
        mem_allocated += 0 if (mem_allocated %
                               4) == 0 else (4-(mem_allocated % 4))

    mem_allocated += mem_alloc_req

    return mem_allocated


"""
get_bytes(q_type) returns number of bytes for a param type
"""


def get_bytes(q_type):
    return type_mem_size_mem[q_type]


"""
calculate_memory_size(param_layout, paran_cnt) returns the required memory in bytes for a param (if relative, multiplied by that)
"""


def calculate_memory_size(param_layout, paran_cnt):
    memory_size = 0
    par_cnt = 0

    for p_type in param_layout:
        if p_type == OPEN_TY:
            par_cnt += 1
        elif p_type == CLOSE_TY:
            par_cnt -= 1
        elif par_cnt == 0 and p_type != POINTER_TY:
            b = get_bytes(p_type)
            memory_size = cal_padding(memory_size, b)
        elif par_cnt == 1:
            b = get_bytes(p_type)
            memory_size = cal_padding(memory_size, b)

    return (memory_size * paran_cnt)


"""
set_memory_value(fn_name, param_pos, param_size, param_reg_addr, init_seed_flag) sets the memory with expected value and convert them to symbolic
"""


def set_memory_value(fn_name, param_pos, i_cnt, pc, param_size, param_reg_addr, init_seed_flag, param_is_string):
    if init_seed_flag:
        data = []
        if param_is_string:
            for d in range(0, param_size-1):
                seed_mem_layout[param_reg_addr + d] = 0x68
                data.append(0x68)
            seed_mem_layout[param_reg_addr + param_size] = 0x0a
            data.append(0x0a)
        else:
            for d in range(0, param_size):
                seed_mem_layout[param_reg_addr + d] = 0x0
                data.append(0x0)
    else:
        sym_addr = fn_param_seed_map[(fn_name, param_pos, i_cnt, pc)]
        data = []
        for d in range(0, param_size):
            if ((sym_addr + d) in seed_mem_layout):
                data.append(seed_mem_layout[sym_addr + d])

    fn_param_seed_map[(fn_name, param_pos, i_cnt, pc)] = param_reg_addr

    Triton.setConcreteMemoryAreaValue(param_reg_addr, data)

    for d in range(0, param_size):
        Triton.symbolizeMemory(MemoryAccess(param_reg_addr + d, CPUSIZE.BYTE))
        Triton.symbolizeMemory(MemoryAccess(
            param_reg_addr + d + 1, CPUSIZE.BYTE))

    return cal_padding(param_reg_addr, param_size)


"""
config_memory_for_param(fn_name, param_info, init_seed_flag, is_ECALL) configures memory for a param
"""


def config_memory_for_param(fn_name, param_info, pc, init_seed_flag, is_ECALL):
    param_pos = int(param_info[0], 10)
    param_mem_layout = param_info[1]
    rel_param_pos = int(param_info[2], 10)
    rel_param_mem_layout = param_info[3]
    param_is_user = True if int(param_info[4], 10) == CONST_USER else False
    param_is_string = True if int(param_info[5], 10) == CONST_STRING else False

    max_param_mem_size = 0

    if rel_param_pos != -1:
        if rel_param_mem_layout == LONG_TY:
            rel_param_val = Triton.getConcreteRegisterValue(
                x64_arg_reg_seq[rel_param_pos])
        else:
            rel_param_val = Triton.getConcreteRegisterValue(
                x86_arg_reg_seq[rel_param_pos])

        max_param_mem_size = calculate_memory_size(
            param_mem_layout, rel_param_val)
    elif param_is_string:
        max_param_mem_size = 100
    else:
        max_param_mem_size = calculate_memory_size(param_mem_layout, 1)

    if is_ECALL:
        param_cnt = 0
        param_reg_addr = 0
        org_param_reg_addr = 0
        for param in param_mem_layout:
            if param_cnt == 0 and param == POINTER_TY:
                param_reg_addr = req_allocate_memory(max_param_mem_size)
                org_param_reg_addr = param_reg_addr
                #print('[SET] Pointer memory at 0x%x of size %d' %(param_reg_addr, max_param_mem_size))
                Triton.setConcreteRegisterValue(
                    x64_arg_reg_seq[param_pos], param_reg_addr)
            elif param_cnt > 0:
                param_reg_addr = set_memory_value(
                    fn_name, param_pos, param_cnt, pc, max_param_mem_size if param_is_string else get_bytes(param), param_reg_addr, init_seed_flag, param_is_string)
            else:
                if param == LONG_TY:
                    next_mem_write_flag[x64_arg_reg_seq[param_pos]] = (fn_name, param_pos, get_bytes(param),
                                                                       init_seed_flag)
                else:
                    next_mem_write_flag[x86_arg_reg_seq[param_pos]] = (fn_name, param_pos, get_bytes(param),
                                                                       init_seed_flag)

            param_cnt += 1

        """ if(param_mem_layout[0] == POINTER_TY):
            data = Triton.getConcreteMemoryAreaValue(org_param_reg_addr, max_param_mem_size)
            print('[USED] At memory address 0x%x of size %d' %(org_param_reg_addr, max_param_mem_size))
            for d in range(0, max_param_mem_size):
                print(data[d], end=' ')
            print('') """


"""
set_delayed_mem_value(target_mem, fn_name, param_pos, mem_size, init_seed_flag) sets the memory with expected value for delayed request
"""


def set_delayed_mem_value(target_mem, fn_name, param_pos, mem_size, init_seed_flag):
    mem_addr = target_mem.getAddress()

    if init_seed_flag:
        data = []
        for d in range(0, mem_size):
            seed_mem_layout[mem_addr + d] = 0x0
            data.append(0x0)
    else:
        sym_addr = fn_param_seed_map[(
            fn_name, param_pos, 0, Triton.getConcreteRegisterValue(Triton.registers.rip))]
        data = []
        for d in range(0, mem_size):
            data.append(seed_mem_layout[sym_addr + d])

    fn_param_seed_map[(fn_name, param_pos, 0, Triton.getConcreteRegisterValue(
        Triton.registers.rip))] = mem_addr

    Triton.setConcreteMemoryAreaValue(mem_addr, data)

    for d in range(0, mem_size):
        Triton.symbolizeMemory(
            MemoryAccess(mem_addr + d, CPUSIZE.BYTE))


"""
hook_process_inst(instruction) processes the hooked events
"""


def hook_process_inst(instruction):
    pc = Triton.getConcreteRegisterValue(Triton.registers.rip)

    for sgx_impl_fn, sgx_impl_fn_info in sgx_implicit_fn.iteritems():
        if (sgx_impl_fn_info[0] == pc):
            sgx_impl_fn_info[1](instruction)
            return True

    for sgx_warn_fn, sgx_warn_fn_addr in sgx_warn_tag.iteritems():
        if (sgx_warn_fn_addr == pc):
            msg = '[SO-REPORT] auto generated warning for ' + sgx_warn_fn + ' from ' + hex(
                pc) + '\n'
            if(not policies.is_vul_reported(pc)):
                policies.make_report(msg)
            force_return_to_callsite(0x0)
            return True

    for interface_fn in interface_hook_fn:
        fn_name = interface_fn[0]
        if interface_fn[1] == pc:
            if EMUL_DEBUG:
                print('[EMULATION] interface hook to %s at %x' % (fn_name, pc))

            if (not fn_name in DDoS):
                DDoS[fn_name] = []

            DDoS[fn_name].append(pc)

            if (DDoS[fn_name].count(pc) > 30):
                if WARN_DEBUG:
                    msg = '[WARNING] a loop because of ocall is detected\nOCALL = ' + fn_name + ' at ' + hex(
                        pc) + '\n'
                    if(not policies.is_vul_reported(pc)):
                        policies.make_report(msg)

                return False

            if (len(DDoS[fn_name]) > 5):
                del DDoS[fn_name][0]

            is_seed = False
            if (not fn_name in fn_param_seed_map):
                fn_param_seed_map[fn_name] = []
                is_seed = True
            for item in input_semantics[fn_name]:
                config_memory_for_param(fn_name, item, pc, is_seed, False)

            force_return_to_callsite(0x0)
            return True

    del_list = []

    for reg_id, param_info in next_mem_write_flag.iteritems():
        if (is_mem_inst_to_reg(instruction, reg_id)):
            for mem_addr, mem_info in instruction.getStoreAccess():
                set_delayed_mem_value(
                    mem_addr, param_info[0], param_info[1], param_info[2], param_info[3])
            del_list.append(reg_id)

    for reg_id in del_list:
        del next_mem_write_flag[reg_id]

    return True


"""
emulate(pc, sgx_ocall, sgx_free, is_threaded) emulates instructions
"""


def emulate(pc, sgx_ocall, sgx_free, is_threaded):
    count = 0
    is_report_flagged = False
    policies.init_emulator()
    policies.init_thread_env()
    while pc:
        if(not policies.is_thread_unlocked()):
            continue
        if is_threaded:
            emul_thread_lock.acquire()
        opcode = Triton.getConcreteMemoryAreaValue(pc, 16)

        instruction = Instruction()
        instruction.setOpcode(opcode)
        instruction.setAddress(pc)

        try:
            ret = Triton.processing(instruction)
            
            if not ret:
                if WARN_DEBUG:
                    print('[LIMITATION] unsupported instruction at 0x%x' % (pc))
                Triton.setConcreteRegisterValue(Triton.registers.rip,
                                            instruction.getNextAddress())
        except:
            print('[EXCEPTION] instruction process error ...')
            break

        count += 1

        inst_ring_buffer[instruction.getAddress()] = True

        if(PRINT_INST_DEBUG and instruction.getType() == OPCODE.X86.RET):
            ret_addr = Triton.getConcreteRegisterValue(Triton.registers.rip)
            print('[INSTRUCTION] return instruction: ', instruction)
            print('[INSTRUCTION] return to: 0x%x' % ret_addr)

        if (PRINT_INST_DEBUG and instruction.getType() == OPCODE.X86.CALL):
            print('[INSTRUCTION] call instruction: ', instruction)

        policies.push_inst_to_ring_buffer(instruction)

        policies.inspection(instruction)

        if (instruction.getDisassembly() == sgx_ocall
                or instruction.getDisassembly() == sgx_free):
            force_return_to_callsite(0x0)

        if (instruction.getType() == OPCODE.X86.XGETBV):
            Triton.setConcreteRegisterValue(Triton.registers.rip,
                                            instruction.getNextAddress())

        if instruction.getType() == OPCODE.X86.HLT:
            if is_threaded:
                emul_thread_lock.release()
            break

        if (not hook_process_inst(instruction)):
            if is_threaded:
                emul_thread_lock.release()
            break

        if (policies.is_report_avl()):
            print_report()
            policies.clear_last_report()
            is_report_flagged = True
            if is_threaded:
                emul_thread_lock.release()
            break

        pc = Triton.getConcreteRegisterValue(Triton.registers.rip)
        prev_instruction = instruction

        if is_threaded:
            emul_thread_lock.release()

    policies.exit_emulator()
    policies.destroy_thread_env()
    return (count, is_report_flagged)


"""
run_single_thread_emul(perm_ECALLs_list) prepares and handles single thread mode of emulation
"""


def run_single_thread_emul(perm_ECALLs_list):
    sgx_ocall = 'call ' + \
        hex(binary.get_function_address('sgx_ocall')).rstrip("L")
    sgx_ofree = 'call ' + \
        hex(binary.get_function_address('sgx_ocfree')).rstrip("L")

    for order_ECALLs in list(perm_ECALLs_list):
        latest_seed = list()
        seed_worklist = list([{0x1000: 1}])

        order_try_cnt = 0
        new_inst_cnt = 0

        init_seed_flag = True
        seed_cnt = 0

        inst_ring_buffer.clear()
        DDoS.clear()

        print('[EMULATION] attempted sequence: ', order_ECALLs)

        while seed_worklist:
            stack_base_addr = BASE_STACK
            Triton.concretizeAllMemory()

            inst_count = 0

            for it_ECALL in order_ECALLs:
                if EMUL_DEBUG:
                    print('[EMULATION] [%s] called ...' % (it_ECALL))

                it_ECALL_addr = binary.get_function_address(it_ECALL)

                stack_base_addr -= 0x10000
                if MEMORY_DEBUG:
                    print('[MEMORY] allocate stack memory at 0x%x' %
                          (stack_base_addr))
                init_stack_memory(stack_base_addr)

                if it_ECALL in input_semantics:
                    for param_ECALL in input_semantics[it_ECALL]:
                        config_memory_for_param(
                            it_ECALL, param_ECALL, it_ECALL_addr, init_seed_flag, True)

                res = emulate(it_ECALL_addr, sgx_ocall, sgx_ofree, False)

                inst_count += res[0]

                if (res[1]):
                    break

            if EMUL_DEBUG:
                print('[EMULATION] instruction emulated: %d' % (inst_count))

            policies.reset_heap_memory()
            policies.clear_heap_mem_history()

            init_seed_flag = False

            if EMUL_DEBUG:
                print('[EMULATION] number of new unique instruction emulated: %d' %
                      (len(inst_ring_buffer) - new_inst_cnt))

            new_inst_cnt = len(inst_ring_buffer)

            temp_seed = copy.deepcopy(seed_mem_layout)
            latest_seed.append(temp_seed)

            new_seeds = query_new_seed()

            new_seeds_len = len(seed_worklist)
            for seeds in new_seeds:
                if seeds not in latest_seed and seeds not in seed_worklist:
                    seed_worklist += [dict(seeds)]
            if SYM_DEBUG:
                print('[SYMBOLIC] number of new input sets %d' %
                      (len(seed_worklist) - new_seeds_len))

            del seed_worklist[seed_cnt]

            if (len(seed_worklist) > 0):
                seed_cnt = random.randint(0, len(seed_worklist) - 1)
                prep_next_input(seed_worklist[seed_cnt])

            if SYM_DEBUG:
                print('[SYMBOLIC] number of seed in queue %d' %
                      (len(seed_worklist)))

            if (order_try_cnt > MAX_SEED_ATTEMPT):
                print('[LIMITATION] number of seeds attempted exceed ...')
                break

            order_try_cnt += 1

        fn_param_seed_map.clear()
        del(seed_worklist)
        del(latest_seed)


"""
run_concurrent__emul(list_ECALLs) prepares and handles multi-thread mode of emulation
"""


def run_concurrent_emul(list_ECALLs):
    sgx_ocall = 'call ' + \
        hex(binary.get_function_address('sgx_ocall')).rstrip("L")
    sgx_ofree = 'call ' + \
        hex(binary.get_function_address('sgx_ocfree')).rstrip("L")

    latest_seed = list()
    seed_worklist = list([{0x1000: 1}])

    order_try_cnt = 0
    new_inst_cnt = 0

    init_seed_flag = True
    seed_cnt = 0

    inst_ring_buffer.clear()
    DDoS.clear()

    if EMUL_DEBUG:
        print('[EMULATION] emulating ECALLs: ', list_ECALLs)

    while seed_worklist:
        stack_base_addr = BASE_STACK
        Triton.concretizeAllMemory()

        emu_threads = [None] * len(list_ECALLs)
        emu_thread_id = 0

        for it_ECALL in list_ECALLs:
            if EMUL_DEBUG:
                print('[EMULATION] [%s] called ...' % (it_ECALL))

            it_ECALL_addr = binary.get_function_address(it_ECALL)

            stack_base_addr -= 0x10000
            if MEMORY_DEBUG:
                print('[MEMORY] allocate stack memory at 0x%x' %
                      (stack_base_addr))
            init_stack_memory(stack_base_addr)

            if it_ECALL in input_semantics:
                for param_ECALL in input_semantics[it_ECALL]:
                    config_memory_for_param(
                        it_ECALL, param_ECALL, it_ECALL_addr, init_seed_flag, True)

            emu_threads[emu_thread_id] = threading.Thread(
                target=emulate, args=(it_ECALL_addr, sgx_ocall, sgx_ofree, True))
            emu_threads[emu_thread_id].start()

            emu_thread_id += 1

        for i in range(len(emu_threads)):
            emu_threads[i].join()

        policies.reset_heap_memory()
        policies.clear_heap_mem_history()

        init_seed_flag = False

        if EMUL_DEBUG:
            print('[EMULATION] number of new unique instruction emulated: %d' %
                  (len(inst_ring_buffer) - new_inst_cnt))

        new_inst_cnt = len(inst_ring_buffer)

        temp_seed = copy.deepcopy(seed_mem_layout)
        latest_seed.append(temp_seed)

        new_seeds = query_new_seed()

        new_seeds_len = len(seed_worklist)
        for seeds in new_seeds:
            if seeds not in latest_seed and seeds not in seed_worklist:
                seed_worklist += [dict(seeds)]
        if SYM_DEBUG:
            print('[SYMBOLIC] number of new input sets %d' %
                  (len(seed_worklist) - new_seeds_len))

        del seed_worklist[seed_cnt]

        if (len(seed_worklist) > 0):
            #seed_cnt = random.randint(0, len(seed_worklist) - 1)
            seed_cnt = 0
            prep_next_input(seed_worklist[seed_cnt])

        if SYM_DEBUG:
            print('[SYMBOLIC] number of seeds in queue %d' %
                  (len(seed_worklist)))

        if (order_try_cnt > MAX_SEED_ATTEMPT):
            print('[LIMITATION] number of seeds attempted exceed ...')
            break

        order_try_cnt += 1

    fn_param_seed_map.clear()
    del(seed_worklist)
    del(latest_seed)


if __name__ == '__main__':
    if len(sys.argv) < 4:
        debug('Syntax: %s <elf binary> <unsafe_input_complete.tmp> <unsafe_ecall_stat.tmp>' %
              (sys.argv[0]))
        sys.exit(1)

    if STEP_DEBUG:
        print('[CORE] loading the enclave shared object ...')
    binary = load_binary(sys.argv[1])

    if STEP_DEBUG:
        print('[CORE] loading the input semantics ...')
    input_semantics = load_input_semantics(sys.argv[2])

    if STEP_DEBUG:
        print('[CORE] loading the ECALL semantics ...')
    primary_ECALLs = load_ECALLs(sys.argv[3])
    duplicate_ECALLs = primary_ECALLs + primary_ECALLs
    perm_ECALLs_list = permutations(duplicate_ECALLs)

    if STEP_DEBUG:
        print('[CORE] configuring the hooks for the emulator ...')
    config_hook_table(binary)

    policies.init_policy_module(Triton)

    if STEP_DEBUG:
        print('[CORE] running single thread mode of emulation ...')
    run_single_thread_emul(perm_ECALLs_list)

    if STEP_DEBUG:
        print('[CORE] running multi thread mode of emulation ...')
    run_concurrent_emul(duplicate_ECALLs)

    policies.policy_summary()

    if STEP_DEBUG:
        print('[CORE] finishing up the analysis ...')

    sys.exit(0)