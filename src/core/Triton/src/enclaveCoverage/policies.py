from __future__ import print_function
from triton import TritonContext, ARCH, MemoryAccess, CPUSIZE, Instruction, OPCODE, MODE, OPERAND, REG
import threading

MAX_INST_DELAY = 10
BASE_ALLOC = 0x30000000
ERROR_CODE = -400

Triton = None

# report container
is_report_flag = False
reported_msg_txt = ""
reported_item = []

# mapping register presenation of different size to their 64-bit register
RegMap = {
    REG.X86_64.EAX: REG.X86_64.RAX,
    REG.X86_64.AH: REG.X86_64.RAX,
    REG.X86_64.AL: REG.X86_64.RAX,
    REG.X86_64.RAX: REG.X86_64.RAX,
    REG.X86_64.EBX: REG.X86_64.RBX,
    REG.X86_64.BH: REG.X86_64.RBX,
    REG.X86_64.BL: REG.X86_64.RBX,
    REG.X86_64.RBX: REG.X86_64.RBX,
    REG.X86_64.ECX: REG.X86_64.RCX,
    REG.X86_64.CH: REG.X86_64.RCX,
    REG.X86_64.CL: REG.X86_64.RCX,
    REG.X86_64.RCX: REG.X86_64.RCX,
    REG.X86_64.EDX: REG.X86_64.RDX,
    REG.X86_64.DH: REG.X86_64.RDX,
    REG.X86_64.DL: REG.X86_64.RDX,
    REG.X86_64.RDX: REG.X86_64.RDX,
    REG.X86_64.EDI: REG.X86_64.RDI,
    REG.X86_64.RDI: REG.X86_64.RDI,
    REG.X86_64.ESI: REG.X86_64.RSI,
    REG.X86_64.RSI: REG.X86_64.RSI,
    REG.X86_64.ESP: REG.X86_64.RSP,
    REG.X86_64.RSP: REG.X86_64.RSP,
    REG.X86_64.EBP: REG.X86_64.RBP,
    REG.X86_64.RBP: REG.X86_64.RBP
}


class Stack:
    # standard python stack implementation
    def __init__(self):
        self.items = []

    def isEmpty(self):
        return self.items == []

    def push(self, item):
        self.items.append(item)

    def pop(self):
        return self.items.pop()

    def peek(self):
        return self.items[len(self.items) - 1]

    def size(self):
        return len(self.items)


heap_map = dict()
heap_story = dict()
thread_lock_track = dict()
reg_prev_status = dict()
mem_prev_status = dict()
call_stack = dict()

heap_alloc_base = BASE_ALLOC
current_heap_alloc = 0

"""
policy intialize related task
"""


def init_emulator():
    global call_stack
    call_stack[threading.currentThread().ident] = Stack()
    call_stack[threading.currentThread().ident].push(0x0)

    reg_prev_status.clear()
    mem_prev_status.clear()


def exit_emulator():
    global call_stack
    del call_stack[threading.currentThread().ident]


def init_policy_module(triton):
    global Triton
    Triton = triton


def twos_complement(value, bits):
    if value & (1 << (bits - 1)):
        value -= 1 << bits
    return value


"""
thread related task handler for multi-thread mode of emulation
"""


def init_thread_env():
    global thread_lock_track
    thread_lock_track[threading.currentThread().ident] = 0


def destroy_thread_env():
    global thread_lock_track
    del thread_lock_track[threading.currentThread().ident]


def is_thread_unlocked():
    global thread_lock_track
    if thread_lock_track[threading.currentThread().ident] > 0:
        thread_lock_track[threading.currentThread().ident] -= 1
        return False
    return True


def set_thread_locked():
    global thread_lock_track
    thread_lock_track[threading.currentThread().ident] = MAX_INST_DELAY


"""
reporting related task handler
"""


def make_report(msg):
    global is_report_flag, reported_msg_txt
    is_report_flag = True
    reported_msg_txt = msg


def is_vul_reported(item):
    if (not item in reported_item):
        reported_item.append(item)
        return False
    return True


def is_report_avl():
    global is_report_flag
    return is_report_flag


def clear_last_report():
    global is_report_flag, reported_msg_txt
    is_report_flag = False
    reported_msg_txt = ""


def get_reported_msg():
    global reported_msg_txt
    return reported_msg_txt


"""
memory allocation related task handler
"""


def get_allocated_mem_addr():
    global heap_alloc_base, current_heap_alloc
    return heap_alloc_base + current_heap_alloc


def reset_heap_memory():
    global heap_map, current_heap_alloc
    heap_map.clear()
    current_heap_alloc = 0


def update_heap_mem_map(mem_addr, mem_range):
    global heap_map, current_heap_alloc
    heap_map[mem_addr] = mem_range
    current_heap_alloc += mem_range


def remove_mem_entry(mem_addr):
    global heap_map
    del heap_map[mem_addr]


def is_mem_allocated(mem_addr):
    global heap_map
    if (mem_addr in heap_map):
        return True
    return False


def get_mem_range_for_addr(mem_addr):
    global heap_map
    if not mem_addr in heap_map:
        return ERROR_CODE
    return heap_map[mem_addr]


def clear_heap_mem_history():
    global heap_story
    heap_story.clear()


def update_heap_mem_history(mem_addr, mem_range, alloc_addr, free_addr):
    global heap_story
    heap_story[mem_addr] = (alloc_addr, mem_range, free_addr)


def get_heap_mem_alloc_at(mem_addr):
    global heap_story
    if not mem_addr in heap_story:
        return ERROR_CODE
    return heap_story[mem_addr][0]


def get_mem_size_at_addr(mem_addr):
    global heap_story
    if not mem_addr in heap_story:
        return ERROR_CODE
    return heap_story[mem_addr][1]


def get_freed_info_for_addr(mem_addr):
    global heap_story
    if not mem_addr in heap_story:
        return ERROR_CODE
    return heap_story[mem_addr][2]


"""
call stack handler related task
"""


def process_call():
    global call_stack
    ret_addr = Triton.getConcreteMemoryValue(
        MemoryAccess(Triton.getConcreteRegisterValue(Triton.registers.rsp),
                     CPUSIZE.QWORD))
    call_stack[threading.currentThread().ident].push(ret_addr)


def process_ret(ret_addr):
    global call_stack
    if call_stack[threading.currentThread().ident].isEmpty():
        print('[ERROR] policy notice the call stack is empty ... 0x%x' %
              (ret_addr))
    else:
        o_ret_addr = Triton.getConcreteRegisterValue(Triton.registers.rip)
        s_ret_addr = call_stack[threading.currentThread().ident].pop()

        if (o_ret_addr and o_ret_addr != s_ret_addr):
            msg = '[ERROR] policy receives an abnormalities in the call stack\ninstruction processing = ' + hex(
                ret_addr) + '\nreceive by accessing RIP = ' + hex(
                    o_ret_addr) + '\nshadow stack = ' + hex(s_ret_addr) + '\n'
            if (not is_vul_reported(o_ret_addr)):
                make_report(msg)


"""
program status handler related tasks
"""


def update_prog_stats(inst):
    operands = inst.getOperands()
    for operand in operands:
        if operand.getType() == OPERAND.REG:
            if (operand.getId() in RegMap):
                regID = RegMap[operand.getId()]
            else:
                regID = operand.getId()
            reg_prev_status[regID] = twos_complement(
                Triton.getConcreteRegisterValue(operand), operand.getBitSize())
        elif operand.getType() == OPERAND.MEM:
            mem_prev_status[operand.getAddress()] = twos_complement(
                Triton.getConcreteMemoryValue(operand), operand.getBitSize())


"""
policy handler related tasks
"""


def is_heap_overflow(inst, dst_addr, src_addr, cpy_len, inst_addr):
    dst_size = get_mem_range_for_addr(dst_addr)
    if dst_size != ERROR_CODE and dst_size < cpy_len:
        msg = '[HO-REPORT] Potential heap overflow at 0x%x\nDestination 0x%x allocated at 0x%x' % (
            inst_addr, dst_addr, get_heap_mem_alloc_at(dst_addr))
        if (not is_vul_reported(inst_addr)):
            make_report(msg)


def oob_uaf_policy(inst):
    operands = inst.getOperands()
    for operand in operands:
        if operand.getType() == OPERAND.MEM:
            addr_start = operand.getAddress()
            addr_end = addr_start + (operand.getBitSize() / 8)

            if (addr_start >= BASE_ALLOC
                    and addr_end < BASE_ALLOC + current_heap_alloc):
                isFlagged = True
                alloc_start = 0
                alloc_end = 0
                for alloc_mem, alloc_size in heap_map.iteritems():
                    alloc_start = alloc_mem
                    alloc_end = alloc_mem + alloc_size
                    if (addr_start >= alloc_start and addr_start <= alloc_end
                            and addr_end >= alloc_start
                            and addr_end <= alloc_end):
                        isFlagged = False

                if (isFlagged):
                    msg = ""
                    if (addr_start >= alloc_start and addr_start <= alloc_end
                            and addr_end > alloc_end):
                        msg = '[ERROR] Potential Out of Bound (OOB) at ' + hex(
                            inst.getAddress()) + ': ' + inst.getDisassembly(
                        ) + '\nTry to use memory at ' + hex(
                                addr_start) + ' - ' + hex(
                                    addr_end
                        ) + '\nAllocated Memory range is ' + hex(
                                    alloc_start) + ' - ' + hex(
                                        alloc_end) + '\n'
                    else:
                        for st_alloc_mem, st_alloc_info in heap_story.iteritems(
                        ):
                            st_alloc_start = st_alloc_mem
                            st_alloc_end = st_alloc_mem + st_alloc_info[1]
                            if (addr_start >= st_alloc_start
                                    and addr_start <= st_alloc_end
                                    and addr_end >= st_alloc_start
                                    and addr_end <= st_alloc_end):
                                msg = '[UAF-REPORT] Potential Use-after-free (UAF) at ' + hex(
                                    inst.getAddress()
                                ) + ': ' + inst.getDisassembly(
                                ) + '\nTry to use memory at ' + hex(
                                    addr_start) + ' - ' + hex(
                                        addr_end
                                ) + '\nAllocated memory range is ' + hex(
                                        st_alloc_start) + ' - ' + hex(
                                            st_alloc_end
                                ) + '\nAllocated memory at ' + hex(
                                            st_alloc_info[0]
                                ) + ' and Freed at ' + hex(
                                            st_alloc_info[2]) + '\n'
                    if (not is_vul_reported(inst.getAddress())):
                        make_report(msg)


"""
policy inspector
"""


def inspection(inst):
    inst_addr = inst.getAddress()

    if (inst.getType() == OPCODE.X86.CALL):
        process_call()
    elif (inst.getType() == OPCODE.X86.RET):
        process_ret(inst_addr)

    if (inst.getType() == OPCODE.X86.MOV or inst.getType() == OPCODE.X86.MOVSX or inst.getType() == OPCODE.X86.LEA):
        oob_uaf_policy(inst)

    update_prog_stats(inst)


def policy_summary():
    None
