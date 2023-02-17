#!/usr/bin/env python3

import pyqbdi
import atexit
import os
import sys
import argparse
from dataclasses import dataclass
from MemTracerMarvel import MemTracerMarvelSqlite, MemTracerMarvelText

@dataclass(frozen=True)
class RelocatedAddressRange:

    beginAddr: int
    endAddr: int
    newBaseAddr: int
    comment: object = None
    data: object = None

    def __post_init__(self):
        assert self.beginAddr <= self.endAddr, "Invalid range"

    @property
    def length(self):
        return self.endAddr - self.beginAddr

    def conflict(self, other):
        # conflit for input range
        if self.beginAddr < other.endAddr and other.beginAddr < self.endAddr:
            return True
        # conflit for output
        elif self.newBaseAddr < other.newBaseAddr + other.length and \
                other.newBaseAddr < self.newBaseAddr + self.length:
            return True
        else:
            return False

    def convert(self, addr):
        if self.beginAddr <= addr and addr < self.endAddr:
            return addr - self.beginAddr + self.newBaseAddr
        return None

class MemAccess:

    def __init__(self, tracer, qbdiAccess):
        self.accessAddress = tracer.convertAddr(qbdiAccess.accessAddress)
        self.flags = qbdiAccess.flags
        self.instAddress = tracer.convertAddr(qbdiAccess.instAddress)
        self.size = qbdiAccess.size
        self.type = qbdiAccess.type
        self.value = qbdiAccess.value

class TracerBase:

    def __init__(self, destFile, sqlite=True, traceAllInstruction=False,
                 traceNoInstruction=False, traceRead=True, traceWrite=True,
                 traceBB=False, memoryRange=None, instructionRange=None):
        if sqlite:
            self.traceWriter = MemTracerMarvelSqlite(destFile)
            # needed for the sqlite
            self.traceBB = True
            self.traceNoInstruction = False
        else:
            self.traceWriter = MemTracerMarvelText(destFile)
            self.traceBB = traceBB
            self.traceNoInstruction = traceNoInstruction

        self.traceAllInstruction = traceAllInstruction
        self.memoryRange = memoryRange
        self.instructionRange = instructionRange

        if traceRead and traceWrite:
            self.traceType = pyqbdi.MEMORY_READ_WRITE
        elif traceRead:
            self.traceType = pyqbdi.MEMORY_READ
        elif traceWrite:
            self.traceType = pyqbdi.MEMORY_WRITE
        else:
            self.traceType = None

        self.moveAdressRange = []
        self.defaultBaseAddr = 0x8000000000000000

    def addAddressRange(self, *args, **kwargs):
        newRange = RelocatedAddressRange(*args, **kwargs)

        for r in self.moveAdressRange:
            assert not r.conflict(newRange)

        self.moveAdressRange.append(newRange)

    def convertAddr(self, addr):
        if len(self.moveAdressRange) == 0:
            return addr
        for r in self.moveAdressRange:
            newAddr = r.convert(addr)
            if newAddr is not None:
                return newAddr
        return addr + self.defaultBaseAddr

    # use static method to not specify self as the first argument
    @staticmethod
    def instCBK(vm, gpr, fpr, self):

        inst = vm.getInstAnalysis()
        self.traceWriter.newInstruction(
                self.convertAddr(inst.address), inst.disassembly,
                pyqbdi.readMemory(inst.address, inst.instSize))

        return pyqbdi.CONTINUE

    @staticmethod
    def accessCBK(vm, gpr, fpr, self):

        inst = vm.getInstAnalysis()
        # accessCBK is called for every instruction that produce an access
        # in the target zone
        # TODO: apply self.instructionRange before the instrumentation
        if self.instructionRange is not None:
            inRange = False
            for start, end in self.instructionRange:
                if not (end <= inst.address or inst.address + inst.instSize <= start):
                    inRange = True
                    break
            if not inRange:
                return pyqbdi.CONTINUE

        memaccess = vm.getInstMemoryAccess()
        if memaccess != [] :
            # if we don't trace all the instruction, we need to print the
            # instruction before the access
            if not (self.traceAllInstruction or self.traceNoInstruction):
                self.traceWriter.newInstruction(
                        self.convertAddr(inst.address), inst.disassembly,
                        pyqbdi.readMemory(inst.address, inst.instSize))
            for acc in memaccess:
                self.traceWriter.newMemAccess(MemAccess(self, acc))
        return pyqbdi.CONTINUE

    @staticmethod
    def BBStartEvent(vm, state, gpr, frp, self):

        if self.instructionRange is not None:
            inRange = False
            for start, end in self.instructionRange:
                if not (end <= state.basicBlockStart or state.basicBlockEnd <= start):
                    inRange = True
                    break
            if not inRange:
                return pyqbdi.CONTINUE

        self.traceWriter.newBasicBlock(self.convertAddr(state.basicBlockStart),
                                state.basicBlockEnd - state.basicBlockStart);
        return pyqbdi.CONTINUE


    def applyIntrumentation(self, vm):

        if self.traceAllInstruction:
            if self.instructionRange is None:
                vm.addCodeCB(pyqbdi.PRE_INST, self.instCBK, self, pyqbdi.PRIORITY_MEMACCESS_LIMIT + 100)
            else:
                for start, end in self.instructionRange:
                    vm.addCodeCB(pyqbdi.PRE_INST, self.instCBK, self, pyqbdi.PRIORITY_MEMACCESS_LIMIT + 100)

        if self.traceType is not None:
            if self.memoryRange is None:
                vm.addMemAccessCB(self.traceType, self.accessCBK, self)
            else:
                for start, end in self.memoryRange:
                    vm.addMemRangeCB(start, end, self.traceType, self.accessCBK, self)

        if self.traceBB:
            vm.addVMEventCB(pyqbdi.BASIC_BLOCK_ENTRY, self.BBStartEvent, self)

    def allocateVMAndtrace(self, startAddress, args=[], stacksize = 0x1000000,
                           translateStackAddress=None):

        # Create VM
        vm = pyqbdi.VM()
        stackptr = pyqbdi.allocateVirtualStack(vm.getGPRState(), stacksize)

        if translateStackAddress:
            self.addAddressRange(stackptr, stackptr+stacksize,
                                 translateStackAddress, "[Stack]")

        self.applyIntrumentation(vm)

        atexit.register(self.writeTrace)
        vm.call(startAddress, args)

        atexit.unregister(self.writeTrace)
        self.writeTrace()

        pyqbdi.alignedFree(stackptr)

    def preloadMode(self, vm, start, stop):

        self.applyIntrumentation(vm)

        atexit.register(self.writeTrace)
        vm.run(start, stop)

        atexit.unregister(self.writeTrace)
        self.writeTrace()

    def writeTrace(self):
        self.traceWriter.write()



## preload parse methods

def get_environ_bool(name, default):
    v = os.environ.get(name, None)
    if v is None:
        return default
    vl = v.lower()
    if vl in ["off", "no", "false", "0"]:
        return False
    if vl in ["on", "yes", "true", "1"]:
        return True
    raise ValueError(f'Invalid boolean value "{v}" for environnment variable {name}.'
                     'Expected one of ["OFF", "ON", "True", "False", "0", "1"]')

def convert_range_ptr(value, modifier):
    res = 0
    for m, v in modifier.items():
        if value.startswith(m + "+"):
            res = v
            value = value.split("+", 1)[1]
            break
    res += int(value, base=0)
    return res

def get_environ_range(name, mainRange, stackRange):
    v = os.environ.get(name, None)
    if v is None:
        return None

    l = []
    modifier = {
        "stack": stackRange.range.start,
        "target": mainRange.range.start
    }

    for r in v.split(','):
        if r == "stack":
            l.append((stackRange.range.start, stackRange.range.end))
        elif r == "target":
            l.append((mainRange.range.start, mainRange.range.end))
        else:
            if '_' in r:
                start, end = r.split('_', 1)
            else:
                start, end = r.split('-', 1)
            start = convert_range_ptr(start, modifier)
            end = convert_range_ptr(end, modifier)
            l.append((start, end))
    return l

def getRegionMemoryRange(addr):

    for r in pyqbdi.getCurrentProcessMaps():
        if r.range.start <= addr and addr < r.range.end:
            return r
    return None


## preload main method

def pyqbdipreload_on_run(vm, start, stop):
    traceSqlite = not get_environ_bool("TRACER_TEXT", False)
    if traceSqlite:
        defaultTraceName = "{}.sqlite".format(sys.argv[0])
    else:
        # None is stdout
        defaultTraceName = None
    traceName = os.environ.get("TRACER_OUTPUT", defaultTraceName)
    traceAllInstruction = get_environ_bool("TRACER_ALLINST", False)
    traceNoInstruction = get_environ_bool("TRACER_NOINST", False)
    traceRead = get_environ_bool("TRACER_MEM_READ", True)
    traceWrite = get_environ_bool("TRACER_MEM_WRITE", True)
    traceBB = get_environ_bool("TRACER_BB", False)

    stackRange = getRegionMemoryRange(vm.getGPRState().REG_SP)
    mainRange = getRegionMemoryRange(start)

    memoryRange = get_environ_range("TRACER_FILTER_MEMORY", mainRange, stackRange)
    instructionRange = get_environ_range("TRACER_FILTER_INST", mainRange, stackRange)

    TracerBase(traceName, sqlite=traceSqlite,
               traceAllInstruction=traceAllInstruction,
               traceNoInstruction=traceNoInstruction,
               traceRead=traceRead, traceWrite=traceWrite,
               traceBB=traceBB, memoryRange=memoryRange,
               instructionRange=instructionRange).preloadMode(vm, start, stop)


## preload inject helper

def run():
    parser = argparse.ArgumentParser()

    parser.add_argument('--text', action='store_true', help="Create a human readable trace")
    parser.add_argument('--sqlite', action='store_false', dest="text", help="Create an sqlite trace")
    parser.add_argument('-o', '--output', type=str, help="output file", default=None)

    groupInst = parser.add_mutually_exclusive_group(required=False)
    groupInst.add_argument('--allInst', action='store_true', help="trace all instruction")
    groupInst.add_argument('--noInst', action='store_true', help="don't display instruction (text mode only)")

    parser.add_argument('--traceRead', action='store_true', default=True, help="Trace the read access (default)")
    parser.add_argument('--no-traceRead', action='store_false', dest="traceRead", help="Don't trace the read access")
    parser.add_argument('--traceWrite', action='store_true', default=True, help="Trace the write access (default)")
    parser.add_argument('--no-traceWrite', action='store_false', dest="traceWrite", help="Don't trace the write access")
    parser.add_argument('--traceBB', action='store_true', help="trace the Basic Block (text mode only)")

    parser.add_argument('--filter', type=str, default=None, help="apply a filter on instruction address")
    parser.add_argument('--filter-memory', type=str, default=None, help="apply a filter on access address")

    parser.add_argument("cmd", type=str, help="command with its arguments", nargs='+')

    args = parser.parse_args()

    environ = os.environ.copy()
    environ["TRACER_TEXT"] = str(args.text)

    if args.output is not None:
        environ["TRACER_OUTPUT"] = args.output
    environ["TRACER_ALLINST"] = str(args.allInst)
    environ["TRACER_NOINST"] = str(args.noInst)
    environ["TRACER_MEM_READ"] = str(args.traceRead)
    environ["TRACER_MEM_WRITE"] = str(args.traceWrite)
    environ["TRACER_BB"] = str(args.traceBB)
    if args.filter is not None:
        environ["TRACER_FILTER_INST"] = args.filter
    if args.filter_memory is not None:
        environ["TRACER_FILTER_MEMORY"] = args.filter_memory

    os.execve(sys.executable, [sys.executable, "-m", "pyqbdipreload", os.path.abspath(__file__), "--"] + args.cmd, environ)

    print("Fail execve")
    exit(1)

if __name__ == "__main__" and not pyqbdi.__preload__:
    run()
