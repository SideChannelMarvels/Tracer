#!/usr/bin/env python3

import pyqbdi
import atexit
import os
import sys
from dataclasses import dataclass
from MemTracerMarvel import MemTracerMarvel

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

    def __init__(self, destFile):
        self.traceWriter = MemTracerMarvel()
        self.moveAdressRange = []
        self.defaultBaseAddr = 0x8000000000000000
        self.destFile = destFile

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
    def writeCBK(vm, gpr, fpr, self):

        inst = vm.getInstAnalysis()
        memaccess = vm.getInstMemoryAccess()
        if memaccess != [] :
            self.traceWriter.newInstruction(
                    self.convertAddr(inst.address), inst.disassembly,
                    pyqbdi.readMemory(inst.address, inst.instSize))
            for acc in memaccess:
                self.traceWriter.newMemAccess(MemAccess(self, acc))
        return pyqbdi.CONTINUE

    @staticmethod
    def BBStartEvent(vm, state, gpr, frp, self):

        self.traceWriter.newBasicBlock(self.convertAddr(state.basicBlockStart),
                                state.basicBlockEnd - state.basicBlockStart);
        return pyqbdi.CONTINUE

    def allocateVMAndtrace(self, startAddress, args=[], stacksize = 0x1000000,
                           translateStackAddress=None):

        # Create VM
        vm = pyqbdi.VM()
        stackptr = pyqbdi.allocateVirtualStack(vm.getGPRState(), stacksize)

        if translateStackAddress:
            self.addAddressRange(stackptr, stackptr+stacksize,
                                 translateStackAddress, "[Stack]")


        vm.addMemAccessCB(pyqbdi.MEMORY_READ_WRITE, self.writeCBK, self)
        vm.addVMEventCB(pyqbdi.BASIC_BLOCK_ENTRY, self.BBStartEvent, self)

        atexit.register(self.writeTrace)
        vm.call(startAddress, args)

        atexit.unregister(self.writeTrace)
        self.writeTrace()

        pyqbdi.alignedFree(stackptr)

    def preloadMode(self, vm, start, stop):

        vm.addMemAccessCB(pyqbdi.MEMORY_READ_WRITE, self.writeCBK, self)
        vm.addVMEventCB(pyqbdi.BASIC_BLOCK_ENTRY, self.BBStartEvent, self)

        atexit.register(self.writeTrace)
        vm.run(start, stop)

        atexit.unregister(self.writeTrace)
        self.writeTrace()


    def writeTrace(self):
        self.traceWriter.write(self.destFile)


def pyqbdipreload_on_run(vm, start, stop):
    traceName = os.environ.get("TRACER_OUTPUT", "{}.sqlite".format(sys.argv[0]))
    TracerBase(traceName).preloadMode(vm, start, stop)

