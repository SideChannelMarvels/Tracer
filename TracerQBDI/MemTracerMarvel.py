#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pyqbdi
import os
import shlex
import sqlite3
import struct
import sys

# Generate sqlite database for https://github.com/SideChannelMarvels/Tracer/tree/master/TraceGraph
# need to register each new basicBlock with 'newBasicBlock'
# need to register executed instruction with 'newInstruction' (the instruction will be associated with the last register BasicBlock)
# need to register MemoryAccess with 'newMemAccess' (the memory will be associate with the last register instruction)
# create and export in the database with 'write'

class MemTracerMarvelSqlite:

    def __init__(self, file):
        self.file = file
        self.db = None
        self.cur = None
        self.regions = pyqbdi.getCurrentProcessMaps()

        # BasicBlock (startAddr, size)
        self.bb = []

        # Instruction (BasicBlockId, address, dissas, instruction_bytes)
        self.instruction = []

        # MemAccess (InstId, instAddress, "R"/"W", accessAddress, size, value)
        self.memAccess = []

    def newBasicBlock(self, address, size):
        self.bb.append((address, size))

    def newInstruction(self, address, disas, raw_inst):
        self.instruction.append((len(self.bb), address, disas, raw_inst))

    def newMemAccess(self, memoryAccess):
        assert memoryAccess.instAddress == self.instruction[-1][1]

        if memoryAccess.type & pyqbdi.MEMORY_READ != 0:
            self.memAccess.append((len(self.instruction), memoryAccess.instAddress, "R",
                memoryAccess.accessAddress, memoryAccess.size, memoryAccess.value))

        if memoryAccess.type & pyqbdi.MEMORY_WRITE != 0:
            self.memAccess.append((len(self.instruction), memoryAccess.instAddress, "W",
                memoryAccess.accessAddress, memoryAccess.size, memoryAccess.value))

    def addlibcInst(self, name):
        self.newBasicBlock(0, 1)
        self.newInstruction(0, "libc." + name, b"\x00")

    def accesslibc(self, addr, size, t, data):
        assert t in ["R", "W"]

        self.memAccess.append((len(self.instruction), 0, t, addr, size, data))

    def write(self):
        if os.path.isfile(self.file):
            os.remove(self.file)
        self.db = sqlite3.connect(self.file)
        self.cur = self.db.cursor()

        self.write_info()
        self.write_lib()
        self.write_thread()
        self.write_bbl()
        self.write_ins()
        self.write_mem()

        self.db.commit()

        self.cur.close()
        self.db.close()

    # private method

    def write_info(self):
        infos = [
            ("TRACERGRIND_VERSION", "QBDI " + pyqbdi.__version__),
            ("ARCH", pyqbdi.__arch__),
            ("PROGRAM", sys.argv[0]),
            ("ARGS", shlex.join(sys.argv[1:])),
        ];

        self.cur.execute("CREATE TABLE info (key TEXT PRIMARY KEY, value TEXT);")
        self.cur.executemany('INSERT INTO info VALUES (?,?);', infos)

    def write_lib(self):
        self.cur.execute("CREATE TABLE lib (name TEXT, base TEXT, end TEXT);")
        for r in self.regions:
            self.cur.execute("INSERT INTO lib (name, base, end) VALUES (?, ?, ?);",
                    (r.name, "0x{:016x}".format(r.range.start), "0x{:016x}".format(r.range.end)))

    def write_thread(self):
        self.cur.execute("CREATE TABLE thread (thread_id INTEGER, start_bbl_id INTEGER, exit_bbl_id INTEGER);")
        self.cur.execute("INSERT INTO thread (thread_id, start_bbl_id, exit_bbl_id) VALUES (?, ?, ?);", (0, 0, len(self.bb)))

    def write_bbl(self):
        self.cur.execute("CREATE TABLE bbl (addr TEXT, addr_end TEXT, size INTEGER, thread_id INTEGER);")
        for addr, size in self.bb:
            self.cur.execute("INSERT INTO bbl (addr, addr_end, size, thread_id) VALUES (?, ?, ?, ?);",
                ("0x{:016x}".format(addr), "0x{:016x}".format(addr+size-1), size, 0))

    def write_ins(self):
        self.cur.execute("CREATE TABLE ins (bbl_id INTEGER, ip TEXT, dis TEXT, op TEXT);")
        for bbl_id, addr, dissas, b in self.instruction:
            self.cur.execute("INSERT INTO ins (bbl_id, ip, dis, op) VALUES (?, ?, ?, ?);",
                     (bbl_id, "0x{:016x}".format(addr), dissas, b.hex()) )

    def write_mem(self):
        self.cur.execute("CREATE TABLE mem (ins_id INTEGER, ip TEXT, type TEXT, addr TEXT,"
                                           "addr_end TEXT, size INTEGER, data TEXT, value TEXT);")
        for ins_id, inst_addr, t, addr, size, value in self.memAccess:
            mem_raw = b""
            v = value
            if type(value) == bytes:
                mem_raw = value
                v = 0
            else:
                if size == 1:
                    v = "0x{:02x}".format(value)
                    mem_raw = struct.pack("<B", value)
                elif size == 2:
                    v = "0x{:04x}".format(value)
                    mem_raw = struct.pack("<H", value)
                elif size == 4:
                    v = "0x{:08x}".format(value)
                    mem_raw = struct.pack("<I", value)
                elif size == 8:
                    v = "0x{:016x}".format(value)
                    mem_raw = struct.pack("<Q", value)

            self.cur.execute("INSERT INTO mem (ins_id, ip, type, addr, addr_end, size, data, value) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                (ins_id, "0x{:016x}".format(inst_addr), t, "0x{:016x}".format(addr), "0x{:016x}".format(addr+size-1),
                    size, mem_raw.hex(), v))

class MemTracerMarvelText:

    def __init__(self, file=None):
        if file is not None:
            self.file = open(file, "w")
        else:
            self.file = None
        for r in pyqbdi.getCurrentProcessMaps(True):
            self.print(f"Map [0x{r.range.start:x}, 0x{r.range.end:x}]: {r.name}")

    def print(self, s):
        print(s, file=self.file)

    def newBasicBlock(self, address, size):
        self.print(f"BB address: 0x{address:x}, size: {size}")

    def newInstruction(self, address, disas, raw_inst):
        self.print(f"Inst address: 0x{address:x}, raw: {raw_inst.hex()}, disas: {disas}")

    def newMemAccess(self, memoryAccess):
        if type(memoryAccess.value) == bytes:
            mem_raw = memoryAccess.value
        else:
            mem_raw = memoryAccess.value.to_bytes(memoryAccess.size, 'little')

        if memoryAccess.type & pyqbdi.MEMORY_READ != 0:
            self.print(f"Read instAddress: 0x{memoryAccess.instAddress:x}, accessAddress: 0x{memoryAccess.accessAddress:x}, "
                       f"size: {memoryAccess.size}, value: {mem_raw.hex()}")

        if memoryAccess.type & pyqbdi.MEMORY_WRITE != 0:
            self.print(f"Write instAddress: 0x{memoryAccess.instAddress:x}, accessAddress: 0x{memoryAccess.accessAddress:x}, "
                       f"size: {memoryAccess.size}, value: {mem_raw.hex()}")

    def write(self):
        print("", end="", file=self.file, flush=True)
        if self.file is not None:
            self.file.close()

