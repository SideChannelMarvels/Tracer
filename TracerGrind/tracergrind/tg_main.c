/* ===================================================================== */
/* This file is part of TracerGrind                                      */
/* TracerGrind is an execution tracing module for Valgrind               */
/* Copyright (C) 2016                                                    */
/* Original author:   Charles Hubain <me@haxelion.eu>                    */
/* Contributors:      Phil Teuwen <phil@teuwen.org>                      */
/*                    Joppe Bos <joppe_bos@hotmail.com>                  */
/*                    Wil Michiels <w.p.a.j.michiels@tue.nl>             */
/*                                                                       */
/* This program is free software: you can redistribute it and/or modify  */
/* it under the terms of the GNU General Public License as published by  */
/* the Free Software Foundation, either version 3 of the License, or     */
/* any later version.                                                    */
/*                                                                       */
/* This program is distributed in the hope that it will be useful,       */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of        */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         */
/* GNU General Public License for more details.                          */
/*                                                                       */
/* You should have received a copy of the GNU General Public License     */
/* along with this program.  If not, see <http://www.gnu.org/licenses/>. */
/* ===================================================================== */
#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_vki.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_debuginfo.h"
#include "pub_tool_options.h"
#include "pub_tool_machine.h"
#include "pub_tool_xarray.h"
#include "pub_tool_clientstate.h"

#include "trace_protocol.h"
#include "version.h"

static uint64_t thread_id = 0;
static uint64_t exec_id = 0;

#define MAX_MEMORY_EVENT 4096
#define MAX_CODE_EVENT 4096
// Assume any instruction on any platform fits in 32 bytes
#define MAX_CODE_SIZE (32 * MAX_CODE_EVENT)
// Assume largest read/write is of 128 bytes
#define MEM_BUFFER_SIZE (128 * MAX_MEMORY_EVENT)
// Largest message header + appropriate storage for events and code
#define MSG_BUFFER_SIZE (42 + 9*MAX_CODE_EVENT + MAX_CODE_SIZE)
#define CODE_BUFFER_SIZE MAX_CODE_SIZE
#define INFO_BUFFER_SIZE 32768
#define MAX_THREAD 2048
#define MAX_FILTER 64

static HChar* trace_output_filename;
static HChar *filter_str;
static HChar *filters_instr[MAX_FILTER];
static HChar *filter_mem_str;
static HChar *filters_mem[MAX_FILTER];
static HChar *filter_bblock_str;
static HChar *filters_bblock[MAX_FILTER];
static Int trace_output_fd = 0;
static Addr filter_instr_start[MAX_FILTER], filter_instr_end[MAX_FILTER];
static Addr filter_mem_start[MAX_FILTER], filter_mem_end[MAX_FILTER];
static Int filter_bblock_start[MAX_FILTER], filter_bblock_end[MAX_FILTER];
static int filter_instr_number = 0;
static int filter_mem_number = 0;
static int filter_bblock_number = 0;
static int trace_instr = 1;
static int trace_mem_read = 1;
static int trace_mem_write = 1;

static int memory_events_idx = 0;
static int memory_buffer_idx = 0;
static uint8_t memory_buffer[MEM_BUFFER_SIZE];
static uint8_t msg_buffer[MSG_BUFFER_SIZE];
static MemoryMsg memory_events[MAX_MEMORY_EVENT];
static int code_buffer_idx = 0;
static int code_event_idx = 0;
static uint64_t address_buffer[MAX_CODE_EVENT];
static uint8_t length_buffer[MAX_CODE_EVENT];
static uint8_t code_buffer[CODE_BUFFER_SIZE];
static uint32_t thread_counter = 0;
static uint64_t thread_ids[MAX_THREAD];

// ---- Trace file format helper functions ----
Bool traceBblock(Int i)
{
    Int        j;
    Bool trace_bblock = False;

    if(filter_bblock_number == 0)
    {
        trace_bblock = True;
    }
    else
    {
        for(j = 0; j < filter_bblock_number; j++)
        {
            if(filter_bblock_start[j] <= i && filter_bblock_end[j] >= i)
            {
                trace_bblock = True;
            }
        }
    }

    return trace_bblock;
}

void sendInfoMsg(UInt fd, InfoMsg *info_msg)
{
    uint8_t type = MSG_INFO;
    uint64_t length = 9; // msg header
    VG_(memcpy)((void*)msg_buffer, &type, 1);
    VG_(strcpy)((HChar*)&(msg_buffer[9]), info_msg->key);
    length += VG_(strlen)(info_msg->key)+1;
    VG_(strcpy)((HChar*)&(msg_buffer[length]), info_msg->value);
    length += VG_(strlen)(info_msg->value)+1;
    VG_(memcpy)((void*)&(msg_buffer[1]), &length, 8);
    VG_(write)(fd, (void*)msg_buffer, length);
}

void sendLibMsg(UInt fd, LibMsg *lib_msg)
{
    uint8_t type = MSG_LIB;
    uint64_t length = 25; // msg header
    length += VG_(strlen)(lib_msg->name)+1;
    VG_(memcpy)((void*)msg_buffer, &type, 1);
    VG_(memcpy)((void*)&(msg_buffer[1]), &length, 8);
    VG_(memcpy)((void*)&(msg_buffer[9]), &(lib_msg->base), 8);
    VG_(memcpy)((void*)&(msg_buffer[17]), &(lib_msg->end), 8);
    VG_(strcpy)((HChar*)&(msg_buffer[25]), lib_msg->name);
    VG_(write)(fd, msg_buffer, length);
}

void sendExecMsg(UInt fd, ExecMsg *exec_msg)
{
    if (traceBblock(exec_msg->exec_id) && trace_instr)
    {
        uint8_t type = MSG_EXEC;
        uint64_t length = 41; // msg header
        length += 9*exec_msg->number + exec_msg->length;
        VG_(memcpy)((void*)msg_buffer, &type, 1);
        VG_(memcpy)((void*)&(msg_buffer[1]), &length, 8);
        VG_(memcpy)((void*)&(msg_buffer[9]), &(exec_msg->exec_id), 8);
        VG_(memcpy)((void*)&(msg_buffer[17]), &(exec_msg->thread_id), 8);
        VG_(memcpy)((void*)&(msg_buffer[25]), &(exec_msg->number), 8);
        VG_(memcpy)((void*)&(msg_buffer[33]), &(exec_msg->length), 8);
        VG_(memcpy)((void*)&(msg_buffer[41]), (void*)exec_msg->addresses, 8*exec_msg->number);
        VG_(memcpy)((void*)&(msg_buffer[41+8*exec_msg->number]), (void*)exec_msg->lengths, exec_msg->number);
        VG_(memcpy)((void*)&(msg_buffer[41+9*exec_msg->number]), (void*)exec_msg->code, exec_msg->length);
        VG_(write)(fd, msg_buffer, length);
    }
}

void sendMemoryMsg(UInt fd, MemoryMsg *memory_msg)
{
    if ((trace_mem_read && (memory_msg->mode == MODE_READ)) || (trace_mem_write && (memory_msg->mode == MODE_WRITE)))
    {
        if (traceBblock(memory_msg->exec_id))
        {
            uint8_t type = MSG_MEMORY;
            uint64_t length = 42; // msg header
            length += memory_msg->length;
            VG_(memcpy)((void*)msg_buffer, &type, 1);
            VG_(memcpy)((void*)&(msg_buffer[1]), &length, 8);
            VG_(memcpy)((void*)&(msg_buffer[9]), &(memory_msg->exec_id), 8);
            VG_(memcpy)((void*)&(msg_buffer[17]), &(memory_msg->ins_address), 8);
            VG_(memcpy)((void*)&(msg_buffer[25]), &(memory_msg->mode), 1);
            VG_(memcpy)((void*)&(msg_buffer[26]), &(memory_msg->start_address), 8);
            VG_(memcpy)((void*)&(msg_buffer[34]), &(memory_msg->length), 8);
            VG_(memcpy)((void*)&(msg_buffer[42]), memory_msg->data, length-42);
            VG_(write)(fd, msg_buffer, length);
        }
    }
}

void sendThreadMsg(UInt fd, ThreadMsg *thread_msg)
{
    uint8_t type = MSG_THREAD;
    uint64_t length = 26; // msg header
    VG_(memcpy)((void*)msg_buffer, &type, 1);
    VG_(memcpy)((void*)&(msg_buffer[1]), &length, 8);
    VG_(memcpy)((void*)&(msg_buffer[9]), &(thread_msg->exec_id), 8);
    VG_(memcpy)((void*)&(msg_buffer[17]), &(thread_msg->thread_id), 8);
    VG_(memcpy)((void*)&(msg_buffer[25]), &(thread_msg->type), 1);
    VG_(write)(fd, msg_buffer, length);
}


// ---- Instrumentation callbacks ----

static void flushMemoryEvents()
{
    int i;
    for(i = 0; i < memory_events_idx; i++)
        sendMemoryMsg(trace_output_fd, &(memory_events[i]));
    memory_events_idx = 0;
    memory_buffer_idx = 0;
}

static void flushCodeEvents()
{
    flushMemoryEvents();
    ExecMsg msg;
    msg.exec_id = exec_id;
    msg.thread_id = thread_id;
    msg.number = code_event_idx;
    msg.length = code_buffer_idx;
    msg.addresses = address_buffer;
    msg.lengths = length_buffer;
    msg.code = code_buffer;
    sendExecMsg(trace_output_fd, &msg);
    exec_id++;
    code_buffer_idx = 0;
    code_event_idx = 0;
}

static VG_REGPARM(3) void instructionCallback(Addr addr, UChar delta, SizeT length)
{
    if(code_event_idx >= MAX_CODE_EVENT ||
       code_buffer_idx + length >= CODE_BUFFER_SIZE ||
       (code_event_idx > 0 &&
       address_buffer[code_event_idx-1]+length_buffer[code_event_idx-1] != addr+delta))
        flushCodeEvents();
    address_buffer[code_event_idx] = addr+delta;
    length_buffer[code_event_idx] = length;
    VG_(memcpy)((void*)&(code_buffer[code_buffer_idx]),(void*)addr, length);
    code_event_idx++;
    code_buffer_idx += length;
}


static void threadCreatedCallback(ThreadId tid, ThreadId child)
{
    ThreadMsg thread_msg;
    thread_counter++;
    thread_msg.exec_id = exec_id;
    thread_msg.type = THREAD_CREATE;
    if(child < MAX_THREAD)
    {
        thread_ids[child] = (thread_counter<<32)|child;
        thread_msg.thread_id = thread_ids[child];
    }
    else
        thread_msg.thread_id = child;
    sendThreadMsg(trace_output_fd, &thread_msg);
}

static void threadExitedCallback(ThreadId tid)
{
    ThreadMsg thread_msg;
    thread_msg.exec_id = exec_id;
    thread_msg.type = THREAD_EXIT;
    if(tid < MAX_THREAD)
        thread_msg.thread_id = thread_ids[tid];
    else
        thread_msg.thread_id = tid;
    sendThreadMsg(trace_output_fd, &thread_msg);
}

static void threadStartedCallback(ThreadId tid, ULong block_dispatched)
{
    if(tid < MAX_THREAD)
        thread_id = thread_ids[tid];
    else
        thread_id = tid;
}

Bool traceMem(Addr a)
{
    Int        j;
    Bool trace_mem = False;

    if(filter_mem_number == 0)
    {
        trace_mem = True;
    }
    else
    {
        for(j = 0; j < filter_mem_number; j++)
        {
            if(filter_mem_start[j] <= a && filter_mem_end[j] >= a)
            {
                trace_mem = True;
            }
        }
    }

    return trace_mem;
}

static VG_REGPARM(3) void readCallback(Addr ins_addr, Addr start_addr, SizeT length)
{
    if(memory_events_idx>=MAX_MEMORY_EVENT ||
       memory_buffer_idx + length >= MEM_BUFFER_SIZE)
        flushMemoryEvents();
    if (traceMem(start_addr))
    {
        MemoryMsg *msg = &(memory_events[memory_events_idx]);
        msg->exec_id = exec_id;
        msg->ins_address = ins_addr;
        msg->mode = MODE_READ;
        msg->start_address = start_addr;
        msg->length = length;
        msg->data = &(memory_buffer[memory_buffer_idx]);
        VG_(memcpy)((void*)&(memory_buffer[memory_buffer_idx]), (void*)start_addr, length);
        memory_events_idx++;
        memory_buffer_idx += length;
    }
}

static VG_REGPARM(3) void writeCallback(Addr ins_addr, Addr start_addr, SizeT length)
{
    if(memory_events_idx>=MAX_MEMORY_EVENT ||
       memory_buffer_idx + length >= MEM_BUFFER_SIZE)
        flushMemoryEvents();
    if (traceMem(start_addr))
    {
        MemoryMsg *msg = &(memory_events[memory_events_idx]);
        msg->exec_id = exec_id;
        msg->ins_address = ins_addr;
        msg->mode = MODE_WRITE;
        msg->start_address = start_addr;
        msg->length = length;
        msg->data = &(memory_buffer[memory_buffer_idx]);
        VG_(memcpy)((void*)&(memory_buffer[memory_buffer_idx]), (void*)start_addr, length);
        memory_events_idx++;
        memory_buffer_idx += length;
    }
}

void trackMemCallback(Addr a, SizeT len, Bool rr, Bool ww, Bool xx, ULong di_handle)
{
    DebugInfo *di = NULL;
    int i;
    while((di = VG_(next_DebugInfo)(di)) != NULL)
    {
        char *filename = VG_(DebugInfo_get_filename)(di);
        char *soname = VG_(DebugInfo_get_soname)(di);
        for(i = 0; i < filter_instr_number; i++)
        {
            if(filters_instr[i] != NULL &&
               ((filename != NULL && VG_(strcmp)(filters_instr[i], filename) == 0) ||
               (soname != NULL && VG_(strcmp)(filters_instr[i], soname) == 0)))
            {
                filter_instr_start[i] = VG_(DebugInfo_get_text_avma)(di);
                filter_instr_end[i] = filter_instr_start[i] + VG_(DebugInfo_get_text_size)(di);
                if (VG_(clo_verbosity) > 0)
                    VG_(umsg)("Filtering %s from 0x%016llx to 0x%016llx\n", filters_instr[i],
                            (Addr64) filter_instr_start[i], (Addr64) filter_instr_end[i]);
                filters_instr[i] = NULL;
            }
        }
    }
}


// ---- Main valgrind plugin functions ----

static void tg_print_usage(void)
{  
    VG_(printf)(
        "    --output=<name>           trace output file name\n"
        "    --filter=<list>           list of comma separated instruction address ranges or binaries to filter (hex, eg 0x1000-0x2000)\n"
        "    --filter-mem=<list>       list of comma separated memory address ranges to filter (hex, eg 0x1000-0x2000)\n"
        "    --filter-bblock=<list>    list of comma separated basic block ranges to filter (dec, eg 1000-2000)\n"
        "    --trace-instr=<yes|no>    trace instructions (default = yes, required for sqlitetrace/tracegraph)\n"
        "    --trace-memread=<yes|no>  trace memory reads (default = yes)\n"
        "    --trace-memwrite=<yes|no> trace memory writes (default = yes)\n"
    );
}

static Bool tg_process_cmd_line_option(const HChar* arg)
{
    if VG_STR_CLO(arg, "--output", trace_output_filename) {}
    else if VG_STR_CLO(arg, "--filter", filter_str)
    {
        int i;
        filters_instr[0] = VG_(strtok)(filter_str, ",");
        for(i = 1; i<MAX_FILTER; i++)
        {
            filters_instr[i] = VG_(strtok)(NULL, ",");
            if(filters_instr[i] == NULL)
                break;
        }
        filter_instr_number = i;
    }
    else if VG_STR_CLO(arg, "--filter-mem", filter_mem_str)
    {
        int i;
        filters_mem[0] = VG_(strtok)(filter_mem_str, ",");
        for(i = 1; i<MAX_FILTER; i++)
        {
            filters_mem[i] = VG_(strtok)(NULL, ",");
            if(filters_mem[i] == NULL)
                break;
        }
        filter_mem_number = i;
    }
    else if VG_STR_CLO(arg, "--filter-bblock", filter_bblock_str)
    {
        int i;
        filters_bblock[0] = VG_(strtok)(filter_bblock_str, ",");
        for(i = 1; i<MAX_FILTER; i++)
        {
            filters_bblock[i] = VG_(strtok)(NULL, ",");
            if(filters_bblock[i] == NULL)
                break;
        }
        filter_bblock_number = i;
    }
    else if VG_BOOL_CLO(arg, "--trace-instr", trace_instr) {}
    else if VG_BOOL_CLO(arg, "--trace-memread", trace_mem_read) {}
    else if VG_BOOL_CLO(arg, "--trace-memwrite", trace_mem_write) {}
    else
        return False;
    return True;
}

static void tg_print_debug_usage(void)
{  
   VG_(printf)(
"    (none)\n"
   );
}

static void tg_post_clo_init(void)
{
    SysRes sres;
    VexArch vex_arch;
    VexArchInfo vex_arch_info;
    InfoMsg msg;
    char* buffer[INFO_BUFFER_SIZE];
    char *start, *end;
    int i;

    if(trace_output_filename == 0)
    {
        tg_print_usage();
        VG_(exit)(1);
    }
    sres = VG_(open)(trace_output_filename, VKI_O_CREAT|VKI_O_TRUNC|VKI_O_WRONLY|VKI_O_LARGEFILE,
                                                VKI_S_IRUSR|VKI_S_IWUSR|VKI_S_IRGRP|VKI_S_IWGRP);
    if(sr_isError(sres))
    {
        VG_(umsg)("Error: cannot create trace file %s\n", trace_output_filename);
        VG_(exit)(2);
    }
    else
    {
        trace_output_fd = sr_Res(sres);
    }
    tl_assert(trace_output_fd);

    for(i = 0; i<MAX_THREAD; i++)
        thread_ids[i] = 0;
    VG_(machine_get_VexArchInfo)(&vex_arch, &vex_arch_info);
    msg.key = STR_TRACERGRIND_VERSION;
    msg.value = VERSION;
    sendInfoMsg(trace_output_fd, &msg);
    msg.key = STR_ARCH;
    msg.value = LibVEX_ppVexArch(vex_arch);
    sendInfoMsg(trace_output_fd, &msg);
    msg.key = STR_PROGRAM;
    msg.value = VG_(args_the_exename);
    sendInfoMsg(trace_output_fd, &msg);
    msg.key = STR_ARGS;
    for(i = 0; i < VG_(sizeXA)(VG_(args_for_client)); i++)
    {
        if(i != 0)
            VG_(strncat)(buffer, " ", INFO_BUFFER_SIZE);
        VG_(strncat)(buffer, *(HChar**)VG_(indexXA)(VG_(args_for_client), i), INFO_BUFFER_SIZE);
    }
    msg.value = buffer;
    sendInfoMsg(trace_output_fd, &msg);
    for(i = 0; i < filter_instr_number; i++)
    {
        start = VG_(strstr)(filters_instr[i], "0x");
        end = VG_(strstr)(filters_instr[i],"-0x");
        if(start != NULL && end != NULL)
        {
            filter_instr_start[i] = VG_(strtoull16)(&(start[2]), NULL);
            filter_instr_end[i] = VG_(strtoull16)(&(end[3]), NULL);
            if (VG_(clo_verbosity) > 0)
                VG_(umsg)("Filtering instruction address range from 0x%016llx to 0x%016llx\n",
                        (Addr64) filter_instr_start[i], (Addr64) filter_instr_end[i]);
            filters_instr[i] = NULL;
        }
    }
    for(i = 0; i < filter_mem_number; i++)
    {
        start = VG_(strstr)(filters_mem[i], "0x");
        end = VG_(strstr)(filters_mem[i],"-0x");
        if(start != NULL && end != NULL)
        {
            filter_mem_start[i] = VG_(strtoull16)(&(start[2]), NULL);
            filter_mem_end[i] = VG_(strtoull16)(&(end[3]), NULL);
            if (VG_(clo_verbosity) > 0)
                VG_(umsg)("Filtering memory address range from 0x%016llx to 0x%016llx\n",
                        (Addr64) filter_mem_start[i], (Addr64) filter_mem_end[i]);
            filters_mem[i] = NULL;
        }
    }
    for(i = 0; i < filter_bblock_number; i++)
    {
        end = VG_(strstr)(filters_bblock[i],"-");
        if(end != NULL)
        {
            filter_bblock_start[i] = VG_(strtoull10)(filters_bblock[i], NULL);
            filter_bblock_end[i] = VG_(strtoull10)(&(end[1]), NULL);
            if (VG_(clo_verbosity) > 0)
                VG_(umsg)("Filtering basic block range from %d to %d\n",
                          filter_bblock_start[i], filter_bblock_end[i]);
            filters_bblock[i] = NULL;
        }
    }
}

static IRSB* tg_instrument(VgCallbackClosure* closure,
                            IRSB* sbIn, 
                            VexGuestLayout* layout, 
                            VexGuestExtents* vge,
                            VexArchInfo* archinfo_host,
                            IRType gWordTy, IRType hWordTy)
{
    IRDirty*   di;
    Int        i, j;
    IRSB*      sbOut;
    IRExpr **argv, *arg1, *arg2, *arg3;
    Addr64 last_addr;
    Bool trace_instr = False;
    if (gWordTy != hWordTy)
    {
        VG_(tool_panic)("host/guest word size mismatch");
    }

    /* Set up SB */
    sbOut = deepCopyIRSBExceptStmts(sbIn);

    // Copy verbatim any IR preamble preceding the first IMark
    i = 0;
    while(i < sbIn->stmts_used && sbIn->stmts[i]->tag != Ist_IMark)
    {
        addStmtToIRSB( sbOut, sbIn->stmts[i] );
        i++;
    }
    if(filter_instr_number == 0)
        trace_instr = True;
    else
        for(j = 0; j < filter_instr_number; j++)
            if(filter_instr_start[j] <= sbIn->stmts[i]->Ist.IMark.addr &&
               filter_instr_end[j] >= sbIn->stmts[i]->Ist.IMark.addr)
                trace_instr = True;
    for(; i < sbIn->stmts_used; i++)
    {
        IRStmt* st = sbIn->stmts[i];
        if(trace_instr == True)
        {
            if(st->tag == Ist_IMark)
            {
                last_addr = st->Ist.IMark.addr;
                arg1 = mkIRExpr_HWord((HWord)st->Ist.IMark.addr);
                arg2 = mkIRExpr_HWord((HWord)st->Ist.IMark.delta);
                arg3 = mkIRExpr_HWord((HWord)st->Ist.IMark.len);
                argv = mkIRExprVec_3(arg1, arg2, arg3);
                di = unsafeIRDirty_0_N(3, "instructionCallback",
                                       VG_(fnptr_to_fnentry)(&instructionCallback),
                                       argv);
                addStmtToIRSB(sbOut, IRStmt_Dirty(di));
            }
            else if(st->tag == Ist_LoadG)
            {
                arg1 = mkIRExpr_HWord((HWord)last_addr);
                if(st->Ist.LoadG.details->cvt == ILGop_Ident32)
                    arg2 = mkIRExpr_HWord((HWord)4);
                else if(st->Ist.LoadG.details->cvt == ILGop_16Uto32 ||
                        st->Ist.LoadG.details->cvt == ILGop_16Sto32)
                    arg2 = mkIRExpr_HWord((HWord)2);
                else if(st->Ist.LoadG.details->cvt == ILGop_8Uto32 ||
                        st->Ist.LoadG.details->cvt == ILGop_8Sto32)
                    arg2 = mkIRExpr_HWord((HWord)1);
                else
                    arg2 = mkIRExpr_HWord((HWord)0);
                argv = mkIRExprVec_3(arg1, st->Ist.LoadG.details->addr, arg2);
                di = unsafeIRDirty_0_N(3, "readCallback",
                                       VG_(fnptr_to_fnentry)(&readCallback),
                                       argv);
                di->guard = st->Ist.LoadG.details->guard;
                addStmtToIRSB(sbOut, IRStmt_Dirty(di));
            }
            else if(st->tag == Ist_LLSC)
            {
                if(st->Ist.LLSC.storedata == NULL)
                {
                    arg1 = mkIRExpr_HWord((HWord)last_addr);
                    arg2 = mkIRExpr_HWord((HWord)sizeofIRType(typeOfIRTemp(sbIn->tyenv, st->Ist.LLSC.result)));
                    argv = mkIRExprVec_3(arg1, st->Ist.LLSC.addr, arg2);
                    di = unsafeIRDirty_0_N(3, "readCallback",
                                           VG_(fnptr_to_fnentry)(&readCallback),
                                           argv);
                    addStmtToIRSB(sbOut, IRStmt_Dirty(di));
                }
            }
            else if(st->tag == Ist_WrTmp)
            {
                if(st->Ist.WrTmp.data->tag == Iex_Load)
                {
                    arg1 = mkIRExpr_HWord((HWord)last_addr);
                    arg2 = mkIRExpr_HWord((HWord)sizeofIRType(st->Ist.WrTmp.data->Iex.Load.ty));
                    argv = mkIRExprVec_3(arg1, st->Ist.WrTmp.data->Iex.Load.addr, arg2);
                    di = unsafeIRDirty_0_N(3, "readCallback",
                                           VG_(fnptr_to_fnentry)(&readCallback),
                                           argv);
                    addStmtToIRSB(sbOut, IRStmt_Dirty(di));
                }
            }
            else if(st->tag == Ist_CAS)
            {
                IRCAS *cas = st->Ist.CAS.details;
                arg1 = mkIRExpr_HWord((HWord)last_addr);
                arg2 = mkIRExpr_HWord((HWord)sizeofIRType(typeOfIRExpr(sbIn->tyenv, cas->dataLo)));
                argv = mkIRExprVec_3(arg1, cas->addr, arg2);
                di = unsafeIRDirty_0_N(3, "readCallback",
                                           VG_(fnptr_to_fnentry)(&readCallback),
                                           argv);
                addStmtToIRSB(sbOut, IRStmt_Dirty(di));
            }
            else if(st->tag == Ist_Dirty && st->Ist.Dirty.details->mFx != Ifx_None)
            {
                VG_(umsg)("Ooops that's a dirty c call ...\n");
            }
        }
        // First executing the instruction then checking what was written
        addStmtToIRSB(sbOut, st);
        if(trace_instr == True)
        {
            if(st->tag == Ist_StoreG)
            {
                arg1 = mkIRExpr_HWord((HWord)last_addr);
                arg2 = mkIRExpr_HWord((HWord)sizeofIRType(typeOfIRExpr(sbIn->tyenv,st->Ist.StoreG.details->data)));
                argv = mkIRExprVec_3(arg1, st->Ist.StoreG.details->addr, arg2);
                di = unsafeIRDirty_0_N(3, "writeCallback",
                                       VG_(fnptr_to_fnentry)(&writeCallback),
                                       argv);
                di->guard = st->Ist.StoreG.details->guard;
                addStmtToIRSB(sbOut, IRStmt_Dirty(di));
            }
            else if(st->tag == Ist_Store)
            {
                arg1 = mkIRExpr_HWord((HWord)last_addr);
                arg2 = mkIRExpr_HWord((HWord)sizeofIRType(typeOfIRExpr(sbIn->tyenv,st->Ist.Store.data)));
                argv = mkIRExprVec_3(arg1, st->Ist.Store.addr, arg2);
                di = unsafeIRDirty_0_N(3, "writeCallback",
                                       VG_(fnptr_to_fnentry)(&writeCallback),
                                       argv);
                addStmtToIRSB(sbOut, IRStmt_Dirty(di));
            }
            else if(st->tag == Ist_LLSC && st->Ist.LLSC.storedata != NULL)
            {
                arg1 = mkIRExpr_HWord((HWord)last_addr);
                arg2 = mkIRExpr_HWord((HWord)sizeofIRType(typeOfIRExpr(sbIn->tyenv, st->Ist.LLSC.storedata)));
                argv = mkIRExprVec_3(arg1, st->Ist.LLSC.addr, arg2);
                di = unsafeIRDirty_0_N(3, "writeCallback",
                                       VG_(fnptr_to_fnentry)(&writeCallback),
                                       argv);
                addStmtToIRSB(sbOut, IRStmt_Dirty(di));
            }
            else if(st->tag == Ist_CAS)
            {
                // We treat it as an unconditional write although it's wrong
                // The write may not have happened and the value might have been the same before
                // But this can be seen in the trace

                IRCAS *cas = st->Ist.CAS.details;
                arg1 = mkIRExpr_HWord((HWord)last_addr);
                arg2 = mkIRExpr_HWord((HWord)sizeofIRType(typeOfIRExpr(sbIn->tyenv, cas->dataLo)));
                argv = mkIRExprVec_3(arg1, cas->addr, arg2);
                di = unsafeIRDirty_0_N(3, "writeCallback",
                                           VG_(fnptr_to_fnentry)(&writeCallback),
                                           argv);
                addStmtToIRSB(sbOut, IRStmt_Dirty(di));
            }
        }
    }
    return sbOut;
}

static void tg_fini(Int exitcode)
{
    DebugInfo *di = NULL;
    LibMsg lib_msg;
    flushCodeEvents();
    while((di = VG_(next_DebugInfo)(di)) != NULL)
    {
        lib_msg.name = VG_(DebugInfo_get_filename)(di);
        lib_msg.base = VG_(DebugInfo_get_text_avma)(di);
        lib_msg.end = lib_msg.base + VG_(DebugInfo_get_text_size)(di);
        sendLibMsg(trace_output_fd, &lib_msg);
    }
    VG_(close)(trace_output_fd);
}

static void tg_pre_clo_init(void)
{
   VG_(details_name)            ("TracerGrind");
   VG_(details_version)         (VERSION);
   VG_(details_description)     ("TracerGrind tracing tool");
   VG_(details_copyright_author)(
      "Charles Hubain");
   VG_(details_bug_reports_to)  (VG_BUGS_TO);
   VG_(details_avg_translation_sizeB) ( 200 );

   VG_(basic_tool_funcs)          (tg_post_clo_init,
                                   tg_instrument,
                                   tg_fini);
   VG_(needs_command_line_options)(tg_process_cmd_line_option,
                                   tg_print_usage,
                                   tg_print_debug_usage);
   VG_(track_pre_thread_ll_create)(threadCreatedCallback);
   VG_(track_start_client_code)(threadStartedCallback);
   VG_(track_pre_thread_ll_exit)(threadExitedCallback);
   VG_(track_new_mem_startup)(trackMemCallback);
   VG_(track_new_mem_mmap)(trackMemCallback);
}

VG_DETERMINE_INTERFACE_VERSION(tg_pre_clo_init)
