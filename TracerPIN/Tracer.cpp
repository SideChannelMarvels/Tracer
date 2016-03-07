/* ===================================================================== */
/* TracerPIN is an execution tracing module for Intel PIN tools          */
/* Copyright (C) 2016                                                    */
/* Original author:   Phil Teuwen <phil@teuwen.org>                      */
/* Contributors:      Charles Hubain <me@haxelion.eu>                    */
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
#include "pin.H"
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <iomanip>
#include <map>
#ifdef MONGOSUPPORT
#include <mongo/bson/bson.h>
#include <mongo/client/dbclient.h>
#include <vector>
#endif //MONGOSUPPORT
#include <sys/time.h>
#ifndef GIT_DESC
#define GIT_DESC "(unknown version)"
#endif //GIT_DESC
using namespace std;
/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

std::ofstream TraceFile;
PIN_LOCK lock;
struct moduledata_t
{
    BOOL excluded;
    ADDRINT begin;
    ADDRINT end;
};

typedef std::map<string, moduledata_t> modmap_t;

modmap_t mod_data;
ADDRINT main_begin;
ADDRINT main_end;
bool main_reached=false;
INT32 picklecount=0;
INT64 logfilter=1;
bool logfilterlive=false;
ADDRINT filter_begin=0;
ADDRINT filter_end=0;
ADDRINT filter_live_start=0;
ADDRINT filter_live_stop=0;
INT32 filter_live_n=0;
INT32 filter_live_i=0;
bool filter_live_reached=false;
long long bigcounter=0; // Ready for 4 billions of instructions
long long currentbbl=0;
enum InfoTypeType { T, C, B, R, I, W };
InfoTypeType InfoType=T;
std::string TraceName;

#ifdef MONGOSUPPORT
enum LogTypeType { HUMAN, PICKLE, MONGO };
mongo::DBClientConnection mongo_c;

#define MONGO_BUFFER_SIZE 2048
struct mongo_buffer {
    string name;
    size_t i;
    std::vector< mongo::BSONObj > *v;
};
struct mongo_buffer mongo_buffer_call;
struct mongo_buffer mongo_buffer_bbl;
struct mongo_buffer mongo_buffer_read;
struct mongo_buffer mongo_buffer_ins;
struct mongo_buffer mongo_buffer_write;

void MongoInsert(struct mongo_buffer *b)
{
    if(b->i != MONGO_BUFFER_SIZE)
        // This should happen only at the end!
        b->v->resize(b->i);
    mongo_c.insert(TraceName+"."+b->name, *(b->v));
    b->i=0;
}
#else //MONGOSUPPORT
enum LogTypeType { HUMAN, PICKLE };
#endif //MONGOSUPPORT
LogTypeType LogType=HUMAN;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
                            "o", "trace-full-info.txt", "specify trace file name");
KNOB<BOOL> KnobLogIns(KNOB_MODE_WRITEONCE, "pintool",
                      "i", "1", "log all instructions");
KNOB<BOOL> KnobLogMem(KNOB_MODE_WRITEONCE, "pintool",
                      "m", "1", "log all memory accesses");
KNOB<BOOL> KnobLogBB(KNOB_MODE_WRITEONCE, "pintool",
                     "b", "1", "log all basic blocks");
KNOB<BOOL> KnobLogCall(KNOB_MODE_WRITEONCE, "pintool",
                       "c", "1", "log all calls");
KNOB<BOOL> KnobLogCallArgs(KNOB_MODE_WRITEONCE, "pintool",
                           "C", "0", "log all calls with their first three args");
KNOB<string> KnobLogFilter(KNOB_MODE_WRITEONCE, "pintool",
                        "f", "1", "(0) no filter (1) filter system libraries (2) filter all but main exec (0x400000-0x410000) trace only specified address range");
KNOB<string> KnobLogFilterLive(KNOB_MODE_WRITEONCE, "pintool",
                        "F", "0", "(0) no live filter (0x400000:0x410000) use addresses as start:stop live filter");
KNOB<INT> KnobLogFilterLiveN(KNOB_MODE_WRITEONCE, "pintool",
                           "n", "0", "which occurence to log, 0=all (only for -F start:stop filter)");
KNOB<INT> KnobCacheIns(KNOB_MODE_WRITEONCE, "pintool",
                        "cache", "0", "(0) default cache size (n) Limit caching to n instructions per trace, useful for SMC (see also -smc_strict 1)");
#ifdef MONGOSUPPORT
KNOB<string> KnobLogType(KNOB_MODE_WRITEONCE, "pintool",
                         "t", "human", "log type: human/pickle/mongo");
#else //MONGOSUPPORT
KNOB<string> KnobLogType(KNOB_MODE_WRITEONCE, "pintool",
                         "t", "human", "log type: human/pickle");
#endif //MONGOSUPPORT

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "Tracer with memory R/W and disass" << endl;
    cerr << "Result by default in trace-full-info.txt" << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary();

    cerr << endl;

    return -1;
}

/* ===================================================================== */
/* Helper Functions                                                      */
/* ===================================================================== */

BOOL ExcludedAddress(ADDRINT ip)
{
    switch (logfilter)
    {
    case 1:
        if (! main_reached)
        {
	        // Filter loader before main
	        if ((ip < main_begin) || (ip > main_end))
	            return TRUE;
            else
                main_reached=true;
		}
        if ((ip >= main_begin) && (ip <= main_end))
            return FALSE;
        for(modmap_t::iterator it = mod_data.begin(); it != mod_data.end(); ++it)
        {
            if(it->second.excluded == FALSE) continue;
            /* Is the EIP value within the range of any excluded module? */
            if(ip >= it->second.begin && ip <= it->second.end) return TRUE;
        }
        break;
    case 2:
    {
        PIN_LockClient();
        IMG im = IMG_FindByAddress(ip);
        PIN_UnlockClient();
        if (! IMG_Valid(im) || ! IMG_IsMainExecutable(im))
            return TRUE;
        break;
    }
    case 3:
        return ((ip < filter_begin) || (ip > filter_end));
        break;
    default:
        break;
    }
    return FALSE;
}

BOOL ExcludedAddressLive(ADDRINT ip)
{
// Always test for (logfilterlive) before calling this function!

//    cerr << hex << ip << "<>" << filter_live_start << dec << endl;
    if (ip == filter_live_start) {
        filter_live_i++;
        if ((filter_live_n == 0) || (filter_live_i == filter_live_n)) filter_live_reached=true;
//        cerr << "BEGIN " << filter_live_i << " @" << hex << filter_live_start << dec << " -> " << filter_live_reached << endl;
    }
    if (ip == filter_live_stop) {
        filter_live_reached=false;
//        cerr << "END   " << filter_live_i << " @" << hex << filter_live_stop << dec << " -> " << filter_live_reached << endl;
    }
    return !filter_live_reached;
}

/* ===================================================================== */
/* Helper Functions for Instruction_cb                                   */
/* ===================================================================== */

VOID pickleAddr(char t, ADDRINT p)
{
    TraceFile << "(S'" << t << "'" << endl;
    TraceFile << "p" << ++picklecount << endl;
    TraceFile << 'I' << dec << p << endl;
    TraceFile << "tp" << ++picklecount << endl;
    TraceFile << "a";
}

VOID printInst(ADDRINT ip, string *disass, INT32 size)
{
    UINT8 value[32];
    // test on logfilterlive here to avoid calls when not using live filtering
    if (logfilterlive && ExcludedAddressLive(ip))
        return;
    if ((size_t)size > sizeof(value))
    {
        cout << "[!] Instruction size > 32 at " << dec << bigcounter << hex << (void *)ip << " " << *disass << endl;
        return;
    }
    PIN_GetLock(&lock, ip);
    if (InfoType >= I) bigcounter++;
    InfoType=I;
    PIN_SafeCopy(value, (void *)ip, size);
    switch (LogType) {
        case HUMAN:
            TraceFile << "[I]" << setw(10) << dec << bigcounter << hex << setw(16) << (void *)ip << "    " << setw(40) << left << *disass << right;
            TraceFile << setfill('0');
            for (INT32 i = 0; i < size; i++)
            {
                TraceFile << " " << setfill('0') << setw(2) << static_cast<UINT32>(value[i]);
            }
            TraceFile << setfill(' ');
            TraceFile << endl;
            break;
        case PICKLE:
            pickleAddr('I', (ADDRINT)ip);
            break;
#ifdef MONGOSUPPORT
        case MONGO:
            mongo::BSONObjBuilder b;
            b.append("_id", bigcounter);
            b.append("bbl_id", currentbbl);
            std::stringstream fmt;
            fmt << hex << "0x" << setfill('0') << setw(16) << ip;
            b.append("ip", fmt.str());
            b.append("dis", *disass);
            std::stringstream fmt2;
            fmt2 << setfill('0') << hex;
            for (INT32 i = 0; i < size; i++)
            {
                fmt2 << setw(2) << static_cast<UINT32>(value[i]);
            }
            b.append("op", fmt2.str());
            mongo_buffer_ins.v->at(mongo_buffer_ins.i++)=b.obj();
            if (mongo_buffer_ins.i == MONGO_BUFFER_SIZE)
                MongoInsert(&mongo_buffer_ins);
            break;
#endif //MONGOSUPPORT
    }
// To get context, see https://software.intel.com/sites/landingpage/pintool/docs/49306/Pin/html/group__CONTEXT__API.html
    PIN_ReleaseLock(&lock);
}

static VOID RecordMemHuman(ADDRINT ip, CHAR r, ADDRINT addr, UINT8* memdump, INT32 size, BOOL isPrefetch)
{
    TraceFile << "[" << r << "]" << setw(10) << dec << bigcounter << hex << setw(16) << (void *) ip << "                                                   "
              << " " << setw(18) << (void *) addr << " size="
              << dec << setw(2) << size << " value="
              << hex << setw(18-2*size);
    if (!isPrefetch)
    {
        switch(size)
        {
        case 0:
            TraceFile << setw(1);
            break;

        case 1:
            TraceFile << "0x" << setfill('0') << setw(2);
            TraceFile << static_cast<UINT32>(*memdump);
            TraceFile << setfill(' ');
            break;

        case 2:
            TraceFile << "0x" << setfill('0') << setw(4);
            TraceFile << *(UINT16*)memdump;
            break;

        case 4:
            TraceFile << "0x" << setfill('0') << setw(8);
            TraceFile << *(UINT32*)memdump;
            break;

        case 8:
            TraceFile << "0x" << setfill('0') << setw(16);
            TraceFile << *(UINT64*)memdump;
            break;

        default:
            for (INT32 i = 0; i < size; i++)
            {
                TraceFile << " " << setfill('0') << setw(2) << static_cast<UINT32>(memdump[i]);
            }
            break;
        }
    }
    TraceFile << setfill(' ') << endl;
}
#ifdef MONGOSUPPORT
static VOID RecordMemMongo(ADDRINT ip, CHAR r, ADDRINT addr, UINT8* memdump, INT32 size, BOOL isPrefetch)
{
    struct mongo_buffer *buffer = (r=='W') ? &mongo_buffer_write : &mongo_buffer_read;
    mongo::BSONObjBuilder b;
    b.append("_id", bigcounter);
    b.append("bbl_id", currentbbl);
    std::stringstream fmt;
    fmt << hex << "0x" << setfill('0') << setw(16) << ip;
    b.append("ip", fmt.str());
    std::stringstream fmt2;
    fmt2 << hex << "0x" << setfill('0') << setw(16) << addr;
    b.append("addr", fmt2.str());
    std::stringstream fmt2b;
    fmt2b << hex << "0x" << setfill('0') << setw(16) << addr + size - 1;
    b.append("addr_end", fmt2b.str());
    b.append("size", size);
    if (!isPrefetch)
    {
        std::stringstream fmt3;
        fmt3 << hex  << "0x" << setfill('0');
        switch(size)
        {
        case 0:
            break;

        case 1:
            fmt3 << setw(2) << static_cast<UINT32>(*memdump);
            b.append("value", fmt3.str());
            break;

        case 2:
            fmt3 << setw(4) << *(UINT16*)memdump;
            b.append("value", fmt3.str());
            break;

        case 4:
            fmt3 << setw(8) << *(UINT32*)memdump;
            b.append("value", fmt3.str());
            break;

        case 8:
            fmt3 << setw(16) << *(UINT64*)memdump;
            b.append("value", fmt3.str());
            break;

        default:
            break;
        }
        std::stringstream fmt4;
        fmt4 << hex << setfill('0');
        for (INT32 i = 0; i < size; i++)
        {
            fmt4 << setw(2) << static_cast<UINT32>(memdump[i]);
        }
        b.append("data", fmt4.str());
    }
    buffer->v->at(buffer->i++)=b.obj();
    if (buffer->i == MONGO_BUFFER_SIZE)
        MongoInsert(buffer);
}
#endif //MONGOSUPPORT
static VOID RecordMem(ADDRINT ip, CHAR r, ADDRINT addr, INT32 size, BOOL isPrefetch)
{
    UINT8 memdump[256];
    // test on logfilterlive here to avoid calls when not using live filtering
    if (logfilterlive && ExcludedAddressLive(ip))
        return;
    PIN_GetLock(&lock, ip);
    if ((size_t)size > sizeof(memdump))
    {
        cout << "[!] Memory size > " << sizeof(memdump) << " at " << dec << bigcounter << hex << (void *)ip << " " << (void *)addr << endl;
        return;
    }
    PIN_SafeCopy(memdump, (void *)addr, size);
    switch (r) {
        case 'R':
            if (InfoType >= R) bigcounter++;
            InfoType=R;
            break;
        case 'W':
            if (InfoType >= W) bigcounter++;
            InfoType=W;
            break;
    }
    switch (LogType) {
        case HUMAN:
            RecordMemHuman(ip, r, addr, memdump, size, isPrefetch);
            break;
        case PICKLE:
            pickleAddr(r, (ADDRINT)addr);
            break;
#ifdef MONGOSUPPORT
        case MONGO:
            RecordMemMongo(ip, r, addr, memdump, size, isPrefetch);
            break;
#endif //MONGOSUPPORT
    }
    PIN_ReleaseLock(&lock);
}

static ADDRINT WriteAddr;
static INT32 WriteSize;

static VOID RecordWriteAddrSize(ADDRINT addr, INT32 size)
{
    WriteAddr = addr;
    WriteSize = size;
}


static VOID RecordMemWrite(ADDRINT ip)
{
    RecordMem(ip, 'W', WriteAddr, WriteSize, false);
}

/* ================================================================================= */
/* This is called for each instruction                                               */
/* ================================================================================= */
VOID Instruction_cb(INS ins, VOID *v)
{
    ADDRINT ceip = INS_Address(ins);
    if(ExcludedAddress(ceip))
        return;

    if (KnobLogMem.Value()) {

        if (INS_IsMemoryRead(ins))
        {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMem,
                IARG_INST_PTR,
                IARG_UINT32, 'R',
                IARG_MEMORYREAD_EA,
                IARG_MEMORYREAD_SIZE,
                IARG_BOOL, INS_IsPrefetch(ins),
                IARG_END);
        }

        if (INS_HasMemoryRead2(ins))
        {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMem,
                IARG_INST_PTR,
                IARG_UINT32, 'R',
                IARG_MEMORYREAD2_EA,
                IARG_MEMORYREAD_SIZE,
                IARG_BOOL, INS_IsPrefetch(ins),
                IARG_END);
        }

        // instruments stores using a predicated call, i.e.
        // the call happens iff the store will be actually executed
        if (INS_IsMemoryWrite(ins))
        {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordWriteAddrSize,
                IARG_MEMORYWRITE_EA,
                IARG_MEMORYWRITE_SIZE,
                IARG_END);

            if (INS_HasFallThrough(ins))
            {
                INS_InsertCall(
                    ins, IPOINT_AFTER, (AFUNPTR)RecordMemWrite,
                    IARG_INST_PTR,
                    IARG_END);
            }
            if (INS_IsBranchOrCall(ins))
            {
                INS_InsertCall(
                    ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)RecordMemWrite,
                    IARG_INST_PTR,
                    IARG_END);
            }

        }
    }
    if (KnobLogIns.Value()) {
        string* disass = new string(INS_Disassemble(ins));
        INS_InsertCall(
            ins, IPOINT_BEFORE, (AFUNPTR)printInst,
            IARG_INST_PTR,
            IARG_PTR, disass,
            IARG_UINT32, INS_Size(ins),
            IARG_END);
    }
}


/* ================================================================================= */
/* This is called every time a MODULE (dll, etc.) is LOADED                          */
/* ================================================================================= */
void ImageLoad_cb(IMG Img, void *v)
{
    std::string imageName = IMG_Name(Img);
    ADDRINT lowAddress = IMG_LowAddress(Img);
    ADDRINT highAddress = IMG_HighAddress(Img);
    bool filtered = false;
    PIN_GetLock(&lock, 0);
    if(IMG_IsMainExecutable(Img))
    {
        switch (LogType) {
            case HUMAN:
                TraceFile << "[-] Analysing main image: " << imageName << endl;
                TraceFile << "[-] Image base: 0x" << hex << lowAddress  << endl;
                TraceFile << "[-] Image end:  0x" << hex << highAddress << endl;
                if (logfilter==2)
                {
                    TraceFile << "[!] Filter all addresses out of that range" << endl;
                }
                break;
            case PICKLE:
                break;
#ifdef MONGOSUPPORT
            case MONGO:
                mongo::BSONObjBuilder b;
                b.append("name", imageName);
                std::stringstream fmtl;
                fmtl << "0x" << hex << setfill('0') << setw(16) << lowAddress;
                b.append("base", fmtl.str());
                std::stringstream fmth;
                fmth << "0x" << hex << setfill('0') << setw(16) << highAddress;
                b.append("end", fmth.str());
                mongo::BSONObj o = b.obj();
                mongo_c.insert(TraceName+".main", o);
                break;
#endif //MONGOSUPPORT
        }
        main_begin = lowAddress;
        main_end = highAddress;
    } else {
        if((logfilter == 1) &&
                ((imageName.compare(0, 10, "C:\\WINDOWS") == 0) ||
                 (imageName.compare(0, 4, "/lib") == 0) ||
                 (imageName.compare(0, 8, "/usr/lib") == 0)))
        {
            filtered = true;
            // Not interested on code within these modules
            mod_data[imageName].excluded = TRUE;
            mod_data[imageName].begin = lowAddress;
            mod_data[imageName].end = highAddress;
        }
        switch (LogType) {
            case HUMAN:
                TraceFile << "[-] Loaded module: " << imageName << endl;
                if (filtered)
                    TraceFile << "[!] Filtered " << imageName << endl;
                TraceFile << "[-] Module base: 0x" << hex << lowAddress  << endl;
                TraceFile << "[-] Module end:  0x" << hex << highAddress << endl;
                break;
            case PICKLE:
                break;
#ifdef MONGOSUPPORT
            case MONGO:
                mongo::BSONObjBuilder b;
                b.genOID();
                b.append("name", imageName);
                std::stringstream fmtl;
                fmtl << "0x" << setfill('0') << setw(16) << hex << lowAddress;
                b.append("base", fmtl.str());
                std::stringstream fmth;
                fmth << "0x" << setfill('0') << setw(16) << hex << highAddress;
                b.append("end", fmth.str());
                mongo::BSONObj o = b.obj();
                mongo_c.insert(TraceName+".lib", o);
                break;
#endif //MONGOSUPPORT
        }
    }
    PIN_ReleaseLock(&lock);
}

/* ===================================================================== */
/* Helper Functions for Trace_cb                                         */
/* ===================================================================== */

void LogBasicBlock(ADDRINT addr, UINT32 size)
{
    PIN_GetLock(&lock, addr);
    if (InfoType >= B) bigcounter++;
    InfoType=B;
    currentbbl=bigcounter;
    switch (LogType) {
        case HUMAN:
            TraceFile << "[B]" << setw(10) << dec << bigcounter << hex << setw(16) << (void *) addr << " loc_" << hex << addr << ":";
            TraceFile << " // size=" << dec << size;
            TraceFile << " thread=" << "0x" << hex << PIN_ThreadUid() << endl;
            break;
        case PICKLE:
            pickleAddr('B', addr);
            break;
#ifdef MONGOSUPPORT
        case MONGO:
            mongo::BSONObjBuilder b;
            b.append("_id", bigcounter);
            std::stringstream fmt;
            fmt << "0x" << hex << setfill('0') << setw(16) << addr;
            b.append("addr", fmt.str());
            std::stringstream fmtb;
            fmtb << hex << "0x" << setfill('0') << setw(16) << addr + size - 1;
            b.append("addr_end", fmtb.str());
            b.append("size", size);
            std::stringstream fmt2;
            fmt2 << "0x" << hex << setfill('0') << setw(16) << PIN_ThreadUid();
            b.append("thread_id", fmt2.str());
            mongo_buffer_bbl.v->at(mongo_buffer_bbl.i++)=b.obj();
            if (mongo_buffer_bbl.i == MONGO_BUFFER_SIZE)
                MongoInsert(&mongo_buffer_bbl);
            break;
#endif //MONGOSUPPORT
    }
    PIN_ReleaseLock(&lock);
}

void LogCallAndArgs(ADDRINT ip, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2)
{
    string nameFunc = "";
    string nameArg0 = "";
    string nameArg1 = "";
    string nameArg2 = "";

    try
    {
        nameFunc = RTN_FindNameByAddress(ip);
        if (KnobLogCallArgs.Value()) {
            nameArg0 = RTN_FindNameByAddress(arg0);
            nameArg1 = RTN_FindNameByAddress(arg1);
            nameArg2 = RTN_FindNameByAddress(arg2);
        }
    }
    catch (int e)
    {
        cout << "[!] Exception when trying to recover call args: " << e << endl;
    }

    PIN_GetLock(&lock, ip);
    if (InfoType >= C) bigcounter++;
    InfoType=C;
    switch (LogType) {
        case HUMAN:
            TraceFile << "[C]" << setw(10) << dec << bigcounter << hex << " Calling function 0x" << ip << "(" << nameFunc << ")";
            if (KnobLogCallArgs.Value()) {
                TraceFile << " with args: ("
                          << (void *) arg0 << " (" << nameArg0 << " ), "
                          << (void *) arg1 << " (" << nameArg1 << " ), "
                          << (void *) arg2 << " (" << nameArg2 << " )";
            }
            TraceFile << endl;
            if (ExcludedAddress(ip))
            {
                TraceFile << "[!] Function 0x" << ip << " is filtered, no tracing" << endl;
            }
            break;
        case PICKLE:
            pickleAddr('C', ip);
            break;
#ifdef MONGOSUPPORT
        case MONGO:
            mongo::BSONObjBuilder b;
            b.append("_id", bigcounter);
            std::stringstream fmt;
            fmt << "0x" << hex << setfill('0') << setw(16) << ip;
            b.append("addr", fmt.str());
            b.append("name", nameFunc);
//TODO ARGS
            mongo_buffer_call.v->at(mongo_buffer_call.i++)=b.obj();
            if (mongo_buffer_call.i == MONGO_BUFFER_SIZE)
                MongoInsert(&mongo_buffer_call);
            break;
#endif //MONGOSUPPORT
    }
    PIN_ReleaseLock(&lock);
}

void LogIndirectCallAndArgs(ADDRINT target, BOOL taken, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2)
{
    if (!taken)
        return;
    LogCallAndArgs(target, arg0, arg1, arg2);
}

/* ================================================================================= */
/* This is called for each Trace. Traces usually begin at the target of a taken      */
/* branch and end with an unconditional branch, including calls and returns.         */
/* Pin guarantees that a trace is only entered at the top,                           */
/* but it may contain multiple exits.                                                */
/* ================================================================================= */
void Trace_cb(TRACE trace, void *v)
{
    /* Iterate through basic blocks */
    for(BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        INS head = BBL_InsHead(bbl);
        if(ExcludedAddress(INS_Address(head)))
            return;
        /* Instrument function calls? */
        if(KnobLogCall.Value() || KnobLogCallArgs.Value())
        {
            /* ===================================================================================== */
            /* Code to instrument the events at the end of a BBL (execution transfer)                */
            /* Checking for calls, etc.                                                              */
            /* ===================================================================================== */
            INS tail = BBL_InsTail(bbl);

            if(INS_IsCall(tail))
            {
                if(INS_IsDirectBranchOrCall(tail))
                {
                    const ADDRINT target = INS_DirectBranchOrCallTargetAddress(tail);

                    INS_InsertPredicatedCall(
                        tail,
                        IPOINT_BEFORE,
                        AFUNPTR(LogCallAndArgs),            // Function to jump to
                        IARG_ADDRINT,                       // "target"'s type
                        target,                             // Who is called?
                        IARG_FUNCARG_ENTRYPOINT_VALUE,      // Arg_0 value
                        0,
                        IARG_FUNCARG_ENTRYPOINT_VALUE,      // Arg_1 value
                        1,
                        IARG_FUNCARG_ENTRYPOINT_VALUE,      // Arg_2 value
                        2,
                        IARG_END
                    );
                }
                else
                {
                    INS_InsertCall(
                        tail,
                        IPOINT_BEFORE,
                        AFUNPTR(LogIndirectCallAndArgs),
                        IARG_BRANCH_TARGET_ADDR,
                        IARG_BRANCH_TAKEN,
                        IARG_FUNCARG_ENTRYPOINT_VALUE,
                        0,
                        IARG_FUNCARG_ENTRYPOINT_VALUE,
                        1,
                        IARG_FUNCARG_ENTRYPOINT_VALUE,
                        2,
                        IARG_END
                    );
                }
            }
            else
            {
                /* Other forms of execution transfer */
                RTN rtn = TRACE_Rtn(trace);
                // Trace jmp into DLLs (.idata section that is, imports)
                if(RTN_Valid(rtn) && SEC_Name(RTN_Sec(rtn)) == ".idata")
                {
                    INS_InsertCall(
                        tail,
                        IPOINT_BEFORE,
                        AFUNPTR(LogIndirectCallAndArgs),
                        IARG_BRANCH_TARGET_ADDR,
                        IARG_BRANCH_TAKEN,
                        IARG_FUNCARG_ENTRYPOINT_VALUE,
                        0,
                        IARG_FUNCARG_ENTRYPOINT_VALUE,
                        1,
                        IARG_FUNCARG_ENTRYPOINT_VALUE,
                        2,
                        IARG_END
                    );
                }
            }
        }
        /* Instrument at basic block level? */
        if(KnobLogBB.Value())
        {
            /* instrument BBL_InsHead to write "loc_XXXXX", like in IDA Pro */
            INS_InsertCall(head, IPOINT_BEFORE, AFUNPTR(LogBasicBlock), IARG_ADDRINT, BBL_Address(bbl), IARG_UINT32, BBL_Size(bbl), IARG_END);
        }
    }
}

/* ================================================================================= */
/* Log some information related to thread execution                                  */
/* ================================================================================= */
void ThreadStart_cb(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    PIN_GetLock(&lock, threadIndex + 1);
    if (InfoType >= T) bigcounter++;
    InfoType=T;
    switch (LogType) {
        case HUMAN:
            TraceFile << "[T]" << setw(10) << dec << bigcounter << hex << " Thread 0x" << PIN_ThreadUid() << " started. Flags: 0x" << hex << flags << endl;
            break;
        case PICKLE:
            pickleAddr('T', (ADDRINT) threadIndex);
            break;
#ifdef MONGOSUPPORT
        case MONGO:
            mongo::BSONObjBuilder b;
            b.append("_id", bigcounter);
            std::stringstream fmt;
            fmt << "0x" << hex << setfill('0') << setw(16) << PIN_ThreadUid();
            b.append("thread_id", fmt.str());
            std::stringstream fmt2;
            fmt2 << "0x" << hex << setfill('0') << setw(8) << flags;
            b.append("entry_flags", fmt2.str());
            mongo::BSONObj o = b.obj();
            mongo_c.insert(TraceName+".thread", o);
            break;
#endif //MONGOSUPPORT
    }
    PIN_ReleaseLock(&lock);
}


void ThreadFinish_cb(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v)
{
    PIN_GetLock(&lock, threadIndex + 1);
    switch (LogType) {
        case HUMAN:
            TraceFile << "[T]" << setw(10) << dec << bigcounter << hex << " Thread 0x" << PIN_ThreadUid() << " finished. Code: " << dec << code << endl;
            break;
        case PICKLE:
            pickleAddr('t', (ADDRINT) threadIndex);
            break;
#ifdef MONGOSUPPORT
        case MONGO:
            mongo::BSONObjBuilder b;
            std::stringstream fmt;
            fmt << "0x" << hex << setfill('0') << setw(16) << PIN_ThreadUid();
            b.append("thread_id", fmt.str());
            mongo::BSONObj q = b.obj();
            mongo::BSONObj o = BSON("$set" << BSON("exit_id" << bigcounter << "exit_code" << code));
            mongo_c.update(TraceName+".thread", q, o);
            break;
#endif //MONGOSUPPORT
    }
    PIN_ReleaseLock(&lock);
}

/* ===================================================================== */
/* Fini                                                                  */
/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{
    switch (LogType) {
        case HUMAN:
            TraceFile.close();
            break;
        case PICKLE:
            TraceFile << "." << endl;
            TraceFile.close();
            break;
#ifdef MONGOSUPPORT
        case MONGO:
            MongoInsert(&mongo_buffer_call);
            MongoInsert(&mongo_buffer_bbl);
            MongoInsert(&mongo_buffer_read);
            MongoInsert(&mongo_buffer_ins);
            MongoInsert(&mongo_buffer_write);
            break;
#endif //MONGOSUPPORT
    }
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int  main(int argc, char *argv[])
{
    PIN_InitSymbols();

    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }

    char *endptr;
    const char *tmpfilter = KnobLogFilter.Value().c_str();
    logfilter=strtoull(tmpfilter, &endptr, 16);
    if (endptr == tmpfilter) {
        cerr << "ERR: Failed parsing option -f" <<endl;
        return 1;
    }
    if ((endptr[0] == '\0') && (logfilter > 2)) {
        cerr << "ERR: Failed parsing option -f" <<endl;
        return 1;
    }
    if (logfilter > 2) {
        filter_begin=logfilter;
        logfilter = 3;
        char *endptr2;
        if (endptr[0] != '-') {
            cerr << "ERR: Failed parsing option -f" <<endl;
            return 1;
        }
        filter_end=strtoull(endptr+1, &endptr2, 16);
        if (endptr2 == endptr+1) {
            cerr << "ERR: Failed parsing option -f" <<endl;
            return 1;
        }
        if (endptr2[0] != '\0') {
            cerr << "ERR: Failed parsing option -f" <<endl;
            return 1;
        }
        if (filter_end <= filter_begin) {
            cerr << "ERR: Failed parsing option -f" <<endl;
            return 1;
        }
    }
    const char *tmpfilterlive = KnobLogFilterLive.Value().c_str();
    INT64 tmpval=strtoull(tmpfilterlive, &endptr, 16);
    if (tmpval != 0) logfilterlive=true;
    if (endptr == tmpfilterlive) {
        cerr << "ERR: Failed parsing option -F" <<endl;
        return 1;
    }
    if ((endptr[0] == '\0') && (logfilterlive)) {
        cerr << "ERR: Failed parsing option -F" <<endl;
        return 1;
    }
    if (tmpval > 0) {
        filter_live_start=tmpval;
        char *endptr2;
        if (endptr[0] != ':') {
            cerr << "ERR: Failed parsing option -F" <<endl;
            return 1;
        }
        filter_live_stop=strtoull(endptr+1, &endptr2, 16);
        if (endptr2 == endptr+1) {
            cerr << "ERR: Failed parsing option -F" <<endl;
            return 1;
        }
        if (endptr2[0] != '\0') {
            cerr << "ERR: Failed parsing option -F" <<endl;
            return 1;
        }
    }
    filter_live_n = KnobLogFilterLiveN.Value();

    // Against very local self-modifying code, you can aggressively invalidate cache by making it small:
    if (KnobCacheIns.Value()) {
        if (CODECACHE_ChangeMaxInsPerTrace(KnobCacheIns.Value()))
            cerr << "Cache size changed to " << KnobCacheIns.Value() << " instructions" << endl;
        else
            cerr << "FAILED changing cache size to " << KnobCacheIns.Value() << " instructions" << endl;
    }

    TraceName = KnobOutputFile.Value();

    if (KnobLogType.Value().compare("human") == 0)
    {
        LogType = HUMAN;
    }
    else if (KnobLogType.Value().compare("pickle") == 0)
    {
        LogType = PICKLE;
        if (TraceName.compare("trace-full-info.txt") == 0)
        {
            TraceName = "trace.pickle";
        }
    }
#ifdef MONGOSUPPORT
    else if (KnobLogType.Value().compare("mongo") == 0)
    {
        LogType = MONGO;
        if (TraceName.compare("trace-full-info.txt") == 0)
        {
            TraceName = "trace_";
            struct timeval tv;
            gettimeofday(&tv, NULL);
            std::stringstream s;
            s << tv.tv_sec;
            TraceName+=s.str();
        }
    }
#endif //MONGOSUPPORT
    switch (LogType) {
        case HUMAN:
        case PICKLE:
            TraceFile.open(TraceName.c_str());
            if(TraceFile == NULL)
            {
                cout << "[!] Something went wrong opening the log file..." << endl;
                return -1;
            } else {
                cout << "[*] Trace file " << TraceName << " opened for writing..." << endl << endl;
            }
            break;
#ifdef MONGOSUPPORT
        case MONGO:
            try {
                mongo_c.connect("localhost");
                cout << "[*] Connected to MongoDB... will use db " << TraceName << endl;
            } catch( mongo::DBException &e ) {
                cout << "[!] Caught " << e.what() << endl;
            }
            break;
#endif //MONGOSUPPORT
    }

    switch (LogType) {
        case HUMAN:
            TraceFile << "#" << endl;
            TraceFile << "# Instruction Trace Generated By Roswell TracerPin " GIT_DESC << endl;
            TraceFile << "#" << endl;
            TraceFile << "[*] Arguments:" << endl;
            for (int nArg=0; nArg < argc; nArg++)
                TraceFile << "[*]" << setw(5) << nArg << ": " << argv[nArg] << endl;
            TraceFile.unsetf(ios::showbase);
            break;
        case PICKLE:
            TraceFile << "(lp0" << endl;
            TraceFile.unsetf(ios::showbase);
            break;
#ifdef MONGOSUPPORT
        case MONGO:
            // If a DB of same name already exists, we drop it
            mongo_c.dropDatabase(TraceName);
			mongo::BSONArrayBuilder bab;
            for (int nArg=0; nArg < argc; nArg++)
                bab.append(argv[nArg]);
            std::stringstream tool;
            tool << "Roswell TracerPin " GIT_DESC " / PIN " << PIN_PRODUCT_VERSION_MAJOR << "." << PIN_PRODUCT_VERSION_MINOR << " build " << PIN_BUILD_NUMBER;
            mongo::BSONObj o = BSON( "created" << mongo::DATENOW << "tool" << tool.str() << "args" << bab.obj());
            mongo_c.insert(TraceName+".trace", o);
			mongo_buffer_call.name="call";
			mongo_buffer_call.i=0;
			mongo_buffer_call.v=new std::vector< mongo::BSONObj > (MONGO_BUFFER_SIZE);
			mongo_buffer_bbl.name="bbl";
			mongo_buffer_bbl.i=0;
			mongo_buffer_bbl.v=new std::vector< mongo::BSONObj > (MONGO_BUFFER_SIZE);
			mongo_buffer_read.name="read";
			mongo_buffer_read.i=0;
			mongo_buffer_read.v=new std::vector< mongo::BSONObj > (MONGO_BUFFER_SIZE);
			mongo_buffer_ins.name="ins";
			mongo_buffer_ins.i=0;
			mongo_buffer_ins.v=new std::vector< mongo::BSONObj > (MONGO_BUFFER_SIZE);
			mongo_buffer_write.name="write";
			mongo_buffer_write.i=0;
			mongo_buffer_write.v=new std::vector< mongo::BSONObj > (MONGO_BUFFER_SIZE);
            break;
#endif //MONGOSUPPORT
    }

    IMG_AddInstrumentFunction(ImageLoad_cb, 0);
    PIN_AddThreadStartFunction(ThreadStart_cb, 0);
    PIN_AddThreadFiniFunction(ThreadFinish_cb, 0);
    TRACE_AddInstrumentFunction(Trace_cb, 0);
    INS_AddInstrumentFunction(Instruction_cb, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns

    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
