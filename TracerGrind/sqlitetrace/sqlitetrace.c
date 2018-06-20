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
#define _FILE_OFFSET_BITS 64 

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <capstone/capstone.h>
#include <sqlite3.h>
#include "../tracergrind/trace_protocol.h"

#define BUFFER_SIZE 2048

static const char *SETUP_QUERY = 
"CREATE TABLE IF NOT EXISTS info (key TEXT PRIMARY KEY, value TEXT);\n"
"CREATE TABLE IF NOT EXISTS lib (name TEXT, base TEXT, end TEXT);\n"
"CREATE TABLE IF NOT EXISTS bbl (addr TEXT, addr_end TEXT, size INTEGER, thread_id INTEGER);\n"
"CREATE TABLE IF NOT EXISTS ins (bbl_id INTEGER, ip TEXT, dis TEXT, op TEXT);\n"
"CREATE TABLE IF NOT EXISTS mem (ins_id INTEGER, ip TEXT, type TEXT, addr TEXT, addr_end TEXT, size INTEGER, data TEXT, value TEXT);\n"
"CREATE TABLE IF NOT EXISTS thread (thread_id INTEGER, start_bbl_id INTEGER, exit_bbl_id INTEGER);\n";

int fget_cstr(char *buffer, int size, FILE *file)
{
    int i;
    char c;
    for(i = 0; i < size-1; i++)
    {
        c = (char)fgetc(file);
        if(c == '\0')
            break;
        buffer[i] = c;
    }
    buffer[i] = '\0';
    return i;
}

int main(int argc, char **argv)
{
    csh capstone_handle;
    cs_arch arch;
    cs_mode mode;
    cs_insn *insn;
    size_t size, count;
    Msg msg;
    int max_events = 128;
    int max_data = 1024;
    MemoryMsg *memory_events_buffer;
    int memory_events_idx = 0;
    char buffer[BUFFER_SIZE];
    FILE *trace;
    sqlite3 *db;
    sqlite3_int64 bbl_id = 0, ins_id = 0;
    sqlite3_stmt *info_insert, *bbl_insert, *lib_insert, *ins_insert, *mem_insert, *thread_insert, *thread_update;

    memory_events_buffer = (MemoryMsg*) malloc(sizeof(MemoryMsg)*max_events);
    if(argc < 3)
    {
        printf("Usage: sqlitetrace trace db\n");
        return 1;
    }
    trace = fopen(argv[1], "rb");
    if(trace == NULL)
    {
        printf("Could not open file %s for reading\n", argv[1]);
        return 2;
    }
    if(sqlite3_open(argv[2], &db) != SQLITE_OK)
    {
        printf("Could not open database %s: %s\n", argv[2], sqlite3_errmsg(db));
        return 3;
    }
    if(sqlite3_exec(db, SETUP_QUERY, NULL, NULL, NULL) != SQLITE_OK)
    {
        printf("Could not setup database: %s\n", sqlite3_errmsg(db));
    }
    sqlite3_prepare_v2(db, "INSERT INTO info (key, value) VALUES (?, ?);", -1, &info_insert, NULL);
    sqlite3_prepare_v2(db, "INSERT INTO lib (name, base, end) VALUES (?, ?, ?);", -1, &lib_insert, NULL);
    sqlite3_prepare_v2(db, "INSERT INTO bbl (addr, addr_end, size, thread_id) VALUES (?, ?, ?, ?);", -1, &bbl_insert, NULL);
    sqlite3_prepare_v2(db, "INSERT INTO ins (bbl_id, ip, dis, op) VALUES (?, ?, ?, ?);", -1, &ins_insert, NULL);
    sqlite3_prepare_v2(db, "INSERT INTO mem (ins_id, ip, type, addr, addr_end, size, data, value) VALUES (?, ?, ?, ?, ?, ?, ?, ?);", -1, &mem_insert, NULL);
    sqlite3_prepare_v2(db, "INSERT INTO thread (thread_id, start_bbl_id) VALUES (?, ?);", -1, &thread_insert, NULL);
    sqlite3_prepare_v2(db, "UPDATE thread SET exit_bbl_id=? WHERE thread_id=?;", -1, &thread_update, NULL);

    sqlite3_exec(db, "BEGIN;", NULL, NULL, NULL);
    while(fread((void*)&(msg.type), 1, 1, trace) != 0)
    {
        fread((void*)&(msg.length), 8, 1, trace);
        if(msg.type == MSG_INFO)
        {
            char key[128], value[BUFFER_SIZE];
            fget_cstr(key, 128, trace);
            fget_cstr(value, BUFFER_SIZE, trace);
            if(strcmp(key, "ARCH") == 0)
            {
                if(strcmp(value, "AMD64") == 0)
                {
                    arch = CS_ARCH_X86;
                    mode = CS_MODE_64;
                }
                else if(strcmp(value, "X86") == 0)
                {
                    arch = CS_ARCH_X86;
                    mode = CS_MODE_32;
                }
                else if(strcmp(value, "ARM64") == 0)
                {
                    arch = CS_ARCH_ARM64;
                    mode = CS_MODE_ARM;
                }
                else if(strcmp(value, "ARM") == 0)
                {
                    arch = CS_ARCH_ARM;
                    mode = CS_MODE_ARM;
                }
                else if(strcmp(value, "PPC64") == 0)
                {   
                    arch = CS_ARCH_PPC;
                    mode = CS_MODE_64; 
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
                    mode =| CS_MODE_BIG_ENDIAN;
#endif
                } 
                else if(strcmp(value, "MIPS32") == 0){
                    arch = CS_ARCH_MIPS;
                    mode = CS_MODE_MIPS32;
                }
                cs_open(arch, mode, &capstone_handle);
            }
            sqlite3_reset(info_insert);
            sqlite3_bind_text(info_insert, 1, key, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(info_insert, 2, value, -1, SQLITE_TRANSIENT);
            if(sqlite3_step(info_insert) != SQLITE_DONE)
                printf("INFO error: %s\n", sqlite3_errmsg(db));
        }
        else if(msg.type == MSG_LIB)
        {
            LibMsg lmsg;
            char name[BUFFER_SIZE];
            fread((void*)&(lmsg.base), 8, 1, trace);
            fread((void*)&(lmsg.end), 8, 1, trace);
            fget_cstr(name, BUFFER_SIZE, trace);
            sqlite3_reset(lib_insert);
            sqlite3_bind_text(lib_insert, 1, name, -1, SQLITE_TRANSIENT);
            snprintf(buffer, BUFFER_SIZE, "0x%016llx", lmsg.base);
            sqlite3_bind_text(lib_insert, 2, buffer, -1, SQLITE_TRANSIENT);
            snprintf(buffer, BUFFER_SIZE, "0x%016llx", lmsg.end);
            sqlite3_bind_text(lib_insert, 3, buffer, -1, SQLITE_TRANSIENT);
            if(sqlite3_step(lib_insert) != SQLITE_DONE)
                printf("LIB error: %s\n", sqlite3_errmsg(db));
        }
        else if(msg.type == MSG_EXEC)
        {
            int i, j, k;
            uint8_t *code, *lengths;
            uint64_t* addresses;
            ExecMsg emsg;

            fread((void*)&(emsg.exec_id), 8, 1, trace);
            fread((void*)&(emsg.thread_id), 8, 1, trace);
            fread((void*)&(emsg.number), 8, 1, trace);
            fread((void*)&(emsg.length), 8, 1, trace);
            if(41 + emsg.number*9 + emsg.length != msg.length)
            {
                printf("Incorrect msg length for ExecMsg %d.\n", emsg.exec_id);
                printf("msg.length: %d emsg.number: %d emsg.length: %d.\n",
                       msg.length, emsg.number, emsg.length);
                exit(1);
            }
            addresses = (uint64_t*) malloc(emsg.number*8);
            lengths = (uint8_t*) malloc(emsg.number);
            code = (uint8_t*) malloc(emsg.length);
            fread((void*)addresses, 8, emsg.number, trace);
            fread((void*)lengths, 1, emsg.number, trace);
            fread((void*)code, 1, emsg.length, trace);
            // Because ARM has special needs
            if(arch == CS_ARCH_ARM)
            {
                // ARM mode switching using the least significant bit of the PC
                if(arch == CS_ARCH_ARM && addresses[0]&1)
                    mode = CS_MODE_THUMB;
                else
                    mode = CS_MODE_ARM;
                // ARM address normalization
                for(i = 0; i < emsg.number; i++)
                    addresses[i] &= 0xFFFFFFFFFFFFFFFE;
                cs_option(capstone_handle, CS_OPT_MODE, mode);
            }
            // Insert BBL
            sqlite3_reset(bbl_insert);
            snprintf(buffer, BUFFER_SIZE, "0x%016llx", addresses[0]);
            sqlite3_bind_text(bbl_insert, 1, buffer, -1, SQLITE_TRANSIENT);
            snprintf(buffer, BUFFER_SIZE, "0x%016llx", addresses[0]+emsg.length-1);
            sqlite3_bind_text(bbl_insert, 2, buffer, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(bbl_insert, 3, emsg.length);
            sqlite3_bind_int64(bbl_insert, 4, emsg.thread_id);
            if(sqlite3_step(bbl_insert) != SQLITE_DONE)
                printf("BBL error: %s\n", sqlite3_errmsg(db));
            bbl_id = sqlite3_last_insert_rowid(db);
            count = cs_disasm_ex(capstone_handle, code, emsg.length, addresses[0], 0, &insn);
            // Some validation to detect disassembly failure
            if(count != emsg.number)
                printf("Disassembly failure at ExecMsg %d!\n", emsg.exec_id);
            for(i = 0; i < count; i++)
            {
                // Insert instruction
                sqlite3_reset(ins_insert);
                sqlite3_bind_int64(ins_insert, 1, bbl_id);
                snprintf(buffer, BUFFER_SIZE, "0x%016llx", addresses[i]);
                sqlite3_bind_text(ins_insert, 2, buffer, -1, SQLITE_TRANSIENT);
                snprintf(buffer, BUFFER_SIZE, "%s %s", insn[i].mnemonic, insn[i].op_str);
                sqlite3_bind_text(ins_insert, 3, buffer, -1, SQLITE_TRANSIENT);
                for(j = 0; j < insn[i].size && j*2+1 < BUFFER_SIZE; j++)
                    snprintf(buffer+j*2, BUFFER_SIZE, "%02hhx", insn[i].bytes[j]);
                sqlite3_bind_text(ins_insert, 4, buffer, -1, SQLITE_TRANSIENT);
                if(sqlite3_step(ins_insert) != SQLITE_DONE)
                    printf("INS error: %s\n", sqlite3_errmsg(db));
                ins_id = sqlite3_last_insert_rowid(db);
                // Find the potential corresponding read and write in the memory events buffer
                for(j = 0; j < memory_events_idx; j++)
                {
                    if(memory_events_buffer[j].ins_address == addresses[i] && 
                       memory_events_buffer[j].mode < MODE_INVALID)
                    {
                        // Insert read or write
                        sqlite3_reset(mem_insert);
                        sqlite3_bind_int64(mem_insert, 1, ins_id);
                        snprintf(buffer, BUFFER_SIZE, "0x%016llx", addresses[i]);
                        sqlite3_bind_text(mem_insert, 2, buffer, -1, SQLITE_TRANSIENT);
                        if(memory_events_buffer[j].mode == MODE_READ)
                            sqlite3_bind_text(mem_insert, 3, "R", -1, SQLITE_TRANSIENT);
                        else if(memory_events_buffer[j].mode == MODE_WRITE)
                            sqlite3_bind_text(mem_insert, 3, "W", -1, SQLITE_TRANSIENT);
                        snprintf(buffer, BUFFER_SIZE, "0x%016llx", memory_events_buffer[j].start_address);
                        sqlite3_bind_text(mem_insert, 4, buffer, -1, SQLITE_TRANSIENT);
                        snprintf(buffer, BUFFER_SIZE, "0x%016llx", memory_events_buffer[j].start_address + 
                                 memory_events_buffer[j].length - 1);
                        sqlite3_bind_text(mem_insert, 5, buffer, -1, SQLITE_TRANSIENT);
                        sqlite3_bind_int(mem_insert, 6, memory_events_buffer[j].length);
                        for(k = 0; k < memory_events_buffer[j].length && k*2+1 < BUFFER_SIZE; k++)
                            snprintf(buffer+k*2, BUFFER_SIZE, "%02hhx", memory_events_buffer[j].data[k]);
                        sqlite3_bind_text(mem_insert, 7, buffer, -1, SQLITE_TRANSIENT);
                        if(memory_events_buffer[j].length == 1)
                            snprintf(buffer, BUFFER_SIZE, "0x%02hhx", *((uint8_t*)memory_events_buffer[j].data));
                        else if(memory_events_buffer[j].length == 2)
                            snprintf(buffer, BUFFER_SIZE, "0x%04hx", *((uint16_t*)memory_events_buffer[j].data));
                        else if(memory_events_buffer[j].length == 4)
                            snprintf(buffer, BUFFER_SIZE, "0x%08x", *((uint32_t*)memory_events_buffer[j].data));
                        else if(memory_events_buffer[j].length == 8)
                            snprintf(buffer, BUFFER_SIZE, "0x%016llx", *((uint64_t*)memory_events_buffer[j].data));
                        sqlite3_bind_text(mem_insert, 8, buffer, -1, SQLITE_TRANSIENT);
                        if(sqlite3_step(mem_insert) != SQLITE_DONE)
                            printf("MEM error: %s\n", sqlite3_errmsg(db));
                        memory_events_buffer[j].mode = MODE_INVALID;
                    }
                }
            }
            // Were all the memory events consumed ?
            j = 0;
            for(i = 0; i < memory_events_idx; i++)
            {
                if(memory_events_buffer[i].mode != MODE_INVALID)
                    j++;
                free(memory_events_buffer[i].data);
            }
            if(j > 0)
                // That's embarassing ...
                printf("%d memory events leaked at EXEC_ID: %d!\n", j, emsg.exec_id);
            memory_events_idx = 0;
            cs_free(insn, count);
            free(addresses);
            free(lengths);
            free(code);
        }
        else if(msg.type == MSG_MEMORY)
        {
            uint8_t *data;
            if(memory_events_idx >= max_events)
            {
                max_events *= 2;
                printf("Increasing size of memory_events_buffer to %d.\n", max_events);
                memory_events_buffer = (MemoryMsg*) realloc(memory_events_buffer, 
                                                            sizeof(MemoryMsg)*max_events);
            }
            MemoryMsg *mmsg = &(memory_events_buffer[memory_events_idx]);
            fread((void*)&(mmsg->exec_id), 8, 1, trace);
            fread((void*)&(mmsg->ins_address), 8, 1, trace);
            fread((void*)&(mmsg->mode), 1, 1, trace);
            fread((void*)&(mmsg->start_address), 8, 1, trace);
            fread((void*)&(mmsg->length), 8, 1, trace);
            if(mmsg->length != msg.length-42)
            {
                printf("MemoryMsg %d has an invalid code length.\n", mmsg->exec_id);
                exit(1);
            }
            mmsg->data = (uint8_t*) malloc(mmsg->length);
            fread((void*)mmsg->data, 1, mmsg->length, trace);
            memory_events_idx++;
        }
        else if(msg.type == MSG_THREAD)
        {
            ThreadMsg tmsg;
            fread((void*)&(tmsg.exec_id), 8, 1, trace);
            fread((void*)&(tmsg.thread_id), 8, 1, trace);
            fread((void*)&(tmsg.type), 1, 1, trace);
            if(tmsg.type == THREAD_CREATE)
            {
                sqlite3_reset(thread_insert);
                sqlite3_bind_int(thread_insert, 1, tmsg.thread_id);
                sqlite3_bind_int64(thread_insert, 2, bbl_id);
                if(sqlite3_step(thread_insert) != SQLITE_DONE)
                    printf("THREAD error: %s\n", sqlite3_errmsg(db));
            }
            else if(tmsg.type == THREAD_EXIT)
            {
                sqlite3_reset(thread_update);
                sqlite3_bind_int64(thread_update, 1, bbl_id);
                sqlite3_bind_int(thread_update, 2, tmsg.thread_id);
                if(sqlite3_step(thread_update) != SQLITE_DONE)
                    printf("THREAD error: %s\n", sqlite3_errmsg(db));
            }
            else
                printf("Invalid thread message type %d encountered.\n", tmsg.type);
        }
         else
        {
            printf("Invalid message of type %d encountered.\n", msg.type);
            return 4;
        }
    }
    sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);
    sqlite3_finalize(info_insert);
    sqlite3_finalize(lib_insert);
    sqlite3_finalize(bbl_insert);
    sqlite3_finalize(ins_insert);
    sqlite3_finalize(mem_insert);
    sqlite3_finalize(thread_insert);
    sqlite3_finalize(thread_update);
    if(sqlite3_close(db) != SQLITE_OK)
    {
        printf("Failed to close db (wut?): %s\n", sqlite3_errmsg(db));
        return 5;
    }
    cs_close(&capstone_handle);
    fclose(trace);
    free(memory_events_buffer);
    return 0;
}
