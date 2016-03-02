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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <capstone/capstone.h>
#include "../tracergrind/trace_protocol.h"
#include <bson.h>
#include <bcon.h>
#include <mongoc.h>

#define BUFFER_SIZE 1024
#define MAX_EVENTS 128
#define BULK_SIZE 10000

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
    int buffer_size = 1024;
    MemoryMsg *memory_events_buffer;
    int memory_events_idx = 0;
    uint8_t *memory_data_buffer;
    int memory_data_idx = 0;
    char buffer[128];
    FILE *trace;
    uint64_t mid = 0, bid;
    mongoc_client_t *client;
    mongoc_database_t *database;
    mongoc_collection_t *lib_collection, *info_collection, *bbl_collection, *read_collection,
                        *ins_collection, *write_collection, *thread_collection;
    mongoc_bulk_operation_t *bbl_bulk, *read_bulk, *ins_bulk, *write_bulk;
    int bulk_number = 0;
    mongoc_cursor_t *cursor;
    bson_error_t error;
    bson_t reply;
    bson_t *doc, *query;

    memory_events_buffer = (MemoryMsg*) malloc(sizeof(MemoryMsg)*max_events);
    memory_data_buffer = (uint8_t*) malloc(buffer_size);
    mongoc_init();
    if(argc < 3)
    {
        printf("Usage: mongtrace <input> mongodb://host:port\n");
        return 1;
    }
    trace = fopen(argv[1], "rb");
    if(trace == NULL)
    {
        printf("Could not open file %s for reading\n", argv[1]);
        return 2;
    }
    client = mongoc_client_new(argv[2]);
    snprintf(buffer, 128, "trace_%d", time(NULL));
    database = mongoc_client_get_database (client, buffer);
    printf("Creating database %s\n", buffer);
    bbl_collection = mongoc_database_create_collection(database, "bbl", NULL, &error);
    if(!bbl_collection)
    {
        printf("Could not connect to %s.\n", argv[2]);
        return 3;
    }
    lib_collection = mongoc_database_create_collection(database, "lib", NULL, &error);
    info_collection = mongoc_database_create_collection(database, "info", NULL, &error);
    read_collection = mongoc_database_create_collection(database, "read", NULL, &error);
    ins_collection = mongoc_database_create_collection(database, "ins", NULL, &error);
    write_collection = mongoc_database_create_collection(database, "write", NULL, &error);
    thread_collection = mongoc_database_create_collection(database, "thread", NULL, &error);
    bbl_bulk = mongoc_collection_create_bulk_operation(bbl_collection, true, NULL);
    read_bulk = mongoc_collection_create_bulk_operation(read_collection, true, NULL);
    ins_bulk = mongoc_collection_create_bulk_operation(ins_collection, true, NULL);
    write_bulk = mongoc_collection_create_bulk_operation(write_collection, true, NULL);
    while(fread((void*)&(msg.type), 1, 1, trace) != 0)
    {
        fread((void*)&(msg.length), 8, 1, trace);
        if(msg.type == MSG_INFO)
        {
            char key[128], value[128];
            fget_cstr(key, 128, trace);
            fget_cstr(value, 128, trace);
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
                else if(strcmp(value, "ARM") == 0)
                {
                    arch = CS_ARCH_ARM;
                    mode = CS_MODE_ARM;
                }
                cs_open(arch, mode, &capstone_handle);
            }
            doc = bson_new();
            BSON_APPEND_UTF8(doc, key, value);
            if(!mongoc_collection_insert(info_collection, MONGOC_INSERT_NONE, doc, NULL, &error))
                printf("INFO error: %s\n", error.message);
            bson_destroy(doc);
        }
        else if(msg.type == MSG_LIB)
        {
            LibMsg lmsg;
            char name[128];
            fread((void*)&(lmsg.base), 8, 1, trace);
            fread((void*)&(lmsg.end), 8, 1, trace);
            fget_cstr(name, 128, trace);
            doc = bson_new();
            BSON_APPEND_UTF8(doc, "name", name);
            snprintf(buffer, BUFFER_SIZE, "0x%016llx", lmsg.base);
            BSON_APPEND_UTF8(doc, "base", buffer);
            snprintf(buffer, BUFFER_SIZE, "0x%016llx", lmsg.end);
            BSON_APPEND_UTF8(doc, "end", buffer);
            if(!mongoc_collection_insert(lib_collection, MONGOC_INSERT_NONE, doc, NULL, &error))
                printf("LIB error: %s\n", error.message);
            bson_destroy(doc);
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
            bid = ++mid;
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
            doc = bson_new();
            BSON_APPEND_INT64(doc, "_id", mid);
            snprintf(buffer, 128, "0x%016llx", addresses[0]);
            BSON_APPEND_UTF8(doc, "addr", buffer);
            snprintf(buffer, 128, "0x%016llx", addresses[0]+emsg.length-1);
            BSON_APPEND_UTF8(doc, "addr_end", buffer);
            BSON_APPEND_INT32(doc, "size", emsg.length);
            snprintf(buffer, 128, "0x%016llx", emsg.thread_id);
            BSON_APPEND_UTF8(doc, "thread_id", buffer);
            mongoc_bulk_operation_insert (bbl_bulk, doc);
            bulk_number++;
            bson_destroy(doc);
            count = cs_disasm_ex(capstone_handle, code, emsg.length, addresses[0], 0, &insn);
            // Some validation to detect disassembly failure
            if(count != emsg.number)
                printf("Disassembly failure at ExecMsg %d!\n", emsg.exec_id);
            // the bbl and first instruction share the same id so we have to decrement
            // ... but not if there is no instruction in the bbl because then the next 
            // bbl will have the same id
            if(count > 0)
                mid--; 
            for(i = 0; i < count; i++)
            {
                mid++;
                // Insert instruction
                doc = bson_new();
                BSON_APPEND_INT64(doc, "_id", mid);
                BSON_APPEND_INT64(doc, "bbl_id", bid);
                snprintf(buffer, 128, "0x%016llx", addresses[i]);
                BSON_APPEND_UTF8(doc, "ip", buffer);
                snprintf(buffer, 128, "%s %s", insn[i].mnemonic, insn[i].op_str);
                BSON_APPEND_UTF8(doc, "dis", buffer);
                for(j = 0; j < insn[i].size; j++)
                    snprintf(buffer+j*2, 128, "%02hhx", insn[i].bytes[j]);
                BSON_APPEND_UTF8(doc, "op", buffer);
                mongoc_bulk_operation_insert(ins_bulk, doc);
                bulk_number++;
                bson_destroy(doc);
                // Find the potential corresponding read and write in the memory events buffer
                for(j = 0; j < memory_events_idx; j++)
                {
                    if(memory_events_buffer[j].ins_address == addresses[i] && 
                       memory_events_buffer[j].mode < MODE_INVALID)
                    {
                        // Insert read or write
                        mid++;
                        doc = bson_new();
                        BSON_APPEND_INT64(doc, "_id", mid);
                        BSON_APPEND_INT64(doc, "bbl_id", bid);
                        snprintf(buffer, 128, "0x%016llx", addresses[i]);
                        BSON_APPEND_UTF8(doc, "ip", buffer);
                        snprintf(buffer, 128, "0x%016llx", memory_events_buffer[j].start_address);
                        BSON_APPEND_UTF8(doc, "addr", buffer);
                        snprintf(buffer, 128, "0x%016llx", memory_events_buffer[j].start_address + 
                                 memory_events_buffer[j].length - 1);
                        BSON_APPEND_UTF8(doc, "addr_end", buffer);
                        BSON_APPEND_INT32(doc, "size", memory_events_buffer[j].length);
                        for(k = 0; k < memory_events_buffer[j].length; k++)
                            snprintf(buffer+k*2, 128, "%02hhx", memory_events_buffer[j].data[k]);
                        BSON_APPEND_UTF8(doc, "data", buffer);
                        if(memory_events_buffer[j].length == 1)
                            snprintf(buffer, 128, "0x%02hhx", *((uint8_t*)memory_events_buffer[j].data));
                        else if(memory_events_buffer[j].length == 2)
                            snprintf(buffer, 128, "0x%04hx", *((uint16_t*)memory_events_buffer[j].data));
                        else if(memory_events_buffer[j].length == 4)
                            snprintf(buffer, 128, "0x%08x", *((uint32_t*)memory_events_buffer[j].data));
                        else if(memory_events_buffer[j].length == 8)
                            snprintf(buffer, 128, "0x%016llx", *((uint64_t*)memory_events_buffer[j].data));
                        BSON_APPEND_UTF8(doc, "value", buffer);
                        if(memory_events_buffer[j].mode == MODE_READ)
                        {
                            mongoc_bulk_operation_insert(read_bulk, doc);
                            bulk_number++;
                        }
                        else if(memory_events_buffer[j].mode == MODE_WRITE)
                        {
                            mongoc_bulk_operation_insert(write_bulk, doc);
                            bulk_number++;
                        }
                        //invalidate event
                        memory_events_buffer[j].mode = MODE_INVALID;
                        bson_destroy(doc);
                    }
                }
            }
            // Were all the memory events consumed ?
            j = 0;
            for(i = 0; i < memory_events_idx; i++)
                if(memory_events_buffer[i].mode != MODE_INVALID)
                    j++;
            if(j > 0)
                // That's embarassing ...
                printf("%d memory events leaked at EXEC_ID: %d!\n", j, emsg.exec_id);
            memory_events_idx = 0;
            memory_data_idx = 0;
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
                printf("memory_events_buffer is too small, increasing size to %d.\n", max_events);
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
            if(memory_data_idx + mmsg->length >= buffer_size)
            {
                buffer_size *= 2;
                printf("memory_data_buffer is too small, increasing size to %d.\n", buffer_size);
                memory_data_buffer = (uint8_t*) realloc(memory_data_buffer, buffer_size);
            }
            mmsg->data = &(memory_data_buffer[memory_data_idx]);
            fread((void*)mmsg->data, 1, mmsg->length, trace);
            memory_events_idx++;
            memory_data_idx += mmsg->length;
        }
        else if(msg.type == MSG_THREAD)
        {
            ThreadMsg tmsg;
            fread((void*)&(tmsg.exec_id), 8, 1, trace);
            fread((void*)&(tmsg.thread_id), 8, 1, trace);
            fread((void*)&(tmsg.type), 1, 1, trace);
            if(tmsg.type == THREAD_CREATE)
            {
                doc = bson_new();
                BSON_APPEND_INT64(doc, "_id", mid+1);
                snprintf(buffer, 128, "%016llx", tmsg.thread_id);
                BSON_APPEND_UTF8(doc, "thread_id", buffer);
                // We can't bulk it because we need the doc to be there before the THREAD_EXIT happens
                if(!mongoc_collection_insert(thread_collection, MONGOC_INSERT_NONE, doc, NULL, &error))
                    printf("THREAD error: %s.\n", error.message);
                bson_destroy(doc);
            }
            else if(tmsg.type == THREAD_EXIT)
            {
                // We need to find the already existing doc and update it
                doc = BCON_NEW("$set", "{", "exit_id", BCON_INT64(mid+1), "}");
                query = bson_new();
                snprintf(buffer, 128, "%016llx", tmsg.thread_id);
                BSON_APPEND_UTF8(query, "thread_id", buffer);
                if(!mongoc_collection_update (thread_collection, MONGOC_UPDATE_NONE, query, doc, NULL, &error))
                    printf("THREAD error: %s.\n", error.message);
            }
            else
                printf("Invalid thread message type %d encountered.\n", tmsg.type);
        }
         else
        {
            printf("Invalid message of type %d encountered.\n", msg.type);
            exit(1);
        }
        if(bulk_number > BULK_SIZE)
        {
            if(!mongoc_bulk_operation_execute(bbl_bulk, &reply, &error))
                printf("BBL error: %s\n", error.message);
            if(!mongoc_bulk_operation_execute(ins_bulk, &reply, &error))
                printf("INS error: %s\n", error.message);
            if(!mongoc_bulk_operation_execute(read_bulk, &reply, &error))
                printf("READ error: %s\n", error.message);
            if(!mongoc_bulk_operation_execute(write_bulk, &reply, &error))
                printf("WRITE error: %s\n", error.message);
            mongoc_bulk_operation_destroy(bbl_bulk);
            mongoc_bulk_operation_destroy(ins_bulk);
            mongoc_bulk_operation_destroy(read_bulk);
            mongoc_bulk_operation_destroy(write_bulk);
            bbl_bulk = mongoc_collection_create_bulk_operation(bbl_collection, true, NULL);
            read_bulk = mongoc_collection_create_bulk_operation(read_collection, true, NULL);
            ins_bulk = mongoc_collection_create_bulk_operation(ins_collection, true, NULL);
            write_bulk = mongoc_collection_create_bulk_operation(write_collection, true, NULL);
            bulk_number = 0;
        }
    }
    if(!mongoc_bulk_operation_execute(bbl_bulk, &reply, &error))
        printf("BBL error: %s\n", error.message);
    if(!mongoc_bulk_operation_execute(ins_bulk, &reply, &error))
        printf("INS error: %s\n", error.message);
    if(!mongoc_bulk_operation_execute(read_bulk, &reply, &error))
        printf("READ error: %s\n", error.message);
    if(!mongoc_bulk_operation_execute(write_bulk, &reply, &error))
        printf("WRITE error: %s\n", error.message);
    mongoc_bulk_operation_destroy(bbl_bulk);
    mongoc_bulk_operation_destroy(ins_bulk);
    mongoc_bulk_operation_destroy(read_bulk);
    mongoc_bulk_operation_destroy(write_bulk);
    mongoc_collection_destroy(lib_collection);
    mongoc_collection_destroy(info_collection);
    mongoc_collection_destroy(bbl_collection);
    mongoc_collection_destroy(read_collection);
    mongoc_collection_destroy(ins_collection);
    mongoc_collection_destroy(write_collection);
    mongoc_database_destroy(database);
    mongoc_client_destroy(client);
    mongoc_cleanup();
    cs_close(&capstone_handle);
    fclose(trace);
    free(memory_events_buffer);
    free(memory_data_buffer);
    return 0;
}
