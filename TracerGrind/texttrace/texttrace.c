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

#include <stdio.h>
#include <string.h>
#include <capstone/capstone.h>
#include "../tracergrind/trace_protocol.h"

#define BUFFER_SIZE 2048

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
    FILE *trace;
    FILE *texttrace;
    if(argc < 3)
    {
        printf("Usage: texttrace <input> <output>\n");
        return 1;
    }
    trace = fopen(argv[1], "rb");
    texttrace = fopen(argv[2], "w");
    if(trace == NULL)
    {
        printf("Could not open file %s for reading\n", argv[1]);
        return 2;
    }
    if(texttrace == NULL)
    {
        printf("Could not open file %s for writing\n", argv[2]);
        return 3;
    }
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
            fprintf(texttrace, "[!] %s: %s\n", key, value);
        }
        else if(msg.type == MSG_LIB)
        {
            LibMsg lmsg;
            char name[BUFFER_SIZE];
            fread((void*)&(lmsg.base), 8, 1, trace);
            fread((void*)&(lmsg.end), 8, 1, trace);
            fget_cstr(name, BUFFER_SIZE, trace);
            fprintf(texttrace, "[L] Loaded %s from 0x%016llx to 0x%016llx\n",
                    name, lmsg.base, lmsg.end);
        }
        else if(msg.type == MSG_EXEC)
        {
            int i;
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
            count = cs_disasm_ex(capstone_handle, code, emsg.length, addresses[0], 0, &insn);
            // Some validation to detect disassembly failure
            if(count != emsg.number)
                printf("Disassembly failure at ExecMsg %d!\n", emsg.exec_id);
            fprintf(texttrace,"[B] EXEC_ID: %lld THREAD_ID: %016llx START_ADDRESS: %016llx END_ADDRESS: %016llx\n",
                    emsg.exec_id, emsg.thread_id, addresses[0], addresses[emsg.number-1]);
            for(i = 0; i < count; i++)
                fprintf(texttrace, "[I] %016llx: %s %s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
            cs_free(insn, count);
            free(code);
            free(addresses);
            free(lengths);
        }
        else if(msg.type == MSG_MEMORY)
        {
            int i;
            uint8_t *data;
            MemoryMsg mmsg;
            fread((void*)&(mmsg.exec_id), 8, 1, trace);
            fread((void*)&(mmsg.ins_address), 8, 1, trace);
            fread((void*)&(mmsg.mode), 1, 1, trace);
            fread((void*)&(mmsg.start_address), 8, 1, trace);
            fread((void*)&(mmsg.length), 8, 1, trace);
            if(mmsg.length != msg.length-42)
            {
                printf("MemoryMsg %d has an invalid code length.\n", mmsg.exec_id);
                exit(1);
            }
            data = (uint8_t*) malloc(mmsg.length);
            fread((void*)data, 1, mmsg.length, trace);
            fprintf(texttrace, "[M] EXEC_ID: %lld INS_ADDRESS: %016llx START_ADDRESS: %016llx LENGTH: %d ",
                    mmsg.exec_id, mmsg.ins_address, mmsg.start_address, mmsg.length);
            if(mmsg.mode == MODE_READ)
                fprintf(texttrace, "MODE: R DATA: ");
            else if(mmsg.mode == MODE_WRITE)
                fprintf(texttrace, "MODE: W DATA: ");
            for(i = 0; i < mmsg.length; i++)
                fprintf(texttrace, "%02hhx", data[i]);
            fprintf(texttrace, "\n");
            free(data);
        }
        else if(msg.type == MSG_THREAD)
        {
            ThreadMsg tmsg;
            fread((void*)&(tmsg.exec_id), 8, 1, trace);
            fread((void*)&(tmsg.thread_id), 8, 1, trace);
            fread((void*)&(tmsg.type), 1, 1, trace);
            fprintf(texttrace, "[T] EXEC_ID: %d THREAD_ID: %016llx TYPE: ", tmsg.exec_id, tmsg.thread_id);
            if(tmsg.type == THREAD_CREATE)
                fprintf(texttrace, "THREAD_CREATE\n");
            else if(tmsg.type == THREAD_EXIT)
                fprintf(texttrace, "THREAD_EXIT\n");
            else
                printf("Invalid thread message type %d encountered.\n", tmsg.type);
        }
        else
        {
            printf("Invalid message of type %d encountered.\n", msg.type);
            exit(1);
        }
    }
    cs_close(&capstone_handle);
    fclose(trace);
    fclose(texttrace);
    return 0;
}
