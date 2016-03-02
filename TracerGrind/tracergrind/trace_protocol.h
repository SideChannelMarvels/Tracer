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
#include <stdint.h>

typedef enum _MsgType
{
    MSG_INFO = 0,
    MSG_LIB,
    MSG_EXEC,
    MSG_MEMORY,
    MSG_THREAD
} MsgType;

typedef enum _MemoryMode
{
    MODE_READ = 0,
    MODE_WRITE,
    MODE_INVALID
} MemoryMode;

typedef enum _ThreadMsgType
{
    THREAD_CREATE = 0,
    THREAD_EXIT
} ThreadMsgType;

typedef struct _Msg 
{
    uint8_t type;
    uint64_t length;
    uint8_t *data;
} Msg;

typedef struct _InfoMsg
{
    const char *key;
    const char *value;
} InfoMsg;

typedef struct _LibMsg
{
    uint64_t base;
    uint64_t end;
    const char *name;
} LibMsg;

typedef struct _ExecMsg
{
    uint64_t exec_id;
    uint64_t thread_id;
    uint64_t number;
    uint64_t length;
    uint64_t *addresses;
    uint8_t *lengths;
    uint8_t *code;
} ExecMsg;

typedef struct _MemoryMsg
{
    uint64_t exec_id;
    uint64_t ins_address;
    uint8_t mode;
    uint64_t start_address;
    uint64_t length;
    uint8_t *data;
} MemoryMsg;

typedef struct _ThreadMsg
{
    uint64_t exec_id;
    uint64_t thread_id;
    uint8_t type;
} ThreadMsg;

static const char* STR_TRACERGRIND_VERSION = "TRACERGRIND_VERSION";
static const char* STR_ARCH = "ARCH";
static const char* STR_PROGRAM = "PROGRAM";
static const char* STR_ARGS = "ARGS";
