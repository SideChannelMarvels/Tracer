/* ===================================================================== */
/* This file is part of TraceGraph                                       */
/* TraceGraph is a tool to visually explore execution traces             */
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
#include "mongoclient.h"

MongoClient::MongoClient(QObject *parent) :
    QObject(parent)
{
    mongoc_init();
    client = NULL;
    database = NULL;
    info_collection = NULL;
    bbl_collection = NULL;
    ins_collection = NULL;
    read_collection = NULL;
    write_collection = NULL;
}

MongoClient::~MongoClient()
{

}

void MongoClient::connectToHost(QString host)
{
    bson_error_t error;
    char **names;
    QString uri = "mongodb://" + host;
    if(client != NULL)
    {
        cleanup();
        mongoc_init();
    }
    client = mongoc_client_new(uri.toLocal8Bit().data());
    names = mongoc_client_get_database_names(client, &error);
    if(names)
    {
        emit connectionResult(names);
    }
    else
    {
        client = NULL;
        emit connectionResult(NULL);
    }

}

void MongoClient::connectToDatabase(QString database_name)
{
    database = mongoc_client_get_database(client, database_name.toLocal8Bit().data());
    info_collection = mongoc_database_get_collection(database, "info");
    bbl_collection = mongoc_database_get_collection(database, "bbl");
    ins_collection = mongoc_database_get_collection(database, "ins");
    read_collection = mongoc_database_get_collection(database, "read");
    write_collection = mongoc_database_get_collection(database, "write");
    if(info_collection && bbl_collection && ins_collection && read_collection && write_collection)
        emit connectedToDatabase();
    else
    {
        cleanup();
        emit invalidDatabase();
    }
}

bson_t* MongoClient::keyExistQuery(char *name)
{
    // If only I could compile this ... BCON_NEW("$query", "{", name, "{", "$exists", "true", "}", "}");
    bson_t *query, *key, *exist;
    query = bson_new();
    key = bson_new();
    exist = bson_new();
    bson_append_document_begin(query, "$query", -1, key);
    bson_append_document_begin(key, name, -1, exist);
    bson_append_bool(exist, "$exists", -1, true);
    bson_append_document_end(key, exist);
    bson_append_document_end(query, key);
    bson_destroy(key);
    bson_destroy(exist);
    return query;
}

bson_t* MongoClient::IPQuery(char *address)
{
    bson_t *query, *ip;
    query = bson_new();
    ip = bson_new();
    bson_append_document_begin(query, "$query", -1, ip);
    bson_append_utf8(ip, "ip", -1, address, -1);
    bson_append_document_end(query, ip);
    bson_destroy(ip);
    return query;
}

bson_t* MongoClient::orderByQuery(char *field, int direction)
{
    bson_t *query, *orderby, *empty;
    query = bson_new();
    orderby = bson_new();
    empty = bson_new();
    bson_append_document_begin(query, "$query", -1, empty);
    bson_append_document_end(query, empty);
    bson_append_document_begin(query, "$orderby", -1, orderby);
    bson_append_int32(orderby, field, -1, direction);
    bson_append_document_end(query, orderby);
    bson_destroy(orderby);
    bson_destroy(empty);
    return query;
}

void MongoClient::queryMetadata()
{
    unsigned int length;
    mongoc_cursor_t *cursor;
    bson_t *query;
    const bson_t *doc;
    bson_iter_t iter;
    char **metadata = new char*[4];

    query = keyExistQuery("TRACERGRIND_VERSION");
    cursor = mongoc_collection_find(info_collection, MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);
    if(mongoc_cursor_next(cursor, &doc))
    {
        bson_iter_init(&iter, doc);
        bson_iter_find(&iter, "TRACERGRIND_VERSION");
        const char *value = bson_iter_utf8(&iter, &length);
        metadata[0] = new char[length];
        strcpy(metadata[0], value);
    }
    else
        metadata[0] = NULL;
    mongoc_cursor_destroy(cursor);
    bson_destroy(query);

    query = keyExistQuery("ARCH");
    cursor = mongoc_collection_find(info_collection, MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);
    if(mongoc_cursor_next(cursor, &doc))
    {
        bson_iter_init(&iter, doc);
        bson_iter_find(&iter, "ARCH");
        const char *value = bson_iter_utf8(&iter, &length);
        metadata[1] = new char[length];
        strcpy(metadata[1], value);
    }
    else
        metadata[1] = NULL;
    mongoc_cursor_destroy(cursor);
    bson_destroy(query);

    query = keyExistQuery("PROGRAM");
    cursor = mongoc_collection_find(info_collection, MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);
    if(mongoc_cursor_next(cursor, &doc))
    {
        bson_iter_init(&iter, doc);
        bson_iter_find(&iter, "PROGRAM");
        const char *value = bson_iter_utf8(&iter, &length);
        metadata[2] = new char[length];
        strcpy(metadata[2], value);
    }
    else
        metadata[2] = NULL;
    mongoc_cursor_destroy(cursor);
    bson_destroy(query);

    query = keyExistQuery("ARGS");
    cursor = mongoc_collection_find(info_collection, MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);
    if(mongoc_cursor_next(cursor, &doc))
    {
        bson_iter_init(&iter, doc);
        bson_iter_find(&iter, "ARGS");
        const char *value = bson_iter_utf8(&iter, &length);
        metadata[3] = new char[length];
        strcpy(metadata[3], value);
    }
    else
        metadata[3] = NULL;
    mongoc_cursor_destroy(cursor);
    bson_destroy(query);

    emit metadataResults(metadata);
}

Event MongoClient::parseInsEvent(const bson_t *doc)
{
    Event ev;
    bson_iter_t iter;
    unsigned int lenght;
    bson_iter_init(&iter, doc);
    bson_iter_find(&iter, "_id");
    ev.id = bson_iter_int64(&iter);
    bson_iter_find(&iter, "bbl_id");
    ev.bbl_id = bson_iter_int64(&iter);
    bson_iter_find(&iter, "ip");
    ev.address = strtoul(bson_iter_utf8(&iter, &lenght), NULL, 16);
    bson_iter_find(&iter, "op");
    bson_iter_utf8(&iter, &lenght);
    ev.size = lenght/2;
    ev.type = EVENT_INS;
    return ev;
}

Event MongoClient::parseMemEvent(const bson_t *doc)
{
    Event ev;
    bson_iter_t iter;
    unsigned int lenght;
    bson_iter_init(&iter, doc);
    bson_iter_find(&iter, "_id");
    ev.id = bson_iter_int64(&iter);
    bson_iter_find(&iter, "bbl_id");
    ev.bbl_id = bson_iter_int64(&iter);
    bson_iter_find(&iter, "addr");
    ev.address = strtoul(bson_iter_utf8(&iter, &lenght), NULL, 16);
    bson_iter_find(&iter, "size");
    ev.size = bson_iter_int32(&iter);
    return ev;
}

void MongoClient::queryStats()
{
    long long *stats = new long long[4];
    bson_error_t error;
    bson_t *query = bson_new();
    stats[0] = mongoc_collection_count(bbl_collection, MONGOC_QUERY_NONE, query, 0, 0, NULL, &error);
    stats[1] = mongoc_collection_count(ins_collection, MONGOC_QUERY_NONE, query, 0, 0, NULL, &error);
    stats[2] = mongoc_collection_count(read_collection, MONGOC_QUERY_NONE, query, 0, 0, NULL, &error);
    stats[3] = mongoc_collection_count(write_collection, MONGOC_QUERY_NONE, query, 0, 0, NULL, &error);
    bson_destroy(query);
    emit statResults(stats);
}

void MongoClient::queryEvents()
{
    bson_t *query;
    mongoc_cursor_t *ins_cursor, *read_cursor, *write_cursor;
    const bson_t *ins_doc, *mem_doc;
    unsigned long long time = 0;
    QLinkedList<Event> ins_event, read_event, write_event;
    bool querying = true;

    query = orderByQuery("_id", 1);
    ins_cursor = mongoc_collection_find(ins_collection, MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);
    read_cursor = mongoc_collection_find(read_collection, MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);
    write_cursor = mongoc_collection_find(write_collection, MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);
    while(querying)
    {   
        Event ev;
        // Fill the list with all the instruction from the same bbl
        do
        {
            if(!mongoc_cursor_next(ins_cursor, &ins_doc))
            {
                querying = false;
                break;
            }
            ev = parseInsEvent(ins_doc);
            ev.time = time;
            time++;
            ins_event.push_back(ev);
        }
        while(ins_event.back().bbl_id == ins_event.front().bbl_id);
        // Fill the list with all the read from the same bbl
        do
        {
            if(!mongoc_cursor_next(read_cursor, &mem_doc))
                break;
            ev = parseMemEvent(mem_doc);
            ev.type = EVENT_R;
            read_event.push_back(ev);

        }
        while(read_event.back().bbl_id == ins_event.front().bbl_id);
        // Fill the list with all the write from the same bbl
        do
        {
            if(!mongoc_cursor_next(write_cursor, &mem_doc))
                break;
            ev = parseMemEvent(mem_doc);
            ev.type = EVENT_W;
            write_event.push_back(ev);

        }
        while(write_event.back().bbl_id == ins_event.front().bbl_id);
        // Empty the list. The FIFO treatment allow for the event of the next bbl to carry over.
        unsigned long long cur_bbl_id = ins_event.front().bbl_id;
        while(!ins_event.isEmpty() && ins_event.front().bbl_id == cur_bbl_id)
        {
            if(!read_event.isEmpty() && ins_event.front().id >= read_event.front().id)
            {
                ev = read_event.front();
                ev.time = ins_event.front().time;
                emit receivedEvent(ev);
                read_event.pop_front();
            }
            if(!write_event.isEmpty() && ins_event.front().id >= write_event.front().id)
            {
                ev = write_event.front();
                ev.time = ins_event.front().time;
                emit receivedEvent(ev);
                write_event.pop_front();
            }
            ev = ins_event.front();
            emit receivedEvent(ev);
            ins_event.pop_front();
        }

    }
    mongoc_cursor_destroy(ins_cursor);
    mongoc_cursor_destroy(read_cursor);
    mongoc_cursor_destroy(write_cursor);
    bson_destroy(query);
    emit dbProcessingFinished();
}

void MongoClient::queryEventDescription(Event ev)
{
    bson_t *query, *id_query;
    mongoc_cursor_t *cursor;
    const bson_t *doc;
    bson_iter_t iter;
    QString description;
    unsigned int length;
    // Construct mongo query
    query = bson_new();
    id_query = bson_new();
    bson_append_document_begin(query, "$query", -1, id_query);
    bson_append_int64(id_query, "_id", -1, ev.id);
    bson_append_document_end(query, id_query);
    // Query the right collection
    if(ev.type == EVENT_INS)
        cursor = mongoc_collection_find(ins_collection, MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);
    else if(ev.type == EVENT_R)
        cursor = mongoc_collection_find(read_collection, MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);
    else if(ev.type == EVENT_W)
        cursor = mongoc_collection_find(write_collection, MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);
    else if(ev.type == EVENT_UFO)
        return; // The NSA is onto us.
    else
    {
        description = "Unknown event type.";
        emit receivedEventDescription(description);
        return;
    }
    // Parse the returned event
    if(mongoc_cursor_next(cursor, &doc))
    {
        bson_iter_init(&iter, doc);
        while(bson_iter_next(&iter))
        {
            description += bson_iter_key(&iter);
            description += ": ";
            bson_type_t type = bson_iter_type(&iter);
            if(type == BSON_TYPE_UTF8)
                description += bson_iter_utf8(&iter, &length);
            else if(type == BSON_TYPE_INT32)
                description += QString::number(bson_iter_int32(&iter));
            else if(type == BSON_TYPE_INT64)
                description += QString::number(bson_iter_int64(&iter));
            description += "\n";
        }
    }
    else
        description = "Event not found in DB.";

    emit receivedEventDescription(description);
    mongoc_cursor_destroy(cursor);
    bson_destroy(id_query);
    bson_destroy(query);
}

void MongoClient::cleanup()
{
    if(info_collection) mongoc_collection_destroy(info_collection);
    if(bbl_collection) mongoc_collection_destroy(bbl_collection);
    if(ins_collection) mongoc_collection_destroy(ins_collection);
    if(read_collection) mongoc_collection_destroy(read_collection);
    if(write_collection) mongoc_collection_destroy(write_collection);
    if(database) mongoc_database_destroy(database);
    if(client) mongoc_client_destroy(client);
    client = NULL;
    database = NULL;
    info_collection = NULL;
    bbl_collection = NULL;
    ins_collection = NULL;
    read_collection = NULL;
    write_collection = NULL;
    mongoc_cleanup();
}
