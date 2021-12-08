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
#ifndef SQLITECLIENT_H
#define SQLITECLIENT_H

#include <QObject>
#include <QLinkedList>
#include <sqlite3.h>
#include <string.h>

enum EVENT_TYPE
{
    EVENT_R = 1,
    EVENT_W = 1 << 1,
    EVENT_RW = 1 | (1 << 1),
    EVENT_INS = 1 << 2,
    EVENT_UFO = 1 << 3,
    EVENT_PTR = 1 << 4
};

struct Event
{
    unsigned long long time;
    unsigned long long address;
    unsigned int size;
    long long id[2];
    unsigned nbID;
    EVENT_TYPE type;
};

Q_DECLARE_METATYPE(Event)

class SqliteClient : public QObject
{
    Q_OBJECT
public:
    explicit SqliteClient(QObject *parent = 0);
    ~SqliteClient();
    bool isConnectedToDatabase() { return db != NULL;}

signals:
    void connectionResult(char **database_names);
    void connectedToDatabase();
    void invalidDatabase();
    void metadataResults(char **metadata);
    void statResults(long long *stats);
    // This HAS to be emited in a time sequential way, or else the event list in the memory blocks won't be sorted.
    void receivedEvent(Event ev);
    void receivedEventDescription(const QString &description);
    void dbProcessingFinished();

public slots:
    void connectToDatabase(QString filename);
    void queryMetadata();
    void queryStats();
    void queryEvents();
    void queryEventDescription(Event ev);
    void cleanup();

private:
    sqlite3 *db;

    QString queryInstDescription(unsigned long long id);
    void queryMemoryDumpDescription(Event ev);
};

#endif // SQLITECLIENT_H
