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
#ifndef TMGRAPHVIEW_H
#define TMGRAPHVIEW_H

#include <QWidget>
#include <QSize>
#include <QWheelEvent>
#include <QPainter>
#include <QList>
#include <QBrush>
#include <QPen>
#include <QColor>
#include <QGuiApplication>
#include <QDebug>
#include <string.h>
#include "sqliteclient.h"
#include <math.h>

enum ZoomState
{
    NO_ZOOM,
    ZOOM_FORWARD,
    ZOOM_BACKWARD
};

enum TraceState
{
    NO_DB,
    PROCESSING_DB,
    TRACE_READY
};

struct MemoryBlock
{
    unsigned long long address, size, display_address;
    bool start_region;
    QList<Event> events;
};

struct Region
{
    unsigned long long address, size, display_address;
};

class TMGraphView : public QWidget
{
    Q_OBJECT
public:
    explicit TMGraphView(QWidget *parent = 0);
    QSize sizeHint() const;
    QSize minimumSizeHint() const;
    void setSqliteClient(SqliteClient *sqlite_client);
    void displayTrace();
    void timeMove(long long dt);
    void addressMove(long long da);
    void setAddress(unsigned long long view_address);
    void setTime(unsigned long long view_time);
    void zoomToOverview();

signals:
    void positionChange(unsigned long long view_address, unsigned long long view_time);
    void cursorPositionChange(unsigned long long view_address, unsigned long long view_time);
    void eventDescriptionQueried(Event ev);

public slots:
    void onEventReceived(Event ev);
    void onConnectedToDatabase();
    void onDBProcessingFinished();
    void onWindowResize();

private:
    QBrush rbrush, wbrush, rwbrush, ibrush, ptrbrush;
    QPen rpen, wpen, rwpen, ipen, ptrpen;
    SqliteClient *sqlite_client;
    QPainter *painter;
    unsigned long long view_address, view_time;
    unsigned long long total_bytes, total_time;
    double address_zoom_factor, time_zoom_factor;
    unsigned long long size_border;
    QList<MemoryBlock> blocks;
    QList<Region> regions;
    ZoomState zoom_state;
    TraceState trace_state;
    QPoint drag_last_pos, drag_start, zoom_start;

    bool display_ptr_event, draw_ptr_event;
    Event ptr_event;

    void setColor(EVENT_TYPE type);
    void regionProcessing();
    unsigned long long realAddressToDisplayAddress(unsigned long long address);
    unsigned long long displayAddressToRealAddress(unsigned long long address);
    Event findEventAt(const QPoint pos);
    void updateZoomFactors();
    void paintOneEvent(const Event& e, unsigned long windows_addr_size);
    void setPtrEvent(QMouseEvent * event);

protected:
    void wheelEvent(QWheelEvent *event);
    void paintEvent(QPaintEvent *event);
    void keyPressEvent(QKeyEvent * event);
    void mouseMoveEvent(QMouseEvent * event);
    void mousePressEvent(QMouseEvent * event);
    void mouseReleaseEvent(QMouseEvent * event);
};

#endif // TMGRAPHVIEW_H
