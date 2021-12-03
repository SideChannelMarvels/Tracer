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
#include "tmgraphview.h"

template <class T>
const T& min(const T& a, const T& b)
{
    if(a < b)
        return a;
    return b;
}

template <class T>
const T& max(const T& a, const T& b)
{
    if(a > b)
        return a;
    return b;
}



TMGraphView::TMGraphView(QWidget *parent) :
    QWidget(parent)
{
    painter = new QPainter();
    rbrush.setColor(Qt::green);
    rbrush.setStyle(Qt::SolidPattern);
    rpen.setColor(Qt::green);
    wbrush.setColor(Qt::red);
    wbrush.setStyle(Qt::SolidPattern);
    wpen.setColor(Qt::red);
    rwbrush.setColor(Qt::blue);
    rwbrush.setStyle(Qt::SolidPattern);
    rwpen.setColor(Qt::blue);
    ibrush.setColor(Qt::black);
    ibrush.setStyle(Qt::SolidPattern);
    ipen.setColor(Qt::black);
    view_address = 0;
    view_time = 0;
    total_time = 0;
    size_factor = 1;
    size_px = 1;
    address_zoom_factor = 1;
    time_zoom_factor = 1;
    zoom_state = NO_ZOOM;
    trace_state = NO_DB;
    setBackgroundRole(QPalette::Base);
    setAutoFillBackground(true);
    setMouseTracking(true);
    setFocusPolicy(Qt::StrongFocus);
    drag_last_pos.setX(0);
    drag_last_pos.setY(0);
}

QSize TMGraphView::sizeHint() const
{
    return QSize(200, 200);
}

QSize TMGraphView::minimumSizeHint() const
{
    return QSize(200, 200);
}

void TMGraphView::setSqliteClient(SqliteClient *sqlite_client)
{
    this->sqlite_client = sqlite_client;
    connect(sqlite_client, &SqliteClient::receivedEvent, this, &TMGraphView::onEventReceived);
    connect(sqlite_client, &SqliteClient::connectedToDatabase, this, &TMGraphView::onConnectedToDatabase);
    connect(sqlite_client, &SqliteClient::dbProcessingFinished, this, &TMGraphView::onDBProcessingFinished);
}

void TMGraphView::onConnectedToDatabase()
{
    for(QList<MemoryBlock>::iterator block_it = blocks.begin(); block_it != blocks.end(); block_it++)
        block_it->events.clear();
    blocks.clear();
    trace_state = PROCESSING_DB;
    update();
    displayTrace();
}

void TMGraphView::onDBProcessingFinished()
{
    trace_state = TRACE_READY;
    regionProcessing();
    // Automatically show full view upon loading a DB
    zoomToOverview();
    update();
}

void TMGraphView::onEventReceived(Event ev)
{
    QList<MemoryBlock>::iterator block_it = blocks.begin();
    bool block_found = false;
    while(block_it != blocks.end())
    {
        // That event fit in that cute little memory block
        if(ev.address >= block_it->address && ev.address < block_it->address + block_it->size)
        {
            block_found = true;
            break;
        }
        else if(ev.address < block_it->address)
            break; // We went further than the event address without finding a block
        block_it++;
    }
    // We need to create a new memory block for our event
    if(!block_found)
    {
        MemoryBlock bl;
        // We make block of the same size as memory pages on x86
        bl.address = ev.address&0xFFFFFFFFFFFFF000;
        bl.size = 0x1000;
        block_it = blocks.insert(block_it, bl);
    }
    // merge event if an instruction read and write the same address
    if ((ev.type & (EVENT_R | EVENT_W)) != 0) {
        QList<Event>::reverse_iterator event_rit = block_it->events.rbegin();
        bool merge = false;
        while (event_rit != block_it->events.rend() and event_rit->time == ev.time) {
            if ((event_rit->type & (EVENT_R | EVENT_W)) == 0) {
                event_rit++;
                continue;
            }
            if (event_rit->address + event_rit->size <= ev.address) {
                event_rit++;
                continue;
            }
            if (ev.address + ev.size <= event_rit->address) {
                event_rit++;
                continue;
            }
            // the two event has the same time, a type R|W and the range of
            // address intersect
            if (event_rit->nbID == sizeof(event_rit->id) / sizeof(event_rit->id[0])){
                // cannot merge the two events
                break;
            }
            merge = true;
            unsigned long long start_addr = min(event_rit->address, ev.address);
            unsigned long long end_addr = max(ev.address + ev.size, event_rit->address + event_rit->size);

            if ((event_rit->type | ev.type) == EVENT_RW) {
                event_rit->type = EVENT_RW;
            }
            event_rit->address = start_addr;
            event_rit->size = end_addr - start_addr;
            event_rit->id[event_rit->nbID] = ev.id[0];
            event_rit->nbID ++;
            break;
        }
        if (!merge) {
            block_it->events.append(ev);
        }
    } else {
        block_it->events.append(ev);
    }
    if(ev.time > total_time)
        total_time = ev.time;
}

void TMGraphView::regionProcessing()
{
    // We create display addresses to collapse empty memory region in the view
    unsigned long long cur_address = 0;
    Region r;
    QList<MemoryBlock>::iterator block_it = blocks.begin();
    while(block_it != blocks.end())
    {
        // Create a new region
        r.address = block_it->address;
        r.display_address = cur_address;
        r.size = block_it->size;
        block_it->display_address = cur_address;
        block_it->start_region = true;
        cur_address += block_it->size;
        // Check if the following blocks are part of this new region
        block_it++;
        while(block_it != blocks.end() && r.address + r.size == block_it->address)
        {
            // Assign the block to the region
            r.size += block_it->size;
            block_it->display_address = cur_address;
            block_it->start_region = false;
            cur_address += block_it->size;
            block_it++;
        }
        regions.append(r);
    }
    if(regions.size() > 0) {
        total_bytes = regions.back().display_address + regions.back().size;
    }
    else {
        total_bytes = 0;
    }
}

unsigned long long  TMGraphView::realAddressToDisplayAddress(unsigned long long address)
{
    for(QList<Region>::iterator region_it = regions.begin(); region_it != regions.end(); region_it++)
        if(address >= region_it->address && address < region_it->address + region_it->size)
            return address - region_it->address + region_it->display_address;
    return 0xffffffffffffffff;
}

unsigned long long  TMGraphView::displayAddressToRealAddress(unsigned long long address)
{
    for(QList<Region>::iterator region_it = regions.begin(); region_it != regions.end(); region_it++)
        if(address >= region_it->display_address && address < region_it->display_address + region_it->size)
            return address - region_it->display_address + region_it->address;
    return 0xffffffffffffffff;
}

Event TMGraphView::findEventAt(QPoint pos)
{
    // Converting screen coordinates to real address and time
    unsigned long long address = displayAddressToRealAddress(view_address + pos.x()/address_zoom_factor);
    unsigned long long time = (unsigned long long)(view_time + pos.y()/time_zoom_factor);
    // Looking for the right memory block
    for(QList<MemoryBlock>::iterator block_it = blocks.begin(); block_it != blocks.end(); block_it++)
    {
        if(address < block_it->address)
            break;// We are too far in memory space
        else if(address >= block_it->address && address < block_it->address + block_it->size)
        {
            // Looking for the right event (if it exist)
            for(QList<Event>::iterator event_it = block_it->events.begin(); event_it != block_it->events.end(); event_it++)
            {
                if(time < event_it->time)
                    break; // We are too far in time
                else if(time >= event_it->time &&
                        time < (event_it->time + max<int>(1, size_px/time_zoom_factor)) &&
                        address >= event_it->address &&
                        address < event_it->address + max<int>(event_it->size, size_px/address_zoom_factor))
                    return *event_it; // Found it!
            }
        }
    }
    Event ev;
    ev.type = EVENT_UFO;
    return ev;
}

void TMGraphView::displayTrace()
{
    QMetaObject::invokeMethod(sqlite_client, "queryEvents", Qt::QueuedConnection);
}

void TMGraphView::timeMove(long long dt)
{
    if(dt < 0 && view_time + dt > view_time)
        view_time = 0;
    else if(dt > 0 && view_time + dt < view_time)
        view_time = 0xFFFFFFFFFFFFFFFF;
    else
        view_time += dt;
    emit positionChange(displayAddressToRealAddress(view_address), view_time);
}

void TMGraphView::addressMove(long long da)
{
    if(da < 0 && view_address + da > view_address)
        view_address = 0;
    else if(da > 0 && view_address + da < view_address)
        view_address = 0xFFFFFFFFFFFFFFFF;
    else
        view_address += da;
    emit positionChange(displayAddressToRealAddress(view_address), view_time);
}

void TMGraphView::setAddress(unsigned long long address)
{
    view_address = realAddressToDisplayAddress(address);
    emit positionChange(address, view_time);
    update();
}

void TMGraphView::setTime(unsigned long long time)
{
    view_time = time;
    emit positionChange(displayAddressToRealAddress(view_address), view_time);
    update();
}

void TMGraphView::updateZoomFactors()
{
    if(total_bytes != 0) {
        address_zoom_factor = width()/(double)total_bytes;
    }
    else {
        address_zoom_factor = 1.0;
    }
    if(total_time != 0) {
        time_zoom_factor = height()/(double)total_time;
    }
    else {
        time_zoom_factor = 1.0;
    }
}

void TMGraphView::zoomToOverview()
{
    view_address = 0;
    view_time = 0;

    updateZoomFactors();

    emit positionChange(displayAddressToRealAddress(view_address), view_time);
    update();
}

void TMGraphView::onWindowResize()
{
    // Special behaviour if overview: fit to new window size
    if (view_address == 0 && view_time == 0)
    {
        updateZoomFactors();
    }
    // Otherwise, repaint at the same zoom level, thus showing more stuff if you increase window size, less stuff if you decrease it

    emit positionChange(displayAddressToRealAddress(view_address), view_time);
    update();
}

void TMGraphView::wheelEvent(QWheelEvent *event)
{
    event->accept();
    double f = (event->angleDelta().y()+event->angleDelta().x())/2000.0;
    Qt::KeyboardModifiers mod = QGuiApplication::keyboardModifiers();
    if(mod == Qt::NoModifier || mod == Qt::ControlModifier)
    {
        addressMove((long long)(event->pos().x()/address_zoom_factor*(2*f)/(1+f)));
        address_zoom_factor *= (1+f)/(1-f);
    }
    if(mod == Qt::NoModifier || mod == Qt::ShiftModifier)
    {
        timeMove((long long)(event->pos().y()/time_zoom_factor*(2*f)/(1+f)));
        time_zoom_factor *= (1+f)/(1-f);
    }
    else if(mod ==Qt::AltModifier)
    {
        size_factor *= (1+f)/(1-f);
        if(size_factor < 1)
            size_factor = 1;
    }
    update();
}

void TMGraphView::keyPressEvent(QKeyEvent * event)
{
    static const double speed = 0.05;
    if(event->key() == Qt::Key_Up)
    {
        timeMove((long)(-height()*speed/time_zoom_factor));
        update();
    }
    else if(event->key() == Qt::Key_Down)
    {
        timeMove((long)(height()*speed/time_zoom_factor));
        update();
    }
    else if(event->key() == Qt::Key_Left)
    {
        addressMove((long)(-width()*speed/address_zoom_factor));
        update();
    }
    else if(event->key() == Qt::Key_Right)
    {
        addressMove((long)(width()*speed/address_zoom_factor));
        update();
    }
    else if(event->key() == Qt::Key_Plus)
    {
        size_px+=1;
        update();
    }
    else if(event->key() == Qt::Key_Minus)
    {
        size_px=max<int>(size_px-1,1);
        update();
    }
}


void TMGraphView::mouseMoveEvent(QMouseEvent * event)
{
    if(event->buttons() & Qt::LeftButton)
    {
        addressMove((long)((drag_last_pos.x()-event->pos().x())/address_zoom_factor));
        drag_last_pos.setX(event->pos().x());
        timeMove((long)((drag_last_pos.y()-event->pos().y())/time_zoom_factor));
        drag_last_pos.setY(event->pos().y());
        update();
    }
    emit cursorPositionChange(displayAddressToRealAddress(view_address + (long long)(event->pos().x()/address_zoom_factor)),
                              view_time + (long long)(event->pos().y()/time_zoom_factor));
}

void TMGraphView::mousePressEvent(QMouseEvent * event)
{
    if(event->button() == Qt::LeftButton)
    {
        drag_start.setX(event->pos().x());
        drag_last_pos.setX(drag_start.x());
        drag_start.setY(event->pos().y());
        drag_last_pos.setY(drag_start.y());
    }
    else if(event->button() == Qt::RightButton)
    {
        zoom_start.setX(event->pos().x());
        zoom_start.setY(event->pos().y());
        if(event->modifiers() == Qt::ControlModifier)
            zoom_state = ZOOM_BACKWARD;
        else
            zoom_state = ZOOM_FORWARD;
    }
}

void TMGraphView::mouseReleaseEvent(QMouseEvent * event)
{
    if(event->button() == Qt::LeftButton)
    {
        // User is trying to select an event
        if(abs(drag_start.x() - event->pos().x()) < 10 || abs(drag_start.y() - event->pos().y()) < 10)
        {
            Event ev = findEventAt(event->pos());
            emit eventDescriptionQueried(ev); // Mongoclient "should" reply with the description
        }
    }
    else if(event->button() == Qt::RightButton)
    {
        if(abs(zoom_start.x() - event->pos().x()) < 10 || abs(zoom_start.y() - event->pos().y()) < 10)
            return; // probably a missclick
        if(zoom_state == ZOOM_FORWARD)
        {
            addressMove((long long)(min(zoom_start.x(), event->pos().x())/address_zoom_factor));
            timeMove((long long)(min(zoom_start.y(), event->pos().y())/time_zoom_factor));
            address_zoom_factor *= width()/(double)abs(zoom_start.x() - event->pos().x());
            time_zoom_factor *= height()/(double)abs(zoom_start.y() - event->pos().y());
        }
        else if(zoom_state == ZOOM_BACKWARD)
        {
            address_zoom_factor *= abs(zoom_start.x() - event->pos().x())/(double)width();
            time_zoom_factor *= abs(zoom_start.y() - event->pos().y())/(double)height();
            addressMove(-(long long)(min(zoom_start.x(), event->pos().x())/address_zoom_factor));
            timeMove(-(long long)(min(zoom_start.y(), event->pos().y())/time_zoom_factor));
        }
        zoom_state = NO_ZOOM;
        update();
    }
}


void TMGraphView::setColor(EVENT_TYPE type)
{
    if(type == (EVENT_R | EVENT_W))
    {
        painter->setPen(rwpen);
        painter->setBrush(rwbrush);
    }
    else if(type == EVENT_R)
    {
        painter->setPen(rpen);
        painter->setBrush(rbrush);
    }
    else if(type == EVENT_W)
    {
        painter->setPen(wpen);
        painter->setBrush(wbrush);
    }
    else if(type == EVENT_INS)
    {
        painter->setPen(ipen);
        painter->setBrush(ibrush);
    }
}

void TMGraphView::paintEvent(QPaintEvent* /*event*/)
{
    painter->begin(this);
    painter->setRenderHint(QPainter::Antialiasing, true);
    // We adapt the size to keep each event size above 1px if the zoom is too low
    if(trace_state == TRACE_READY)
    {
        QList<MemoryBlock>::iterator block_it = blocks.begin();
        // Looking for blocks inside our view
        while(block_it != blocks.end())
        {
             if(block_it->display_address > view_address + (unsigned long)this->width()/address_zoom_factor)
                 break; // block is outside of the view so it will be the same for the following blocks thus we break
             else if(block_it->display_address + block_it->size > view_address)
             {
                 if(block_it->start_region)
                 {
                     // Draw region marker and address
                     char address_str[64];
                     painter->setPen(QColor(255,128,0));
                     painter->drawLine((block_it->display_address - view_address)*address_zoom_factor, 0,
                                       (block_it->display_address - view_address)*address_zoom_factor, height());
                     snprintf(address_str, 64, "0x%llx", block_it->address);
                     painter->drawText((block_it->display_address - view_address)*address_zoom_factor, height(), address_str);
                 }
                 QList<Event>::iterator event_it = block_it->events.begin();
                 while(event_it != block_it->events.end())
                 {
                     if(event_it->time > view_time + (unsigned long)this->height()/time_zoom_factor)
                         break;
                     else if(event_it->time >= view_time)
                     {
                         setColor(event_it->type);
                         painter->drawRect((realAddressToDisplayAddress(event_it->address) - view_address)*address_zoom_factor,
                                           (event_it->time - view_time)*time_zoom_factor,
                                            max<int>(event_it->size*address_zoom_factor, size_px)*size_factor,
                                            max<int>(time_zoom_factor, size_px)*size_factor);
                     }
                     event_it++;
                 }
             }
             block_it++;
        }
    }
    else if(trace_state == PROCESSING_DB)
        painter->drawText(this->width()/2, this->height()/2, "Processing database.");
    else if(trace_state == NO_DB)
        painter->drawText(this->width()/2, this->height()/2, "No database selected.");
    painter->end();
}
