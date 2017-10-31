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
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QThread>
#include <QMessageBox>
#include <QFileDialog>
#include <QPixmap>
#include <string.h>
#include "sqliteclient.h"
#include "metadatadialog.h"
#include "tmgraphview.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();   
    void openFile(const char* filename);

protected:
    virtual void resizeEvent(QResizeEvent* event);

private slots:

    void on_actionMetadata_triggered();
    void onInvalidDatabase();
    void positionChanged(unsigned long long address, unsigned long long time);
    void cursorPositionChanged(unsigned long long address, unsigned long long time);

    void on_graph_address_editingFinished();
    void on_graph_time_editingFinished();

    void on_actionSave_Image_triggered();

    void on_actionOverview_zoom_triggered();

    void on_actionOpenDatabase_triggered();

private:
    Ui::MainWindow *ui;
    QThread worker_thread;
    SqliteClient sqlite_client;
    TMGraphView *scene;
};

#endif // MAINWINDOW_H
