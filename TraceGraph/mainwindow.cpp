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
#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    sqlite_client.moveToThread(&worker_thread);
    worker_thread.start();
    connect(&sqlite_client, &SqliteClient::invalidDatabase, this, &MainWindow::onInvalidDatabase);
    connect(ui->graph, &TMGraphView::positionChange, this, &MainWindow::positionChanged);
    connect(ui->graph, &TMGraphView::cursorPositionChange, this, &MainWindow::cursorPositionChanged);
    connect(ui->graph_address, &QLineEdit::returnPressed, this, &MainWindow::on_graph_address_editingFinished);
    connect(ui->graph_time, &QLineEdit::returnPressed, this, &MainWindow::on_graph_time_editingFinished);
    //Querying event description is a three party interconnection
    connect(ui->graph, &TMGraphView::eventDescriptionQueried, &sqlite_client, &SqliteClient::queryEventDescription);
    connect(&sqlite_client, &SqliteClient::receivedEventDescription, ui->event_display, &QTextEdit::setText);
    ui->graph->setSqliteClient(&sqlite_client);
}

MainWindow::~MainWindow()
{
    QMetaObject::invokeMethod(&sqlite_client, "cleanup", Qt::QueuedConnection);
    worker_thread.exit();
    worker_thread.wait(1000);
    delete ui;
}

void MainWindow::openFile(const char* filename) {
    QMetaObject::invokeMethod(&sqlite_client, "connectToDatabase", Qt::QueuedConnection, Q_ARG(QString, QString(filename)));
}

void MainWindow::on_actionMetadata_triggered()
{
    if(sqlite_client.isConnectedToDatabase())
    {
        MetadataDialog metadata_dialog(&sqlite_client, this);
        metadata_dialog.exec();
    }
    else
    {
        QMessageBox error;
        error.setText("Not connected to a database.");
        error.exec();
    }
}

void MainWindow::onInvalidDatabase()
{
    QMessageBox error;
    error.setText("This database is not a valid execution trace.");
    error.exec();
}

void MainWindow::resizeEvent(QResizeEvent* event)
{
    QMainWindow::resizeEvent(event);
    // Update UI
    ui->graph->onWindowResize();
}

void MainWindow::positionChanged(unsigned long long address, unsigned long long time)
{
    char buffer[64];
    snprintf(buffer, 64, "0x%016llx", address);
    ui->graph_address->setText(buffer);
    snprintf(buffer, 64, "%llu", time);
    ui->graph_time->setText(buffer);
}

void MainWindow::cursorPositionChanged(unsigned long long address, unsigned long long time)
{
    char buffer[64];
    snprintf(buffer, 64, "Address: 0x%016llx", address);
    ui->cursor_address->setText(buffer);
    snprintf(buffer, 64, "Time: %llu", time);
    ui->cursor_time->setText(buffer);
}

void MainWindow::on_graph_address_editingFinished()
{
    ui->graph->setAddress(strtoul(ui->graph_address->text().toLocal8Bit().data(), NULL, 16));
}

void MainWindow::on_graph_time_editingFinished()
{
    ui->graph->setTime(strtoul(ui->graph_time->text().toLocal8Bit().data(), NULL, 10));
}

void MainWindow::on_actionSave_Image_triggered()
{
    QString filename = QFileDialog::getSaveFileName(this, "Save graph as image");
    if(filename != NULL) {
        QPixmap image = ui->graph->grab();
        image.save(filename);
    }
}

void MainWindow::on_actionOverview_zoom_triggered()
{
    ui->graph->zoomToOverview();
}

void MainWindow::on_actionOpenDatabase_triggered()
{
    QString filename = QFileDialog::getOpenFileName(this, "Open database");
    if(filename != NULL) {
        QMetaObject::invokeMethod(&sqlite_client, "connectToDatabase", Qt::QueuedConnection, Q_ARG(QString, filename));
    }
}
