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
#ifndef CONNECTDIALOG_H
#define CONNECTDIALOG_H

#include <QDialog>
#include <QMessageBox>
#include <QDebug>
#include <QMetaObject>
#include <QMetaMethod>
#include "mongoclient.h"

namespace Ui {
class ConnectDialog;
}

class ConnectDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ConnectDialog(MongoClient *mongo_client, QWidget *parent = 0);
    ~ConnectDialog();

private slots:
    void on_connect_button_clicked();
    void onConnectionResult(char **names);
    void on_select_button_clicked();

private:
    Ui::ConnectDialog *ui;
    MongoClient *mongo_client;
};

#endif // CONNECTDIALOG_H
