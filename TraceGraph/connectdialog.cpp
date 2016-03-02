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
#include "connectdialog.h"
#include "ui_connectdialog.h"

ConnectDialog::ConnectDialog(MongoClient *mongo_client, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ConnectDialog)
{
    ui->setupUi(this);
    this->mongo_client = mongo_client;
    connect(mongo_client, &MongoClient::connectionResult, this, &ConnectDialog::onConnectionResult);
}

ConnectDialog::~ConnectDialog()
{
    delete ui;
}

void ConnectDialog::on_connect_button_clicked()
{
    // Qt voodoo techniques
    QMetaObject::invokeMethod(mongo_client, "connectToHost", Qt::QueuedConnection, Q_ARG(QString, ui->mongodb_url->text()));
}

void ConnectDialog::onConnectionResult(char **names)
{
    if(names)
    {
        for(int i = 0; names[i]; i++)
            ui->database_list->addItem(names[i]);
        bson_strfreev(names);
    }
    else
    {
        QMessageBox error;
        error.setText("The connection to the server failed.");
        error.exec();
    }
}

void ConnectDialog::on_select_button_clicked()
{
    // Qt voodoo techniques
    QMetaObject::invokeMethod(mongo_client, "connectToDatabase", Qt::QueuedConnection, Q_ARG(QString, ui->database_list->selectedItems().first()->text()));
    this->close();
}
