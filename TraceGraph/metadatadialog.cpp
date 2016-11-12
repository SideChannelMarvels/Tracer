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
#include "metadatadialog.h"
#include "ui_metadatadialog.h"

MetadataDialog::MetadataDialog(SqliteClient *mongo_client, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MetadataDialog)
{
    ui->setupUi(this);
    this->mongo_client = mongo_client;
    connect( mongo_client, &SqliteClient::metadataResults, this, &MetadataDialog::onMetadataResults);
    connect( mongo_client, &SqliteClient::statResults, this, &MetadataDialog::onStatResults);
    QMetaObject::invokeMethod(mongo_client, "queryMetadata", Qt::QueuedConnection);
    QMetaObject::invokeMethod(mongo_client, "queryStats", Qt::QueuedConnection);
}

MetadataDialog::~MetadataDialog()
{
    delete ui;
}

void MetadataDialog::onMetadataResults(char* metadata[4])
{
    if(metadata)
    {
        if(metadata[0])
        {
            ui->version->setText(metadata[0]);
            delete metadata[0];
        }
        else
            ui->version->setText("not found");
        if(metadata[1])
        {
            ui->architecture->setText(metadata[1]);
            delete metadata[1];
        }
        else
            ui->architecture->setText("not found");
        if(metadata[2])
        {
            ui->program->setText(metadata[2]);
            delete metadata[2];
        }
        else
            ui->program->setText("not found");
        if(metadata[3])
        {
            ui->arguments->setText(metadata[3]);
            delete metadata[3];
        }
        else
            ui->arguments->setText("not found");
        delete metadata;
    }
    else
    {
        QMessageBox error;
        error.setText("Failed to retrieve metadata.");
        error.exec();
    }
}

void MetadataDialog::onStatResults(long long *stats)
{
    ui->bbl_count->setText(QString::number(stats[0], 10));
    ui->ins_count->setText(QString::number(stats[1], 10));
    ui->mem_count->setText(QString::number(stats[2], 10));
}

void MetadataDialog::mousePressEvent(QMouseEvent* /*event*/)
{
    this->destroy();
}
