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
#ifndef METADATADIALOG_H
#define METADATADIALOG_H

#include <QDialog>
#include <QMessageBox>
#include "sqliteclient.h"

namespace Ui {
class MetadataDialog;
}

class MetadataDialog : public QDialog
{
    Q_OBJECT

public:
    explicit MetadataDialog(SqliteClient *mongo_client, QWidget *parent = 0);
    ~MetadataDialog();

private:
    Ui::MetadataDialog *ui;
    SqliteClient *mongo_client;

private slots:
    void onMetadataResults(char **metadata);
    void onStatResults(long long *stats);

protected:
    void mousePressEvent(QMouseEvent * event);
};

#endif // METADATADIALOG_H
