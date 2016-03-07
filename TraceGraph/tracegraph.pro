#-------------------------------------------------
#
# Project created by QtCreator 2014-08-08T16:38:18
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = tracegraph
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    metadatadialog.cpp \
    tmgraphview.cpp \
    sqliteclient.cpp

HEADERS  += mainwindow.h \
    metadatadialog.h \
    tmgraphview.h \
    sqliteclient.h

FORMS    += mainwindow.ui \
    metadatadialog.ui

LIBS += -lsqlite3

target.path = /usr/bin
INSTALLS += target
