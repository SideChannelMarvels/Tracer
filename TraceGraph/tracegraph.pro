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
    connectdialog.cpp \
    mongoclient.cpp \
    metadatadialog.cpp \
    tmgraphview.cpp

HEADERS  += mainwindow.h \
    connectdialog.h \
    mongoclient.h \
    metadatadialog.h \
    tmgraphview.h

FORMS    += mainwindow.ui \
    connectdialog.ui \
    metadatadialog.ui

LIBS += -lbson-1.0 -lmongoc-1.0

INCLUDEPATH += /usr/local/include/libmongoc-1.0 /usr/local/include/libbson-1.0

target.path = /usr/local/bin
INSTALLS += target
