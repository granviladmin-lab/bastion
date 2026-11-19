QT += core gui qml quick quickcontrols2 network

CONFIG += c++17 release
TARGET = bastion
TEMPLATE = app

HEADERS += \
    src/backend.h \
    src/logmodel.h \
    src/policy.h \
    src/theme.h \
    src/translator.h

SOURCES += \
    src/main.cpp \
    src/backend.cpp \
    src/logmodel.cpp \
    src/policy.cpp \
    src/theme.cpp \
    src/translator.cpp

RESOURCES += src/resources.qrc
