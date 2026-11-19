QT += core gui quick quickcontrols2 testlib network
CONFIG += c++17 testcase
TARGET = bastion_tests
TEMPLATE = app

INCLUDEPATH += ../src

HEADERS += ../src/backend.h ../src/logmodel.h ../src/policy.h ../src/theme.h ../src/translator.h
SOURCES += bastion_tests.cpp ../src/backend.cpp ../src/logmodel.cpp ../src/policy.cpp ../src/theme.cpp ../src/translator.cpp
