QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    bip39.cpp \
    main.cpp \
    mainwindow.cpp \
    sha.cpp

HEADERS += \
    bignum.h \
    bip39.h \
    mainwindow.h \
    sha.h \
    serialize.h \
    uint256.h \
    base58.h \
    util.h

FORMS += \
    mainwindow.ui

TRANSLATIONS += \
    bip39_zh_CN.ts
CONFIG += lrelease
CONFIG += embed_translations

INCLUDEPATH += \
/usr/local/ssl/include

LIBS += \
/usr/local/ssl/lib/libssl.a \
/usr/local/ssl/lib/libcrypto.a \
/usr/local/lib/libsecp256k1.a

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
