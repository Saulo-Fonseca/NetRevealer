# Aluno: Saulo Queiroz da Fonseca.
# Numero: 1100890.
# UC: Projeto Final - NetRevealer
# Segundo semestre de 2013/2014.
# Criado com o Qt v. 5.2.1 rodando no Windows 8

QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = NetRevealer
TEMPLATE = app

SOURCES += main.cpp\
	mainwindow.cpp \
	about.cpp \
	host.cpp \
	iana.cpp \
	capture.cpp \
    packet.cpp

HEADERS  += mainwindow.h \
	about.h \
	host.h \
	iana.h \
    packet.h

FORMS    += mainwindow.ui \
	about.ui

RESOURCES += \
	resources.qrc

win32{
	INCLUDEPATH += C:/WpdPack/Include
	LIBS += -LC:/WpdPack/Lib -lwpcap -lpacket
	RC_FILE = NetRevealer.rc
}

macx{
	QMAKE_LFLAGS += -lpcap
	ICON = NetRevealer.icns
}

unix{
	INCLUDEPATH += /usr/include/pcap
	LIBS += -lpcap
}
