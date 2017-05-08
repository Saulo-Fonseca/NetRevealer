// Aluno: Saulo Queiroz da Fonseca.
// Numero: 1100890.
// UC: Projeto Final - NetRevealer
// Segundo semestre de 2013/2014.
// Criado com o Qt v. 5.2.1 rodando no Windows 8

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QNetworkInterface>
#include <QGraphicsRectItem>
#include <QGraphicsScene>
#include <QSignalMapper>
#include <QInputDialog>
#include <QMainWindow>
#include <QMouseEvent>
#include <QMessageBox>
#include <QHostInfo>
#include <pcap.h>
#include <QEvent>
#include <QTimer>
#include <QTime>
#include "host.h"
#include "packet.h"

namespace Ui
{
	class MainWindow;
}

// Provide types not present in Mac-OSX and Linux
#if defined(Q_OS_MAC) || defined(Q_OS_LINUX)
	struct sockaddr
	{
		u_short sa_family;
		char    sa_data[14];
	};

	typedef struct in_addr
	{
		union
		{
			struct { u_char  s_b1, s_b2, s_b3, s_b4; } S_un_b;
			struct { u_short s_w1, s_w2; } S_un_w;
			u_int S_addr;
		} S_un;
	} IN_ADDR;

	struct sockaddr_in
	{
		short    sin_family;
		u_short  sin_port;
		in_addr  sin_addr;
		char     sin_zero[8];
	};
#endif

// Provice the in6_addr, not present in Pcap
struct in6_addr
{
	u_char  byte[16];
};

// Provice the sockaddr_in6, not present in Pcap
struct sockaddr_in6 {
	u_short  sin6_port;
	u_int   sin6_flowinfo;
	in6_addr sin6_addr;
	u_int   sin6_scope_id;
};

// Ethernet header
struct ETHERNET
{
	u_char  destination[6];
	u_char  source[6];
	u_short type;
};

// IPv4 header
struct IPv4
{
	u_char  vhl;
	u_char  type_of_service;
	u_short lenght;
	u_short id;
	u_short offset;
	u_char  ttl;
	u_char  protocol;
	u_short checksum;
	in_addr source;
	in_addr destination;
};

// IPv6 header
struct IPv6
{
	u_int    vtcfl;
	u_short  lenght;
	u_char   next_header;
	u_char   ttl;
	in6_addr source;
	in6_addr destination;
};

// TCP or UDP header (only part that will be used)
struct TCP_or_UDP
{
	u_short source_port;
	u_short destination_port;
};

// Handle and bool to control for Pcap
struct SOCKET_PCAP
{
	pcap_t* handle;
	bool    active;
};

class MainWindow : public QMainWindow
{
	Q_OBJECT

private:
	QVector<SOCKET_PCAP> socket;	// Pcap sockets
	QGraphicsScene *scene;			// Interface to graphics view
	QVector<host*> hosts;			// Copy of host in GraphicsView
	Ui::MainWindow *ui;				// Main window
	QTimer *timer;					// Timer to repeat all actions
	bool broadcast;					// Show/hide broadcast
	bool reading;					// Activate packet reading
	int delLimit;					// Limite before delete hosts

	// Private methods
	void delHost(int);
	void detectOverlaping();
	QString mac2str(u_char*);
	QString ipv4str(in_addr);
	QString ipv6str(in6_addr);
	QString expandStr(QString,int);
	bool eventFilter(QObject*,QEvent*);
	void addHost(QString,QString,QString,QString,int,int);
	void onPacket(u_char*,const struct pcap_pkthdr*,const u_char*);

	// Standart C multi-instance callback pattern to convert static to dynamic
	static void callBack(u_char *args, const struct pcap_pkthdr *header,
		const u_char *packet)
	{
		((MainWindow*)args)->onPacket(args,header,packet);
	}

private slots:
	void on_actionDelete_all_hosts_triggered();
	void on_actionIgnore_broadcast_triggered();
	void on_actionRead_packets_triggered();
	void lookedUp(const QHostInfo&);
	void on_actionAbout_triggered();
	void on_actionExit_triggered();
	void onIface(int);
	void onDel(int);
	void onTime();

public:
	explicit MainWindow(QWidget *parent = 0);
	~MainWindow();
};

#endif // MAINWINDOW_H

// Plataform dependent code
#ifdef Q_OS_WIN
	// Windows code
#endif
#ifdef Q_OS_MAC
	// Mac code
#endif
#ifdef Q_OS_LINUX
	// Linux code
#endif
