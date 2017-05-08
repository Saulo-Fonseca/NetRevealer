// Aluno: Saulo Queiroz da Fonseca.
// Numero: 1100890.
// UC: Projeto Final - NetRevealer
// Segundo semestre de 2013/2014.
// Criado com o Qt v. 5.2.1 rodando no Windows 8

#ifndef HOST_H
#define HOST_H
#include <QGraphicsItem>
#include <QMainWindow>
#include <QStringList>
#include <QPainter>
#include <QtCore>
#include <QtMath>
#include <QStyle>
#include "iana.h"
#include "packet.h"

class host : public QGraphicsItem
{
private:
	struct port
	{
		int value;
		int protocol;
	};
	int sent;
	int icon;
	QTime time;
	int received;
	QString name;
	QStringList mac;
	QStringList ipv4;
	QStringList ipv6;
	QStringList mask;
	QTime broadcastTime;
	QVector<port> ports;
	uint ip2int(QString);
	QVector<packet*> packets;
	QRectF boundingRect() const;
	void paint(QPainter*,const QStyleOptionGraphicsItem*,QWidget*);
	QVariant itemChange(GraphicsItemChange change, const QVariant &value);
	template<class T, class M> void insertSort(QVector<M> &vec, T (M::*var));

public:
	host();
	void reset();
	void angle(host*);
	void detectIcon();
	QStringList info();
	bool subnet(QString);
	void incSnd() {sent++;}
	bool exists(QString s);
	void addMac(QString m);
	void addIPv4(QString i);
	void addIPv6(QString i);
	void addPacket(packet*);
	bool broadcast(QString);
	void incRcv() {received++;}
	void removePacket(packet*);
	QTime getTime() {return time;}
	static QVector<QPixmap> icons;
	void setIcon(int n) {icon = n;}
	QString getName() {return name;}
	void setTime(QTime t) {time = t;}
	static QString shortIPv6(QString);
	void setName(QString n) {name = n;}
	void addPort(int value, int protocol);
	QString getMask(int n) {return mask[n];}
	QVector<packet*> getPackets() {return packets;}
	QTime getBroadcastTime() {return broadcastTime;}
	void setBroadcastTime(QTime b) {broadcastTime = b;}
	void addMask(QString m) {if (m != "") mask.push_front(m);}
	QString getIPv4(int n) {if (ipv4.empty()) return ""; return ipv4[n];}
	QString getIPv6(int n) {if (ipv6.empty()) return ""; return ipv6[n];}
};
#endif // HOST_H
