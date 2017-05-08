// Aluno: Saulo Queiroz da Fonseca.
// Numero: 1100890.
// UC: Projeto Final - NetRevealer
// Segundo semestre de 2013/2014.
// Criado com o Qt v. 5.2.1 rodando no Windows 8

#ifndef PACKET_H
#define PACKET_H

#include <QGraphicsItem>
#include <QMainWindow>

class host;

class packet : public QGraphicsItem
{
private:
	QTime last;
	host *source;
	host *destination;
	QRectF boundingRect() const;
	void paint(QPainter*,const QStyleOptionGraphicsItem*,QWidget*);

public:
	packet(host*,host*);
	host* getSrc() {return source;}
	void setTime(QTime t) {last = t;}
	host* getDst() {return destination;}
};

#endif // PACKET_H
