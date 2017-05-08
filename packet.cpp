// Aluno: Saulo Queiroz da Fonseca.
// Numero: 1100890.
// UC: Projeto Final - NetRevealer
// Segundo semestre de 2013/2014.
// Criado com o Qt v. 5.2.1 rodando no Windows 8

#include "host.h"
#include "packet.h"

// Define limits of line
QRectF packet::boundingRect() const
{
	double deltaX = abs(source->x()-destination->x());
	double deltaY = abs(source->y()-destination->y());
	double x = (source->x()<destination->x()?source->x():destination->x());
	double y = (source->y()<destination->y()?source->y():destination->y());
	return QRectF(x,y,deltaX,deltaY);
}

// Define apearence
void packet::paint(QPainter *painter, const QStyleOptionGraphicsItem*,QWidget*)
{
	if (last.msecsTo(QTime::currentTime()) < 200)
	{
		QPen orange(QColor(255,133,0));
		painter->setPen(orange);
	}
	else
		painter->setPen(Qt::black);
	painter->drawLine(source->x(),source->y(),destination->x(),destination->y());
}

// Constructor
packet::packet(host *src, host *dst)
{
	source = src;
	destination = dst;
	source->addPacket(this);
	destination->addPacket(this);
	setTime(QTime::currentTime());
}
