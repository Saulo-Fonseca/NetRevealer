// Aluno: Saulo Queiroz da Fonseca.
// Numero: 1100890.
// UC: Projeto Final - NetRevealer
// Segundo semestre de 2013/2014.
// Criado com o Qt v. 5.2.1 rodando no Windows 8

#ifndef IANA_H
#define IANA_H
#include <QMainWindow>

namespace iana
{
	QString getEtherType(int);
	QString getProtocol(int);
	QString getTCP(int);
	QString getUDP(int);
}
#endif // IANA_H
