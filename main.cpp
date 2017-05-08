// Aluno: Saulo Queiroz da Fonseca.
// Numero: 1100890.
// UC: Projeto Final - NetRevealer
// Segundo semestre de 2013/2014.
// Criado com o Qt v. 5.2.1 rodando no Windows 8

#include <QApplication>
#include "mainwindow.h"
QVector<QPixmap> host::icons;

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	qsrand(QTime(0,0,0).secsTo(QTime::currentTime()));
	MainWindow w;
	w.show();
	return a.exec();
}
