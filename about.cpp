// Aluno: Saulo Queiroz da Fonseca.
// Numero: 1100890.
// UC: Projeto Final - NetRevealer
// Segundo semestre de 2013/2014.
// Criado com o Qt v. 5.2.1 rodando no Windows 8

#include "about.h"
#include "ui_about.h"

About::About(QWidget *parent) :
	QDialog(parent),
	ui(new Ui::About)
{
	ui->setupUi(this);
}

About::~About()
{
	delete ui;
}

void About::on_commandLinkButton_clicked()
{
	QDesktopServices::openUrl(QUrl("mailto:fonseca@astrotown.de"));
}

void About::on_commandLinkButton_2_clicked()
{
	QDesktopServices::openUrl(QUrl("http://www.AstroTown.de/netrevealer"));
}
