// Aluno: Saulo Queiroz da Fonseca.
// Numero: 1100890.
// UC: Projeto Final - NetRevealer
// Segundo semestre de 2013/2014.
// Criado com o Qt v. 5.2.1 rodando no Windows 8

#ifndef ABOUT_H
#define ABOUT_H

#include <QDesktopServices>
#include <QDialog>
#include <QUrl>

namespace Ui
{
    class About;
}

class About : public QDialog
{
	Q_OBJECT

private:
	Ui::About *ui;

public:
	explicit About(QWidget *parent = 0);
	~About();
private slots:
	void on_commandLinkButton_clicked();
	void on_commandLinkButton_2_clicked();
};
#endif // ABOUT_H
