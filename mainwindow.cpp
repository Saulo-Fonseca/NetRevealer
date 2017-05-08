// Aluno: Saulo Queiroz da Fonseca.
// Numero: 1100890.
// UC: Projeto Final - NetRevealer
// Segundo semestre de 2013/2014.
// Criado com o Qt v. 5.2.1 rodando no Windows 8

#include "ui_mainwindow.h"
#include "mainwindow.h"
#include "about.h"

// Constructor
MainWindow::MainWindow(QWidget *parent) :
	QMainWindow(parent),
	ui(new Ui::MainWindow)
{
	// Setup GraphicsView
	ui->setupUi(this);
	scene = new QGraphicsScene(this);
	scene->setSceneRect(-5000,-5000,10000,10000); // Set canvas area
	ui->graphicsView->setScene(scene);
	ui->graphicsView->viewport()->setMouseTracking(true);
	ui->graphicsView->viewport()->installEventFilter(this);
	ui->graphicsView->setRenderHint(QPainter::Antialiasing);
	ui->graphicsView->setDragMode(QGraphicsView::ScrollHandDrag);
	ui->graphicsView->setCacheMode(QGraphicsView::CacheBackground);
	ui->graphicsView->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
	ui->graphicsView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
	ui->graphicsView->setViewportUpdateMode(QGraphicsView::BoundingRectViewportUpdate);
	QApplication::setOverrideCursor(Qt::ArrowCursor);

	// Setup listWidget
	ui->listWidget->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
	ui->listWidget->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
	ui->listWidget->setFont((QFont("Courier")));

	// Create first host
	host *thisHost = new host();
	QStringList networkListStr;
	QList<QNetworkInterface> networkList;
	networkList = QNetworkInterface::allInterfaces();
	QHostInfo *info = new QHostInfo;
	thisHost->setName(info->localHostName());

	// Add IP and Netmask captured from Qt
	foreach (QNetworkInterface f, networkList)
	{
		networkListStr.append(f.hardwareAddress());
		foreach (QNetworkAddressEntry a, f.addressEntries())
		{
			if (a.ip().toString().contains("."))
			{
				thisHost->addIPv4(a.ip().toString());
				thisHost->addMask(a.netmask().toString());
			}
			else if (a.ip().toString().contains(":"))
			{
				QString str;
				for (int i=0; i<16; i+=2)
				{
					str += QString().sprintf("%02x",a.ip().toIPv6Address()[i]);
					str += QString().sprintf("%02x",a.ip().toIPv6Address()[i+1]);
					if (i!=14)
						str +=":";
				}
				thisHost->addIPv6(str);
			}
		}
	}

	// Add Mac Addresses
	for (int i=0; i<networkListStr.size(); i++)
	{
		networkListStr[i].replace(":","-");
		thisHost->addMac(networkListStr[i].toLower());
	}

	// Setup Pcap
	char errbuf[PCAP_ERRBUF_SIZE];
	QVector<QString> iface;
	pcap_if_t *alldevs;
	if (pcap_findalldevs(&alldevs,errbuf) == -1)
		QMessageBox::warning(this,"Error",
			QString("Error in pcap_findalldevs<br>")+errbuf);

	// For every NIC
	for (pcap_if_t *dev=alldevs; dev!=NULL; dev=dev->next)
	{
		// Open the NIC in promiscuous mode
		SOCKET_PCAP socket_temp;
		socket_temp.handle = pcap_open_live(dev->name,1518,true,
			1000,errbuf);
		if (socket_temp.handle == NULL)
			continue;

		// Verify if it's an ethernet device
		if (pcap_datalink(socket_temp.handle) != DLT_EN10MB)
			continue;

		// Put the handle in non-block mode (no wait for packets)
		if (pcap_setnonblock(socket_temp.handle,1,errbuf) == -1)
			continue;

		// Add handle and name to the lists
		socket_temp.active = true;
		socket.push_back(socket_temp);
		iface.push_back(dev->name);

		// For every address on this NIC
		for (pcap_addr_t *adr=dev->addresses; adr!=NULL; adr=adr->next)
		{
			// IF IPv4 address
			if (adr->addr->sa_family == 2) // AF_INET
			{
				// Capture IPv4
				in_addr temp = ((sockaddr_in*)adr->addr)->sin_addr;
				thisHost->addIPv4(ipv4str(temp));

				// Capture netmask
				if (adr->netmask != NULL)
				{
					temp = ((sockaddr_in*)adr->netmask)->sin_addr;
					thisHost->addMask(ipv4str(temp));
				}
			}
			else
			// IF IPv6 address
			if (adr->addr->sa_family == 23) // AF_INET6
			{
				// Capture IPv6
				in6_addr temp = ((sockaddr_in6*)adr->addr)->sin6_addr;
				thisHost->addIPv6(ipv6str(temp));
			}
		}
	}
	pcap_freealldevs(alldevs);

	// Quit if no devices found
	if (socket.empty())
	{
		#ifdef Q_OS_WIN
		QMessageBox::warning(this,"Error",
			"It's not possible to connect to any network interface! Please verify if Libpcap is installed.");
		#endif
		#ifdef Q_OS_MAC
		QMessageBox::warning(this,"Error",
			"It's not possible to connect to any network interface! Please install from the file NetRevealer-Installer.mpkg.");
		#endif
		#ifdef Q_OS_LINUX
		QMessageBox::warning(this,"Error",
			"It's not possible to connect to any network interface! This program needs to run as root to access the interfaces.");
		#endif
		exit(0);
	}

	// Add menu to enable/disable NICs
	QMenu *ifaceMenu = new QMenu(this);
	QSignalMapper *ifaceMapper = new QSignalMapper(this);
	QAction *action;
	for (int i=0; i<iface.size(); i++)
	{
		action = new QAction(iface[i],this);
		action->setCheckable(true);
		action->setChecked(true);
		ifaceMapper->setMapping(action,i);
		connect(action,SIGNAL(triggered()),ifaceMapper,SLOT(map()));
		ifaceMenu->addAction(action);
	}
	connect(ifaceMapper,SIGNAL(mapped(int)),this,SLOT(onIface(int)));
	ui->actionEnable_interface->setMenu(ifaceMenu);

	// Add menu to delete hosts after X seconds
	QMenu *delMenu = new QMenu(this);
	QSignalMapper *delMapper = new QSignalMapper(this);
	QActionGroup *grp = new QActionGroup(this);
	grp->setExclusive(true);

	action = new QAction("Disable",this);
	action->setCheckable(true);
	action->setChecked(true);
	delMapper->setMapping(action,0);
	connect(action,SIGNAL(triggered()),delMapper,SLOT(map()));
	delMenu->addAction(action);
	grp->addAction(action);

	action = new QAction("10 seconds",this);
	action->setCheckable(true);
	delMapper->setMapping(action,10);
	connect(action,SIGNAL(triggered()),delMapper,SLOT(map()));
	delMenu->addAction(action);
	grp->addAction(action);

	action = new QAction("30 seconds",this);
	action->setCheckable(true);
	delMapper->setMapping(action,30);
	connect(action,SIGNAL(triggered()),delMapper,SLOT(map()));
	delMenu->addAction(action);
	grp->addAction(action);

	action = new QAction("1 minute",this);
	action->setCheckable(true);
	delMapper->setMapping(action,60);
	connect(action,SIGNAL(triggered()),delMapper,SLOT(map()));
	delMenu->addAction(action);
	grp->addAction(action);

	action = new QAction("5 minutes",this);
	action->setCheckable(true);
	delMapper->setMapping(action,300);
	connect(action,SIGNAL(triggered()),delMapper,SLOT(map()));
	delMenu->addAction(action);
	grp->addAction(action);

	action = new QAction("Custom time",this);
	action->setCheckable(true);
	delMapper->setMapping(action,-1);
	connect(action,SIGNAL(triggered()),delMapper,SLOT(map()));
	delMenu->addAction(action);
	grp->addAction(action);

	connect(delMapper,SIGNAL(mapped(int)),this,SLOT(onDel(int)));
	ui->actionDel_inactive_host_after->setMenu(delMenu);

	// Setup a timer
	timer = new QTimer(this);
	connect(timer,SIGNAL(timeout()),this,SLOT(onTime()));
	timer->start(50);

	// Add icons
	host::icons.append(QPixmap(":Monitor.png"));
	host::icons.append(QPixmap(":Computer.png"));
	host::icons.append(QPixmap(":Notebook.png"));
	host::icons.append(QPixmap(":Phone.png"));
	host::icons.append(QPixmap(":Tablet.png"));
	host::icons.append(QPixmap(":Rack.png"));
	host::icons.append(QPixmap(":Router.png"));
	host::icons.append(QPixmap(":wRouter.png"));

	// Define initial state
	broadcast = true;
	reading = true;
	delLimit = 0;

	// Concludes creation of first host
	scene->addItem(thisHost);
	hosts.append(thisHost);
}

// Destructor
MainWindow::~MainWindow()
{
	for (int i=0; i<socket.size(); i++)
		pcap_close(socket[i].handle);
	delete ui;
}

// About dialog
void MainWindow::on_actionAbout_triggered()
{
	About about;
	about.setModal(true); // Avoid clicking elsewhere
	about.setWindowFlags(Qt::WindowCloseButtonHint); // Remove ? button
	about.exec();
}

// Timer
void MainWindow::onTime()
{
	// Capture a packet
	if (reading)
		for (int i=0; i<socket.size(); i++)
			if (socket[i].active == true)
				pcap_dispatch(socket[i].handle,1,MainWindow::callBack,
					(u_char*)this);

	// Delete old inactive hosts
	if (delLimit != 0)
	{
		for (int i=1; i<hosts.size(); i++)
		{
			if (hosts[i]->getTime().secsTo(QTime::currentTime()) > delLimit)
			{
				delHost(i);
				i--;
			}
			else if (hosts[i]->
				getBroadcastTime().secsTo(QTime::currentTime()) > delLimit)
			{
				hosts[i]->setBroadcastTime(QTime(0,0,0));
			}
		}
	}

	// Update scene
	foreach (QGraphicsItem *item, scene->items())
		item->update();
}

// Start or stop reading packets
void MainWindow::on_actionRead_packets_triggered()
{
	if (reading)
	{
		ui->actionRead_packets->setText("Start reading");
		reading = false;
	}
	else
	{
		ui->actionRead_packets->setText("Stop reading");
		reading = true;
	}
}

// Hide/show broadcast packets
void MainWindow::on_actionIgnore_broadcast_triggered()
{
	if (broadcast)
	{
		ui->actionIgnore_broadcast->setText("Read broadcast");
		broadcast = false;
	}
	else
	{
		ui->actionIgnore_broadcast->setText("Ignore broadcast");
		broadcast = true;
	}
}

// Start or stop network interface
void MainWindow::onIface(int n)
{
	socket[n].active = !socket[n].active;
}

// Delete host
void MainWindow::delHost(int hostIdx)
{
	// Get packets linked to this host
	QVector<packet*> toDel;
	foreach (packet *p, hosts[hostIdx]->getPackets())
		toDel.append(p);

	// Remove this packets from other hosts
	for (int i=0; i<hosts.size(); i++)
		foreach (packet *p, toDel)
			hosts[i]->removePacket(p);

	// Del packets
	foreach (packet *p, toDel)
		scene->removeItem(p);

	// Del host
	scene->removeItem(hosts[hostIdx]);
	hosts.erase(hosts.begin() + hostIdx);

	// Update scene
	scene->setSceneRect(scene->sceneRect().adjusted(1,1,1,1));
	scene->setSceneRect(scene->sceneRect().adjusted(-1,-1,-1,-1));
	scene->update();
}

// Delete all hosts
void MainWindow::on_actionDelete_all_hosts_triggered()
{
	QMessageBox msgBox;
	msgBox.setIcon(QMessageBox::Warning);
	msgBox.setText("All hosts will be deleted!");
	msgBox.setInformativeText("Are you sure?");
	msgBox.setStandardButtons(QMessageBox::Ok | QMessageBox::Cancel);
	msgBox.setDefaultButton(QMessageBox::Ok);
	int ret = msgBox.exec();
	if (ret == QMessageBox::Ok)
	{
		while (hosts.size() != 1)
			delHost(1);
		hosts[0]->reset();
	}
}

// Delete hosts after X seconds
void MainWindow::onDel(int n)
{
	if (n == -1)
	{
		n = QInputDialog::getInt(this,"Custom time","Time in seconds:",
			delLimit,0,86400,1);
	}
	if (n != -1)
		delLimit = n;
}

// Capture mouse movements in GraphicsView
bool MainWindow::eventFilter(QObject *, QEvent *event)
{
	// Static values for custom toolTip
	#if defined(Q_OS_WIN) || defined(Q_OS_LINUX)
		static QFont font("Courier",8);
	#else
		static QFont font("Courier");
	#endif
	static QPen pen(Qt::black);
	static QBrush brush(QColor(255,204,153,224));
	static QGraphicsRectItem *rect = scene->addRect(0,0,0,0,pen,brush);
	static QGraphicsTextItem *text = scene->addText(" ",font);
	rect->setFlags(QGraphicsItem::ItemIgnoresTransformations);
	text->setFlags(QGraphicsItem::ItemIgnoresTransformations);

	// Show host info
	if (event->type() == QEvent::MouseMove)
	{
		static bool done = false;
		if (!done)
		{
			rect->setZValue(2);
			text->setZValue(2);
			rect->setVisible(false);
			text->setVisible(false);
			done = true;
		}

		// Capture position and item under the mouse
		QMouseEvent* mouse = static_cast<QMouseEvent*>(event);
		QPointF pos = ui->graphicsView->mapToScene(mouse->pos());
		QGraphicsItem *item = scene->itemAt(pos,ui->graphicsView->transform());

		// Item info
		if (item != 0)
		{
			// Find item in hosts list
			int i;
			for (i=0; i<hosts.size(); i++)
				if (item == hosts[i])
					break;
			if (i != hosts.size())
			{
				// Find the longest string
				QStringList list = hosts[i]->info();
				int longest = 0;
				foreach (QString s, list)
					if (s.length() > longest)
						longest = s.length();

				// Update text
				pos.setX(pos.x()+5);
				pos.setY(pos.y()+5);
				text->setHtml("<pre>"+list.join("<br>")+"</pre>");
				text->setPos(pos);
				text->setVisible(true);

				// Update rect
				rect->setRect(text->boundingRect());
				rect->setPos(pos);
				rect->setBrush(brush);
				rect->setPen(pen);
				rect->setVisible(true);

			}
			else
			{
				rect->setVisible(false);
				text->setVisible(false);
			}
		}
		else
		{
			rect->setVisible(false);
			text->setVisible(false);
		}
	}
	else if (event->type() == QEvent::MouseButtonPress)
	{
		rect->setVisible(false);
		text->setVisible(false);
		QMouseEvent* mouse = static_cast<QMouseEvent*>(event);
		if (mouse->button() == Qt::RightButton)
		{
			QPointF pos = ui->graphicsView->mapToScene(mouse->pos());
			QGraphicsItem *item = scene->itemAt(pos,ui->graphicsView->transform());

			// Item menu
			if (item != 0)
			{
				// Find item in hosts list
				int i;
				for (i=0; i<hosts.size(); i++)
					if (item == hosts[i])
						break;
				if (i == hosts.size())	// Not found
					item = 0;			// Goes to zoom menu
				else
				{
					// Show menu
					QAction *del = new QAction("Delete",this);
					QAction *none = new QAction("'Del host after x seconds' is active",this);
					QMenu popup(this);
					if (delLimit == 0)
					{
						if (i != 0)
							popup.addAction(del);
					}
					else
						popup.addAction(none);
					QAction *selectedItem = popup.exec(mapToGlobal(mouse->pos()));
					if (selectedItem == del)
					{
						// Confirm deletion
						QMessageBox msgBox;
						msgBox.setIcon(QMessageBox::Warning);
						msgBox.setText("This host will be deleted!");
						msgBox.setInformativeText("Are you sure?");
						msgBox.setStandardButtons(QMessageBox::Ok | QMessageBox::Cancel);
						msgBox.setDefaultButton(QMessageBox::Ok);
						int ret = msgBox.exec();
						if (ret == QMessageBox::Ok)
							delHost(i);
					}
				}
			}

			// Zoom menu
			if ( item == 0)
			{
				QAction *zIn = new QAction("Zoom in",this);
				QAction *zOut = new QAction("Zoom out",this);
				QMenu popup(this);
				popup.addAction(zIn);
				popup.addAction(zOut);
				QAction *selectedItem = popup.exec(mapToGlobal(mouse->pos()));
				if (selectedItem == zIn)
					ui->graphicsView->scale(1.5,1.5);
				else if (selectedItem == zOut)
					ui->graphicsView->scale(1/1.5,1/1.5);
			}
		}
	}
	return false;
}

// Convert in_addr to QString
QString MainWindow::ipv4str(in_addr adr)
{
	QString str = QString::number(adr.S_un.S_un_b.s_b1)+".";
	str += QString::number(adr.S_un.S_un_b.s_b2)+".";
	str += QString::number(adr.S_un.S_un_b.s_b3)+".";
	str += QString::number(adr.S_un.S_un_b.s_b4);
	return str;
}

// Convert in6_addr to QString
QString MainWindow::ipv6str(in6_addr adr)
{
	QString str;
	for (int i=0; i<16; i+=2)
	{
		str += QString().sprintf("%02x",adr.byte[i]);
		str += QString().sprintf("%02x",adr.byte[i+1]);
		if (i!=14)
			str +=":";
	}
	return str;
}

// Convert MAC address to QString
QString MainWindow::mac2str(u_char *mac)
{
	QString str;
	for (int i=0; i<6; i++)
	{
		str += QString().sprintf("%02x",mac[i]);
		if (i!=5)
			str +="-";
	}
	return str;
}

// Add n spaces to string
QString MainWindow::expandStr(QString str,int n)
{
	while(str.size() < n)
		str += " ";
	return str;
}

// Move hosts if over each other
void MainWindow::detectOverlaping()
{
	for (int i=1; i<hosts.size()-1; i++)
	{
		for (int j=i+1; j<hosts.size(); j++)
		{
			if (hosts[i]->x() > hosts[j]->x() - 8 &&
				hosts[i]->x() < hosts[j]->x() + 8 &&
				hosts[i]->y() > hosts[j]->y() - 8 &&
				hosts[i]->y() < hosts[j]->y() + 8)
			{
				// Take horizonzaly apart
				if (hosts[i]->x() < hosts[j]->x())
				{
					hosts[i]->setX(hosts[i]->x()-1);
					hosts[j]->setX(hosts[j]->x()+1);
				}
				else
				{
					hosts[i]->setX(hosts[i]->x()+1);
					hosts[j]->setX(hosts[j]->x()-1);
				}

				// Take verticaly apart
				if (hosts[i]->y() < hosts[j]->y())
				{
					hosts[i]->setY(hosts[i]->y()-1);
					hosts[j]->setY(hosts[j]->y()+1);
				}
				else
				{
					hosts[i]->setY(hosts[i]->y()+1);
					hosts[j]->setY(hosts[j]->y()-1);
				}
			}
		}
	}
}

// Receive hostnames searched by QHostInfo::lookupHost
void MainWindow::lookedUp(const QHostInfo &host)
{
	if (host.error() != QHostInfo::NoError)
		return;
	for (int i=0; i<hosts.size(); i++)
	{
		QString adr;
		if (hosts[i]->getIPv4(0) != "")
			adr = hosts[i]->getIPv4(0);
		else if (hosts[i]->getIPv6(0) != "")
			adr = hosts[i]->getIPv6(0);
		if (adr != "")
			foreach (const QHostAddress &address, host.addresses())
				if (adr.left(5) != host.hostName().left(5) && // Error detection fail
					adr == address.toString())
				{
					hosts[i]->setName(host.hostName());
					hosts[i]->detectIcon();
				}
	}
}

// Menu File->Exit
void MainWindow::on_actionExit_triggered()
{
	close();
}
