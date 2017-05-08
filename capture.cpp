// Aluno: Saulo Queiroz da Fonseca.
// Numero: 1100890.
// UC: Projeto Final - NetRevealer
// Segundo semestre de 2013/2014.
// Criado com o Qt v. 5.2.1 rodando no Windows 8

#include "iana.h"
#include <QtEndian>
#include "mainwindow.h"
#include "ui_mainwindow.h"

// Process captured packet
void MainWindow::onPacket(u_char*, const struct pcap_pkthdr *header,
	const u_char *packet)
{
	QString source;
	QString destination;
	QString portSrc;
	QString portDst;
	QString toList;
	QString macSrc;
	QString macDst;
	int port=-1, protocol=-1;

	// Capture Ethernet and IP headers
	if (header->caplen < sizeof(ETHERNET))
		return;
	ETHERNET *frame = (ETHERNET*)(packet);

	// Process IPv4 packet
	if (qFromBigEndian(frame->type) == 0x0800)
	{
		// Capture header
		if (header->caplen < sizeof(ETHERNET)+sizeof(IPv4))
			return;
		IPv4 *ip = (IPv4*)(packet + sizeof(ETHERNET));

		// Get source and destination
		source = ipv4str(ip->source);
		destination = ipv4str(ip->destination);

		// If TCP or UDP, capture ports
		if (ip->protocol == 6 || ip->protocol == 17)
		{
			u_int tcp_size = (ip->vhl & 0x0f)*4;
			if (tcp_size < sizeof(IPv4)) return;
			if (header->caplen < sizeof(ETHERNET)+tcp_size+sizeof(TCP_or_UDP))
				return;
			TCP_or_UDP *tcp = (TCP_or_UDP*)
				(packet + sizeof(ETHERNET) + tcp_size);
			portSrc = QString::number(qFromBigEndian(tcp->source_port));
			port = qFromBigEndian(tcp->destination_port);
			portDst = QString::number(port);
		}

		// Add protocol
		toList += "Protocol:";
		protocol = ip->protocol;
		toList += iana::getProtocol(protocol);
	}
	else // Process IPv6 packet
	if (qFromBigEndian(frame->type) == 0x86dd)
	{
		// Capture header
		if (header->caplen < sizeof(ETHERNET)+sizeof(IPv6))
			return;
		IPv6 *ip = (IPv6*)(packet + sizeof(ETHERNET));

		// Get source and destination
		source = ipv6str(ip->source);
		destination = ipv6str(ip->destination);

		// If TCP or UDP, capture ports
		if (ip->next_header == 6 || ip->next_header == 17)
		{
			if (header->caplen<sizeof(ETHERNET)+sizeof(IPv6)+sizeof(TCP_or_UDP))
				return;
			TCP_or_UDP *tcp = (TCP_or_UDP*)
				(packet + sizeof(ETHERNET) + sizeof(IPv6));
			portSrc = QString::number(qFromBigEndian(tcp->source_port));
			port = qFromBigEndian(tcp->destination_port);
			portDst = QString::number(port);
		}

		// Add protocol
		toList += "Protocol:";
		protocol = ip->next_header;
		toList += iana::getProtocol(protocol);
	}
	else // Show other protocols
	{
		source = mac2str(frame->source);
		destination = mac2str(frame->destination);
		toList += "Protocol:";
		toList += iana::getEtherType(qFromBigEndian(frame->type));
	}

	// Add host
	macSrc = mac2str(frame->source);
	macDst = mac2str(frame->destination);
	if (!broadcast && hosts[0]->broadcast(destination))
		return;
	addHost(source,destination,macSrc,macDst,port,protocol);

	// Add item to listWidget
	if (source.contains(":"))
		source = host::shortIPv6(source);
	if (destination.contains(":"))
		destination = host::shortIPv6(destination);
	static int count = 0;
	static int maxItens = 50;
	toList = expandStr(toList,21);
	toList += "Source:";
	toList += source;
	if (portSrc != "")
		toList += ":"+portSrc;
	toList = expandStr(toList,74);
	toList += "Destination:";
	toList += destination;
	if (portDst != "")
		toList += ":"+portDst;
	ui->listWidget->addItem(toList);
	ui->listWidget->scrollToBottom();
	count ++;
	if (count > maxItens)
		ui->listWidget->removeItemWidget(ui->listWidget->takeItem(0));
}

// Add a new host
void MainWindow::addHost(QString source, QString destination, QString macSrc,
	QString macDst, int port=-1, int protocol=-1)
{
	// Avoid DHCP requests
	if (source == "0.0.0.0" ||
		source == "0000:0000:0000:0000:0000:0000:0000:0000")
		source = macSrc;

	// Search if hosts are already present
	int lastSrc = 0;
	int lastDst = 0;
	bool srcPresent = false;
	bool dstPresent = false;
	for (int i=0; i<hosts.size(); i++)
	{
		if  (hosts[i]->exists(source) ||
			(hosts[i]->exists(macSrc) && hosts[0]->subnet(source)))
		{
			srcPresent = true;
			if (source.contains("."))
				hosts[i]->addIPv4(source);
			else if (source.contains(":"))
				hosts[i]->addIPv6(source);
			if (hosts[0]->subnet(source))
				hosts[i]->addMac(macSrc);
			if (hosts[i]->getName() == "")
				QHostInfo::lookupHost(source,this,SLOT(lookedUp(QHostInfo)));
			hosts[i]->setTime(QTime::currentTime());
			hosts[i]->incSnd();
			lastSrc = i;
		}
		if  (hosts[i]->exists(destination) ||
			(hosts[i]->exists(macDst) && hosts[0]->subnet(destination)))
		{
			dstPresent = true;
			if (port != -1)
				hosts[i]->addPort(port,protocol);
			if (destination.contains("."))
				hosts[i]->addIPv4(destination);
			else if (destination.contains(":"))
				hosts[i]->addIPv6(destination);
			if (hosts[0]->subnet(destination))
				hosts[i]->addMac(macDst);
			if (hosts[i]->getName() == "")
				QHostInfo::lookupHost(destination,this,SLOT(lookedUp(QHostInfo)));
			hosts[i]->setTime(QTime::currentTime());
			hosts[i]->incRcv();
			lastDst = i;
		}
	}

	// Add source host
	if (!srcPresent)
	{
		// Create a new host
		host *newHost = new host();
		newHost->setIcon(1);
		if (source.contains("."))
			newHost->addIPv4(source);
		else if (source.contains(":"))
			newHost->addIPv6(source);
		if (hosts[0]->subnet(source))
		{
			newHost->addMac(macSrc);
			newHost->setIcon(2);
		}
		newHost->setTime(QTime::currentTime());
		newHost->incSnd();
		QHostInfo::lookupHost(source,this,SLOT(lookedUp(QHostInfo)));
		hosts[0]->angle(newHost);

		// Add host to view
		scene->addItem(newHost);
		hosts.append(newHost);
		lastSrc = hosts.size()-1;
		detectOverlaping();
	}

	// Verifies if destination is a broadcast
	if (hosts[0]->broadcast(destination))
		hosts[lastSrc]->setBroadcastTime(QTime::currentTime());

	// Add destination host
	else
	{
		if (!dstPresent)
		{
			// Create a new host
			host *newHost = new host();
			newHost->setIcon(1);
			if (destination.contains("."))
				newHost->addIPv4(destination);
			else if (destination.contains(":"))
				newHost->addIPv6(destination);
			if (hosts[0]->subnet(destination))
			{
				newHost->addMac(macDst);
				newHost->setIcon(2);
			}
			newHost->setTime(QTime::currentTime());
			newHost->incRcv();
			QHostInfo::lookupHost(destination,this,SLOT(lookedUp(QHostInfo)));
			hosts[lastSrc]->angle(newHost);
			if (port != -1)
				newHost->addPort(port,protocol);

			// Add host to view
			scene->addItem(newHost);
			hosts.append(newHost);
			lastDst = hosts.size()-1;
			detectOverlaping();
		}

		// Search if packet from source to destination was already sent
		bool find = false;
		for (int i=0; i<hosts[lastSrc]->getPackets().size(); i++)
		{
			if (hosts[lastSrc]->getPackets()[i]->getSrc() == hosts[lastDst] ||
				hosts[lastSrc]->getPackets()[i]->getDst() == hosts[lastDst])
			{
				hosts[lastSrc]->getPackets()[i]->setTime(QTime::currentTime());
				find = true;
				break;
			}
		}

		// Search if packet from destination to source was already sent
		if (!find)
		{
			for (int i=0; i<hosts[lastDst]->getPackets().size(); i++)
			{
				if (hosts[lastDst]->getPackets()[i]->getSrc() == hosts[lastSrc] ||
					hosts[lastDst]->getPackets()[i]->getDst() == hosts[lastSrc])
				{
					hosts[lastDst]->getPackets()[i]->setTime(QTime::currentTime());
					find = true;
					break;
				}
			}
		}

		// If it's new
		if (!find)
		{
			packet *p = new packet(hosts[lastSrc],hosts[lastDst]);
			scene->addItem(p);
		}
	}
}
