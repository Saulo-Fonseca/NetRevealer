// Aluno: Saulo Queiroz da Fonseca.
// Numero: 1100890.
// UC: Projeto Final - NetRevealer
// Segundo semestre de 2013/2014.
// Criado com o Qt v. 5.2.1 rodando no Windows 8

#include "host.h"

// Constructor
host::host()
{
	icon = 0;
	sent = 0;
	received = 0;
	setZValue(1);
	setFlag(ItemIsMovable);
	setFlag(ItemSendsGeometryChanges);
	setCacheMode(DeviceCoordinateCache);
	broadcastTime = QTime(0,0,0);
}

// Add IPv4
void host::addIPv4(QString s)
{
	if (s != "")
	{
		bool exist = false;
		foreach (QString str, ipv4)
		{
			if (s == str)
			{
				exist = true;
				break;
			}
		}
		if (!exist)
			ipv4.push_front(s);
	}
}

// Add IPv6
void host::addIPv6(QString s)
{
	if (s != "")
	{
		s = s.left(39);
		bool exist = false;
		foreach (QString str, ipv6)
		{
			if (s == str)
			{
				exist = true;
				break;
			}
		}
		if (!exist)
			ipv6.push_front(s);
	}
}

// Add Mac Address
void host::addMac(QString s)
{
	if (s != "")
	{
		s = s.left(17);
		bool exist = false;
		foreach (QString str, mac)
		{
			if (s == str)
			{
				exist = true;
				break;
			}
		}
		if (!exist)
			mac.push_front(s);
	}
}

// Sort ports
template<class T, class M>
void host::insertSort(QVector<M> &vec, T (M::*var))
{
	if (vec.size() > 1)
	{
		for (int i = 1; i < vec.size(); i++)
		{
			int j = i;
			while (j > 0 && vec[j-1].*var > vec[j].*var)
			{
				M tmp = vec[j];
				vec[j] = vec[j-1];
				vec[j-1] = tmp;
				j--;
			}
		}
	}
}

// Clean all but interface data
void host::reset()
{
	ports.clear();
	broadcastTime = QTime(0,0,0);
	sent = 0;
	received = 0;
}

// Add port
void host::addPort(int value, int protocol)
{
	bool present = false;
	for (int i=0; i<ports.size(); i++)
	{
		if (value == ports[i].value &&
			protocol == ports[i].protocol)
		{
			present = true;
			break;
		}
	}
	if (!present)
	{
		port temp;
		temp.value = value;
		temp.protocol = protocol;
		ports.append(temp);
		insertSort(ports,&port::value);
		insertSort(ports,&port::protocol);
	}
}

// Check if the host already exists
bool host::exists(QString str)
{
	foreach (QString s, ipv4)
		if (s == str)
			return true;
	foreach (QString s, ipv6)
		if (s == str)
			return true;
	foreach (QString s, mac)
		if (s == str)
			return true;
	return false;
}

// Define the angle for a child host
void host::angle(host *h)
{
	double ang, x, y, dist = this->x()*this->x() + this->y()*this->y();
	do
	{
		ang = qrand()%628;
		x = this->x()+sin(ang)*100;
		y = this->y()+cos(ang)*100;
	} while (x*x + y*y < dist+84);
	h->setPos(x,y);
}

// Create info about the host
QStringList host::info()
{
	QStringList hostInfo;

	// Add hostname
	if (name != "")
		hostInfo.append("Hostname: "+name);

	// Add IPv4 and netmask
	for (int i=0; i<ipv4.size(); i++)
	{
		if (ipv4.size() == 1)
			hostInfo.append("IPv4: "+ipv4[i]);
		else
			hostInfo.append("IPv4 nr."+QString::number(i+1)+": "+ipv4[i]);
		if (mask.size() != 0)
		{
			if (mask.size() == 1)
				hostInfo.append("Mask: "+mask[i]);
			else
				hostInfo.append("Mask nr."+QString::number(i+1)+": "+mask[i]);
		}
	}

	// Add IPv6
	for (int i=0; i<ipv6.size(); i++)
	{
		if (ipv6.size() == 1)
			hostInfo.append("IPv6: "+shortIPv6(ipv6[i]));
		else
			hostInfo.append("IPv6 nr."+QString::number(i+1)+": "+shortIPv6(ipv6[i]));
	}

	// Add mac
	for (int i=0; i<mac.size(); i++)
	{
		if (mac.size() == 1)
			hostInfo.append("Mac: "+mac[i]);
		else
			hostInfo.append("Mac nr."+QString::number(i+1)+": "+mac[i]);
	}

	// Add Packets sent / received
	hostInfo.append("Packets sent: "+QString::number(sent));
	hostInfo.append("Packets received: "+QString::number(received));

	// Add ports
	if (!ports.empty())
	{
		hostInfo.append("Receive a packet to port:");
		for (int i=0; i<ports.size(); i++)
		{
			QString linha = iana::getProtocol(ports[i].protocol)+" ";
			linha += QString("%1").arg(ports[i].value,5);
			if (ports[i].protocol == 6) // TCP
				linha += " "+iana::getTCP(ports[i].value);
			if (ports[i].protocol == 17) // UDP
				linha += " "+iana::getUDP(ports[i].value);
			hostInfo.append(linha);
		}
	}
	return hostInfo;
}

// Add packet to list
void host::addPacket(packet *pkt)
{
	bool present = false;
	foreach (packet *p, packets)
	{
		if (p == pkt)
		{
			present = true;
			break;
		}
	}
	if (!present)
	{
		packets.append(pkt);
		pkt->update();
	}
}

// Return true if the address is a broadcast
bool host::broadcast(QString str)
{
	// IPv4
	if (str.contains("."))
	{
		// Broadcast
		if (str == "255.255.255.255")
			return true;

		else foreach (QString msk, mask)
		{
			// Subnet broadcast (like 192.168.0.255)
			if ((~(ip2int(msk))) == (ip2int(str) & (~(ip2int(msk)))))
				return true;

			// Subnet address (like 192.168.0.0)
			else if ((ip2int(str) & (~(ip2int(msk)))) == 0)
				return true;
		}

		// Network addres as broadcast
		if (str == "0.0.0.0")
			return true;

		// IPv4 multicast
		QString multicast = "224.0.0.0";
		QString multicasMask = "240.0.0.0";
		if ((ip2int(multicast) & ip2int(multicasMask)) ==
				  (ip2int(str) & ip2int(multicasMask)))
			return true;
		return false;
	}

	// IPv6 multicast
	else if (str.left(3) == "ff0" || str.left(4) == "ff3" ||
			 str == "0000:0000:0000:0000:0000:0000:0000:0000" ||
			 str == "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
		return true;

	// Mac Address
	else if (str == "ff-ff-ff-ff-ff-ff")
		return true;
	return false;
}

// Remove packet from this host
void host::removePacket(packet *p)
{
	for (int i=0; i<packets.size(); i++)
		if (packets[i] == p)
			packets.erase(packets.begin() + i--);
}

// Confirm if a host is in the local subnet
bool host::subnet(QString str)
{
	if (str.contains("."))
	{
		// IPv4
		for (int i=0; i<ipv4.size(); i++)
			if ((ip2int(ipv4[i]) & ip2int(mask[i])) ==
				(ip2int(str) & ip2int(mask[i])))
				return true;
		return false;
	}
	else if (str.contains(":"))
	{
		// IPv6
		for (int i=0; i<ipv6.size(); i++)
			if (ipv6[i].left(20) == str.left(20))
				return true;
		return false;
	}
	return true; // If it is a Mac Address
}

// Convert a string IP address in a 32 bits unsigned int
uint host::ip2int(QString str)
{
	uint bits = 0, byte = 3;
	QStringList tokens(str.split("."));
	foreach (QString s, tokens)
	{
		bits += s.toInt();
		if (byte != 0) bits = bits << 8;
		byte--;
	}
	return bits;
}

// Display host
void host::paint(QPainter *painter, const QStyleOptionGraphicsItem *, QWidget*)
{
	// Draw broadcast circle
	if (broadcastTime != QTime(0,0,0))
	{
		if (broadcastTime.msecsTo(QTime::currentTime()) < 200)
			painter->setPen(QColor(255,133,0)); // Orange
		else
			painter->setPen(Qt::black);
		painter->setBrush(QBrush(Qt::white));
		painter->drawEllipse(boundingRect());
	}

	// Draw icon
	QRectF target(-16,-16,32,32);
	QRectF source(0,0,32,32);
	painter->drawPixmap(target,icons[icon],source);
}

// Shorts the IPv6 address
QString host::shortIPv6(QString ip)
{
	// Remove leading zeros
	while (ip.left(1) == "0")
		ip = ip.right(ip.length()-1);
	for (int i=0; i<3; i++)
		ip.replace(":0",":");

	// Colapse zeros to ::
	QString temp = ":0:0";
	do
		temp += ":0";
	while (ip.contains(temp));
	temp = temp.right(temp.size()-2);
	if (ip.indexOf(temp) != -1)
	{
		if (ip.right(temp.size()) == temp)
			ip.replace(ip.indexOf(temp),temp.size(),"::0");
		else
			ip.replace(ip.indexOf(temp),temp.size(),":");
	}
	return ip;
}

// Run if position change
QVariant host::itemChange(QGraphicsItem::GraphicsItemChange change,
	const QVariant& value)
{
	if (change == ItemPositionHasChanged)
	{
		foreach (packet *p, packets)
			p->update();
	}
	return QGraphicsItem::itemChange(change, value);
}

// Define the limits of the object
QRectF host::boundingRect() const
{
	return QRectF(-20,-20,40,40);
}

// Set host icon
void host::detectIcon()
{
	QString name = this->name.toLower();
	// Smartphone
	if (name.contains("phone") ||
		name.contains("droid") ||
		name.contains("galaxy") ||
		name.contains("sony") ||
		name.contains("berry") ||
		name.contains("lg") ||
		name.contains("fone") ||
		name.contains("huawei") ||
		name.contains("alcatel") ||
		name.contains("meizu") ||
		name.contains("motorola") ||
		name.contains("nokia") ||
		name.contains("xiaomi") ||
		name.contains("htc"))
		icon = 3; // Phone

	// Tablet
	else if (name.contains("pad") ||
		name.contains("acer") ||
		name.contains("asus") ||
		name.contains("lenovo") ||
		name.contains("nook") ||
		name.contains("nexus") ||
		name.contains("kindle") ||
		name.contains("tesco") ||
		name.contains("surface") ||
		name.contains("dell") ||
		name.contains("logitech") ||
		name.contains("tab"))
		icon = 4; // Tablet

	// wRouter
	else if (name.contains("router") ||
		name.contains("fritz") ||
		name.contains("speed") ||
		name.contains("gtw") ||
		name.contains("link") ||
		name.contains("netgear"))
		icon = 7; // wRouter

	// Router
	else if (name.contains("cisco") ||
		name.contains("buffalo") ||
		name.contains("3com") ||
		name.contains("belkin") ||
		name.contains("zyxel") ||
		name.contains("airport") ||
		name.contains("capsule") ||
		name.contains("vigor") ||
		name.contains("bintec") ||
		name.contains("gate") ||
		name.contains("a-msr") ||
		name.contains("mikrotik") ||
		name.contains("sonicwall") ||
		name.contains("switch") ||
		name.contains("netiron") ||
		name.contains("tew"))
		icon = 6; // Router

	// Server
	else if (name.contains("dhcp") ||
		name.contains("firewall") ||
		name.contains("domain") ||
		name.contains("dc") ||
		name.contains("dns") ||
		name.contains("server") ||
		name.contains("mail") ||
		name.contains("sql") ||
		name.contains("citrix") ||
		name.contains("data") ||
		name.contains("file") ||
		name.contains("sap") ||
		name.contains("exchange") ||
		name.contains("net") ||
		name.contains("druck") ||
		name.contains("print") ||
		name.contains("ftp") ||
		name.contains("www") ||
		name.contains("http") ||
		name.contains("web"))
		icon = 5; // Rack
}
