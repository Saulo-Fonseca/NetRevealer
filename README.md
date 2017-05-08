# NetRevealer
NetRevealer is a multi-platform graphical tool to analyze 
the traffic in your network. It reads the interface cards in your computer and 
draw an icon for each host / device sending or receiving packets. The map shows 
the traffic in real time and allows you to detect unwanted activities such as 
backdoors and people not allowed to use your network.

The program can be compiled on Windows, Mac and Linux. It was made as a project for 
Saulo Fonseca's bachelor's degree at Portugal Open University and was written in C++
using the Qt-Framework and Libpcap. It's available under the GPL3 license (open source).

# What it can do:
Allows to move, pan, zoom and delete the map / icons.

Shows a log for all packets read at window's bottom.

Permits to select a limit to delete inactive hosts after a while.

Permits to select which network cards should be read.

Show the broadcast packets as a circle around the hosts.

Collects and shows information about every host such as:
- Hostname.
- IPv4 / IPv6 addresses.
- Netmask.
- MAC Address.
- Number of packets sent or received.
- Ports used by other hosts.

Created with Qt 5.2.1. You need to install Libpcap to compile it.

Video at https://player.vimeo.com/video/100517892

Downloads at http://www.astrotown.de/netrevealer
