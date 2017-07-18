# NetworkPrograms
contains implementation of some network commands like ping and traceroute also a simple ip spoof program . The ping command is implemented by sending ICMP echo requets and the traceroute uses hopcount to find the intermediate routers in reaching the destination . 
the ipspoof program creates its own ipheader and uses raw sockets 
there is also a simple net stopping program which stops the net of other devices connected to same router by sending false arp messages to the router
