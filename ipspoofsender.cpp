//use ./receiver program itself to receive
 #include <bits/stdc++.h>
 #include <sys/types.h>          
 #include <sys/socket.h>
 #include <arpa/inet.h>
 #include <netinet/in.h>
 #include <linux/ip.h>
 using namespace std;
 int main(int argc, char const *argv[])
 {
 	int protocol=240,on=1;
 	int rsfd=socket(AF_INET,SOCK_RAW,protocol);
 	char buf[1000];
 	struct iphdr *ip=(struct iphdr *)buf;
 	setsockopt(rsfd,IPPROTO_IP,IP_HDRINCL,&on,sizeof(int));
 	ip->ihl         = 7;
    ip->version     = 4;
    ip->tot_len     = sizeof(buf);
    ip->protocol    = 240;
    ip->ttl 		=htons(64);
    ip->saddr       = inet_addr("192.168.192.5");
    ip->daddr       = inet_addr("127.0.0.1");
    strcpy(buf+28,"hello");

     sockaddr_in cli_addr;
     socklen_t cli_addr_len;
 	 cli_addr.sin_family = AF_INET;
     cli_addr_len=sizeof(cli_addr);
     //char bf[4];
     //strcpy(buf+20,"lol");
     //setsockopt(rsfd,IPPROTO_IP,IP_OPTIONS,bf,sizeof(bf));
     //perror(" sock opt error");
    while(1)
    {
    	sendto(rsfd,buf,sizeof(buf),0,(sockaddr *)&cli_addr,cli_addr_len);
    	perror(" error in send ::");//break;

    }
 	return 0;
 }