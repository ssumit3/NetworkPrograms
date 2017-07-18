#include <bits/stdc++.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
using namespace std;

uint16_t checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}


int main(int argc, char const *argv[])
{
	struct protoent *proto = getprotobyname("ICMP");
	int protocol=1;
	int rsfd=socket(AF_INET,SOCK_RAW,1);
  int on=1;
  setsockopt(rsfd,IPPROTO_IP,IP_HDRINCL,&on,sizeof(int));
 	int ident = getpid() & 0xFFFF;
  int seqno=1;
  int hopcnt=1;
  while(1)
  {
    sockaddr_in send_addr,recv_addr;
    socklen_t send_addr_len,recv_addr_len;
    send_addr.sin_family = AF_INET;
    send_addr.sin_port=htons(0);
    inet_aton(argv[1],&send_addr.sin_addr);
    send_addr_len=sizeof(send_addr);
  
   	timeval *t1,t2;
   	char buf[100];
    	
   	char recvbuf[100];
   	memset(buf,'\0',sizeof(buf));
   	memset(recvbuf,'\0',sizeof(recvbuf));
    	
   	struct iphdr * sndip= (struct iphdr *)buf;
   	sndip->version=(unsigned int)4;
		sndip->ihl=(unsigned int)5;
		sndip->id=0;
		sndip->tos=(unsigned int)0;
		sndip->tot_len=htons(sizeof(iphdr)+sizeof(icmp)+sizeof(timeval));
		sndip->ttl=(unsigned int)hopcnt++;
		sndip->protocol=(unsigned int)1;
		
		sndip->daddr=inet_addr(argv[1]);
		sndip->check=checksum ((uint16_t *)(buf),sizeof(iphdr));
		    
   	struct icmphdr *icp = (struct icmphdr *) (buf+sizeof(iphdr));
   	icp->type = ICMP_ECHO;
		icp->code = 0;
		icp->checksum = 0;
		icp->un.echo.sequence = seqno++;
		icp->un.echo.id= ident;
		icp->checksum=checksum((uint16_t *)(buf+20),sizeof(icmphdr));
		t1=(struct timeval *)(buf+sizeof(iphdr)+sizeof(icmphdr));
		gettimeofday((struct timeval *)t1,NULL);
		sendto(rsfd,buf,sizeof(iphdr)+sizeof(icmphdr),0,(struct sockaddr *) &send_addr,sizeof(send_addr));
   	perror("error ::");
   	recv_addr_len=sizeof(recv_addr);
    recvfrom(rsfd,recvbuf,sizeof(recvbuf),0,(struct sockaddr *) &recv_addr,&recv_addr_len);
    perror(" error ");
    gettimeofday(&t2,NULL);
    struct ip *ips=(struct ip *)recvbuf;
    int iplen=ips->ip_hl<<2;
    struct icmp * recvicmp=(struct icmp *)(recvbuf+iplen);
    	//t1=(struct timeval *)recvicmp->icmp_data;
    //cout<<t1->tv_sec<<"  "<<t2.tv_sec<<" are times \n";
    if((t2.tv_usec-=t1->tv_usec)<0)
    {
    		t2.tv_usec+=1000000;
    		t2.tv_sec--;
    }
    	t2.tv_sec-=t1->tv_sec;
    	double rtt=t2.tv_sec*1000.0 +t2.tv_usec/1000.0;
    	int icmplen=100-iplen;
    	if(recvicmp->icmp_type!=0)
      {
        cout<<"hop "<<hopcnt-1<<"from "<<inet_ntoa(recv_addr.sin_addr)<<endl;

      }
      else
      {
          cout<<"reached destination in hops "<<hopcnt-1<<"from "<<inet_ntoa(recv_addr.sin_addr)<<endl;        
          break;
      }
      //printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%f ms \n",icmplen,argv[1],recvicmp->icmp_seq,ips->ip_ttl,rtt);
    	sleep(1);
    }
	return 0;
}