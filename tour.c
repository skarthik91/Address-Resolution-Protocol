#include "hw_addrs.h"

#define IP_PROTOCOL 1385


struct IP_Payload *ptrippayload_send,*ptrippayload_rcv;



int main(int argc, char const *argv[])
{
	
	char sourcevm[5];
	int i,pg,rt,udpsend_socket,pf_socket,udprecv_socket;
	const int on = 1;
	char list[argc][MAXLINE];
	struct hostent *he;
	char **ip;
	
	
	
	
	if(argc < 1)
    {
        printf("error");
    }
	
	
	//creating 4 sockets two IP raw socket, PF_Packet, UDP socket 
	
	//ping socket for receiving ICMP echo reply messages
	pg = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	
	if(pg < 0)
    {
        printf("error in creating ping socket\n");
    }
	
	
	//route traversal socket
	rt= socket(AF_INET, SOCK_RAW, IP_PROTOCOL);
    if(rt < 0)
    {
        printf("error in creating route traversal socket\n");
    }
	
	
	//setting socket option for rt socket to IP_HDRINCL
	if (setsockopt(rt, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		 printf("error while set socket to IP_HDRINCL\n");
	}


    //pf packet socket for sending echo request
	
	pf_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	
	if(pf_socket < 0)
	{
		printf("error in creating pf packet socket\n");
	}
   
    //UDP Socket for multicast communication
	udpsend_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if(udpsend_socket < 0)
    {
         printf("error in creating udp socket\n");
    }

	udprecv_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if(udprecv_socket < 0)
    {
         printf("error in creating udp socket\n");
    }
	
	
	
	gethostname(sourcevm, sizeof sourcevm);
	
	//Checking for first node, which cannot be source node
	if(strcmp(argv[1],sourcevm) == 0){
		printf("Cannot Start with Source vm. Enter different node \n");
	}
	
	//Checking for Consecutive nodes.consecutive nodes cannot be same
	for(i=1;i<argc;i++){
		if(strcmp(argv[i],argv[i-1]) == 0){
			printf("Consecutive Nodes cannot be same. Enter different node \n");
		}
	}
	
	
	/* he = gethostbyname(sourcevm);
	if (he == NULL) { 
		herror("gethostbyname");
		exit(1);
	}
				
	
	
	listtour[0] =  */
	
	
	//creating IP payload 
	/* for(i=0;i<argc;i++){
		
	} */
	
	
}