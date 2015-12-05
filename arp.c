//
//  arp.c
//
//
//  Created by Karthikeyan Swaminathan on 11/29/15.
//
//


#include "unp.h"
#include <linux/if_ether.h>
#include <setjmp.h>
#include <net/ethernet.h>
#include <sys/un.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <errno.h>
#include "hw_addrs.h"

#include <linux/if_packet.h>

#define PROTOCOL 62357     //Unique protocol
#define SOURCEPORT 13855
#define SERVERPORT 13854
#define ARP_PATH "kimi"   //Unique sun path
#define ETH_HDRLEN 14      // Ethernet header length
#define IP4_HDRLEN 20      // IPv4 header length
#define ARP_HDRLEN 30      // ARP header length
#define ARPOP_REQUEST 1    // Taken from <linux/if_arp.h>
#define GROUP_ID 3571       //Group Unique ID for the team
#define ETH_FRAME_LENGTH 1500
// Function prototypes
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);



/*Global Declarations*/
char ip_canonical[INET_ADDRSTRLEN];
unsigned char mac_address[IF_HADDR];
int if_index;
int pf_packet;


// Define a struct for ARP header
typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
    uint16_t id;
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sender_mac[6];
    char sender_ip[16];
    uint8_t target_mac[6];
    char target_ip[16];
}*parphdr_send,*parphdr_rcv;

//typedef struct _Ethernet_hdr Ethernet_Hdr;
struct Ethernet_hdr{
    unsigned char destMAC[6];
    unsigned char sourceMAC[6];
    uint16_t frame_type;
}*pethframehdr_send,*pethframehdr_rcv;



struct arp_cache{
    int sll_ifindex;
    int socketfd;
    unsigned short sll_hatype;
    unsigned char sll_addr[8];
    unsigned char IP[INET_ADDRSTRLEN];
    int valid;
    
}arpcache[50];

int ip_hwaddr()
{
    struct hwa_info	*hwa, *hwahead;
    struct sockaddr	*sa;
    char   *ptr;
    int    i, prflag;
    
    printf("\n");
    
    for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next)
    {
        if (strncmp(hwa->if_name, "eth0",4) == 0)
        {
            printf("The IP address and Ethernet MAC address pairs for interface eth0 are : \n");
            printf("%s :%s", hwa->if_name, ((hwa->ip_alias) == IP_ALIAS) ? " (alias)\n" : "\n");
            
            if ( (sa = hwa->ip_addr) != NULL)
            {
                printf("           IP address is %s \n", Sock_ntop_host(sa, sizeof(*sa)));
                if_index=hwa->if_index;
                
                memcpy(ip_canonical,Sock_ntop_host(sa, sizeof(*sa)),16);
                memcpy(mac_address,hwa->if_haddr,6);
            }
            
            prflag = 0;
            i = 0;
            do {
                if (hwa->if_haddr[i] != '\0') {
                    prflag = 1;
                    break;
                }
            } while (++i < IF_HADDR);
            
            if (prflag) {
                printf("           MAC Address = ");
                ptr = hwa->if_haddr;
                i = IF_HADDR;
                //int j=0;
                do {
                    
                    printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
                    
                } while (--i > 0);
            }
            
            printf("\n           Interface index is %d \n",if_index);
            
        }
        
    }
    free_hwa_info(hwahead);
    printf("\n");
    
    return 0;
}

// Allocate memory for an array of chars.
char *
allocate_strmem (int len)
{
    void *tmp;
    
    if (len <= 0) {
        fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
        exit (EXIT_FAILURE);
    }
    
    tmp = (char *) malloc (len * sizeof (char));
    if (tmp != NULL) {
        memset (tmp, 0, len * sizeof (char));
        return (tmp);
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
        exit (EXIT_FAILURE);
    }
}

// Allocate memory for an array of unsigned chars.
uint8_t *
allocate_ustrmem (int len)
{
    void *tmp;
    
    if (len <= 0) {
        fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
        exit (EXIT_FAILURE);
    }
    
    tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
    if (tmp != NULL) {
        memset (tmp, 0, len * sizeof (uint8_t));
        return (tmp);
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
        exit (EXIT_FAILURE);
    }
}

int find_mac_address(char resolve_ip[INET_ADDRSTRLEN],char src_ip[INET_ADDRSTRLEN])
{
    int j;
    struct hwa_info	*hwa, *hwahead;
    char   *ptr;
    int    i;
    /*target address*/
    struct sockaddr_ll socket_address;
    unsigned char src_mac[6];
  
    int send_result = 0;
    
    for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next)
    {
        if (strncmp(hwa->if_name, "eth0",4) == 0)
        {
        ptr = hwa->if_haddr;
        i = IF_HADDR;
        j=0;
        /*Loading source Mac Address*/
        do{
            src_mac[j] = *ptr++ & 0xff;
        } while (--i > 0 && j++ < 5);
        
        
        
        /*buffer for ethernet frame*/
        void* buffer = (void*)malloc(ETH_FRAME_LENGTH);
        
        /*pointer to ethenet header*/
        //unsigned char* etherhead = buffer;
        pethframehdr_send = buffer;
        
        /*userdata in ethernet frame*/
        parphdr_send = (buffer + sizeof(struct Ethernet_hdr));
        
        
        
        /*other host MAC address*/
        unsigned char dest_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        // memcpy(buffer,src_mac,6);
        //memcpy(buffer+6,dest_mac,6);
        pethframehdr_send->frame_type=htons(PROTOCOL);
        
        parphdr_send->id=htons(GROUP_ID);
        parphdr_send->htype= htons(1);
        parphdr_send->ptype = htons(0x800);
        parphdr_send->hlen = htons(6);
        parphdr_send->plen = htons(4);
        parphdr_send->opcode = htons(ARPOP_REQUEST);
        
        memcpy(parphdr_send->sender_mac,src_mac,ETH_ALEN);
        memcpy(parphdr_send->sender_ip,src_ip,16);
        
        memset(parphdr_send->target_mac,0,ETH_ALEN);
        memcpy(parphdr_send->target_ip,resolve_ip,16);
        
        
        
        
        
        
        /*RAW communication*/
        socket_address.sll_family   = PF_PACKET;
        /*we don't use a protocoll above ethernet layer
         ->just use anything here*/
        socket_address.sll_protocol = htons(PROTOCOL);
        
        /*index of the network device
         see full code later how to retrieve it*/
        socket_address.sll_ifindex  = hwa->if_index;
        
        /*ARP hardware identifier is ethernet*/
        socket_address.sll_hatype   = 1;
        
        /*target is another host*/
        socket_address.sll_pkttype  = PACKET_BROADCAST;
        
        /*address length*/
        socket_address.sll_halen    = ETH_ALEN;
        /*MAC - begin*/
        socket_address.sll_addr[0]  = 0xff;
        socket_address.sll_addr[1]  = 0xff;
        socket_address.sll_addr[2]  = 0xff;
        socket_address.sll_addr[3]  = 0xff;
        socket_address.sll_addr[4]  = 0xff;
        socket_address.sll_addr[5]  = 0xff;
        /*MAC - end*/
        socket_address.sll_addr[6]  = 0x00;/*not used*/
        socket_address.sll_addr[7]  = 0x00;/*not used*/
        
        
        /*set the frame header*/
        /*set the frame header*/
        memcpy((void*)buffer, (void*)dest_mac, ETH_ALEN);
        memcpy((void*)(buffer+ETH_ALEN), (void*)src_mac, ETH_ALEN);
        /*send the packet*/
        send_result = sendto(pf_packet, buffer, ETH_FRAME_LENGTH, 0,
                             (struct sockaddr*)&socket_address, sizeof(socket_address));
        if (send_result == -1) {
            printf("Sending error : %d",errno);
            exit(1);
            
        }
        
        printf("\n Packet Sent \n");
        
        
        }
    }
    
    
    
    
    return 0;
    
}

//int find_mac_address(char resolve_ip[INET_ADDRSTRLEN],char src_ip[INET_ADDRSTRLEN],int pf_packet)
//{
//    int i, status, frame_length, sd, bytes;
//    char *interface, *target;
//    arp_hdr arphdr;
//    uint8_t *src_mac, *dst_mac, *ether_frame;
//    struct addrinfo hints, *res;
//    struct sockaddr_in *ipv4;
//    struct sockaddr_ll device;
//    struct ifreq ifr;
//
//    // Allocate memory for various arrays.
//    src_mac = allocate_ustrmem (6);
//    dst_mac = allocate_ustrmem (6);
//    ether_frame = allocate_ustrmem (IP_MAXPACKET);
//    interface = allocate_strmem (40);
//    target = allocate_strmem (40);
//    //src_ip = allocate_strmem (INET_ADDRSTRLEN);
//
//    // Interface to send packet through.
//    strcpy (interface, "eth0");
//
//    // Submit request for a socket descriptor to look up interface.
//    if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
//        perror ("socket() failed to get socket descriptor for using ioctl() ");
//        exit (EXIT_FAILURE);
//    }
//
//    // Use ioctl() to look up interface name and get its MAC address.
//    memset (&ifr, 0, sizeof (ifr));
//    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
//    if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
//        perror ("ioctl() failed to get source MAC address ");
//        return (EXIT_FAILURE);
//    }
//    close (sd);
//
//    // Copy source MAC address.
//    memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));
//
//    // Report source MAC address to stdout.
//    printf ("MAC address for interface %s is ", interface);
//    for (i=0; i<5; i++) {
//        printf ("%02x:", src_mac[i]);
//    }
//    printf ("%02x\n", src_mac[5]);
//
//    // Find interface index from interface name and store index in
//    // struct sockaddr_ll device, which will be used as an argument of sendto().
//    memset (&device, 0, sizeof (device));
//    if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
//        perror ("if_nametoindex() failed to obtain interface index ");
//        exit (EXIT_FAILURE);
//    }
//    printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);
//
//    // Set destination MAC address: broadcast address
//    memset (dst_mac, 0xff, 6 * sizeof (uint8_t));
//
//    // Source IPv4 address:  you need to fill this out
//    //strcpy (src_ip, "192.168.1.116");
//
//    // Destination URL or IPv4 address (must be a link-local node): you need to fill this out
//    strcpy (target, resolve_ip);
//
//    // Fill out hints for getaddrinfo().
//    memset (&hints, 0, sizeof (struct addrinfo));
//    hints.ai_family = AF_INET;
//    hints.ai_socktype = SOCK_STREAM;
//    hints.ai_flags = hints.ai_flags | AI_CANONNAME;
//
//
//    printf("\n Source Ip Address in find MAC addresS() is %s \n",src_ip);
//    // Source IP address
//    if ((status = inet_pton (AF_INET, src_ip, &arphdr.sender_ip)) != 1) {
//        fprintf (stderr, "inet_pton() failed for source IP address.\nError message: %s", strerror (status));
//        exit (EXIT_FAILURE);
//    }
//
//    // Resolve target using getaddrinfo().
//    if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
//        fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
//        exit (EXIT_FAILURE);
//    }
//    ipv4 = (struct sockaddr_in *) res->ai_addr;
//    memcpy (&arphdr.target_ip, &ipv4->sin_addr, 4 * sizeof (uint8_t));
//    freeaddrinfo (res);
//
//    // Fill out sockaddr_ll.
//    device.sll_family = AF_PACKET;
//    memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
//    device.sll_halen = 6;
//
//    // ARP header
//
//    // Group Identification 16 bits
//    arphdr.id = htons(GROUP_ID);
//
//    // Hardware type (16 bits): 1 for ethernet
//    arphdr.htype = htons (1);
//
//    // Protocol type (16 bits): 2048 for IP
//    arphdr.ptype = htons (ETH_P_IP);
//
//    // Hardware address length (8 bits): 6 bytes for MAC address
//    arphdr.hlen = 6;
//
//    // Protocol address length (8 bits): 4 bytes for IPv4 address
//    arphdr.plen = 4;
//
//    // OpCode: 1 for ARP request
//    arphdr.opcode = htons (ARPOP_REQUEST);
//
//    // Sender hardware address (48 bits): MAC address
//    memcpy (&arphdr.sender_mac, src_mac, 6 * sizeof (uint8_t));
//
//    // Sender protocol address (32 bits)
//    // See getaddrinfo() resolution of src_ip.
//
//    // Target hardware address (48 bits): zero, since we don't know it yet.
//    memset (&arphdr.target_mac, 0, 6 * sizeof (uint8_t));
//
//    // Target protocol address (32 bits)
//    // See getaddrinfo() resolution of target.
//
//    // Fill out ethernet frame header.
//
//    // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (ARP header)
//    frame_length = 6 + 6 + 2 + ARP_HDRLEN;
//
//    // Destination and Source MAC addresses
//    memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));
//    memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));
//
//    // Next is ethernet type code (ETH_P_ARP for ARP).
//    // http://www.iana.org/assignments/ethernet-numbers
//    ether_frame[12] = ETH_P_ARP / 256;
//    ether_frame[13] = ETH_P_ARP % 256;
//
//    // Next is ethernet frame data (ARP header).
//
//    // ARP header
//    memcpy (ether_frame + ETH_HDRLEN, &arphdr, ARP_HDRLEN * sizeof (uint8_t));
//
//    // Submit request for a raw socket descriptor.
////    if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
////        perror ("socket() failed ");
////        exit (EXIT_FAILURE);
////    }
//
//    printf("\n Sending ARP Request \n");
//    // Send ethernet frame to socket.
//    if ((bytes = sendto (pf_packet, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
//        perror ("sendto() failed");
//        exit (EXIT_FAILURE);
//    }
//
//    // Close socket descriptor.
//   // close (sd);
//
//    // Free allocated memory.
//    free (src_mac);
//    free (dst_mac);
//    free (ether_frame);
//    free (interface);
//    free (target);
//
//
//    return (EXIT_SUCCESS);
//}
//


int check_cache(char resolve_ip[INET_ADDRSTRLEN])
{
    int i;
    for(i=0;i<40;i++)
    {
        if(strcmp(arpcache[i].IP,resolve_ip)==0)
        {
            if(arpcache[i].valid==1)
            {
                printf("\n IP address %s is present in AREP cache at entry %d",arpcache[i].IP,i);
                return 1;
            }
        }
    }
    
    return 0;
    
    
}




int check_unixpacket(struct sockaddr_un recvip,char resolve_ip[INET_ADDRSTRLEN],char src_ip[INET_ADDRSTRLEN],int unixdomain_socket)
{
    if(check_cache(resolve_ip)==1)
    {
        printf("\n Cache Entry found \n");
        
    }
    
    else if (check_cache(resolve_ip)==0)
    {
        printf("\n Cache Entry not found \n");
        printf("\n Source Ip Address in check_unixpacket() is %s \n",src_ip);
        find_mac_address(resolve_ip,src_ip);
        return 0;
    }
    return 0;
    
}

int arpreply(struct sockaddr_ll receivepktAddr,unsigned char rcvbuf[ETH_HDRLEN+ARP_HDRLEN])
{
    return 0;
}

int main(int argc, char *argv[])
{
    struct sockaddr_un arpaddr,recvip;
    struct sockaddr_ll receivepktAddr;
    arp_hdr* rcvframe;
    int unixdomain_socket;
    fd_set rset;
    int acceptfd;
    int maxfdp,nready,nbytes;
    char resolve_ip[INET_ADDRSTRLEN];
    char sourceCanonicalIP[INET_ADDRSTRLEN];
    struct hostent *he;
    char odrvm[5];
    char **ip;
    //void* rcvbuffer = (void*)malloc(ETH_FRAME_LENGTH);
    //creating pf_packet socket - packet interface on device level.
    pf_packet = socket(PF_PACKET, SOCK_RAW, htons(PROTOCOL));
    
    socklen_t pktlen = sizeof(receivepktAddr);
    //
    
    socklen_t rcvlen = sizeof(recvip);
    ip_hwaddr();
    if (pf_packet == -1)
    {
        printf("Error in creating pf_packet socket \n");
    }
    
    //creating unix domain socket
    
    
    unixdomain_socket= socket(AF_LOCAL, SOCK_STREAM, 0);
    if(unixdomain_socket < 0){
        printf("\n Unix Domain Socket creation error\n");
        
    }
    
    unlink(ARP_PATH);
    bzero(&arpaddr, sizeof(arpaddr));
    arpaddr.sun_family = AF_LOCAL;
    strcpy(arpaddr.sun_path, ARP_PATH);
    
    if(bind(unixdomain_socket, (struct sockaddr *)&arpaddr, sizeof(arpaddr))<0){
        printf("Unix Domain Socket bind error \n");
    }
    
    listen(unixdomain_socket,50);
    //check on which socket request is coming through select
    while(1)
    {
        printf("\n Waiting in While 1");
        FD_ZERO(&rset);
        FD_SET(pf_packet, &rset);
        FD_SET(unixdomain_socket, &rset);
        maxfdp = max(pf_packet,unixdomain_socket) +1;
        nready = select(maxfdp, &rset, NULL, NULL, NULL);
        if (nready < 0)
        {
            printf(" Select error: %d\n", errno);
            continue;
        }
        
        //if request is received on unix domain socket
        if (FD_ISSET(unixdomain_socket, &rset))
        {
            acceptfd = accept(unixdomain_socket,(struct sockaddr *)&recvip, &rcvlen);
            printf("Packet received on  UNIX_SOCKET \n");
            if(nbytes = read(acceptfd, resolve_ip, INET_ADDRSTRLEN)<=0)
                printf("\n Error in reading IP address %d \n",nbytes);
            printf("\n IP address to be resolved is %s \n ",resolve_ip);
            
            gethostname(odrvm, sizeof odrvm);
            printf("\n odrvm: %s\n", odrvm);
            
            //get arp odr canonical IP address
            
            
            he = gethostbyname(odrvm);
            if (he == NULL) { // do some error checking
                herror("gethostbyname");
                exit(1);
            }
            
            ip=he->h_addr_list;
            printf("\n source Canonical IP : %s \n",inet_ntop(he->h_addrtype,*ip,sourceCanonicalIP,sizeof(sourceCanonicalIP)));
            
            
            check_unixpacket(recvip,resolve_ip,sourceCanonicalIP,unixdomain_socket);
            //return 0;
            
        }
        
        if (FD_ISSET(pf_packet, &rset))
        {
            printf("Packet received on  PF_SOCKET \n");
            
            struct sockaddr_ll rcv_pkt_addr;
            void* rcvbuffer = (void*)malloc(ETH_FRAME_LEN); /*Buffer for ethernet frame*/
            pethframehdr_rcv = rcvbuffer;
            
            /*userdata in ethernet frame*/
            parphdr_rcv = (rcvbuffer + sizeof(struct Ethernet_hdr));
            memset(&rcv_pkt_addr, 0, sizeof(rcv_pkt_addr));
            memset(rcvbuffer, 0, sizeof(rcvbuffer));
            
            socklen_t rcvlen = sizeof(rcv_pkt_addr);
            
            
          
            int length = 0; /*length of the received frame*/
            length = recvfrom(pf_packet, rcvbuffer, ETH_FRAME_LEN, 0,(struct sockaddr*)&rcv_pkt_addr,&rcvlen);
            
            if (length == -1)
            {
                printf("receive error %d",errno);
                exit(1);
                
            }
            
            printf("Packet received on  PF_SOCKET of length %d bytes \n",length);
            //arp_hdr* rcvframe;
            
            
            
            
            // arpreply(pf_packet,receivepktAddr,rcvbuf);
            
            //return 0;
            
        }
        
        
    }
    
    return 0;
    
    
}