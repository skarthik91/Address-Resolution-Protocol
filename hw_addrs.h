/* Our own header for the programs that need hardware address info. */
#include "unp.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
//#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <setjmp.h>
#include <sys/un.h>
#include <errno.h>
#include <netinet/in_systm.h>


#define	IF_NAME		16	/* same as IFNAMSIZ    in <net/if.h> */
#define	IF_HADDR	 6	/* same as IFHWADDRLEN in <net/if.h> */

#define	IP_ALIAS  	 1	/* hwa_addr is an alias */

struct hwa_info {
  char    if_name[IF_NAME];	/* interface name, null terminated */
  char    if_haddr[IF_HADDR];	/* hardware address */
  int     if_index;		/* interface index */
  short   ip_alias;		/* 1 if hwa_addr is an alias IP address */
  struct  sockaddr  *ip_addr;	/* IP address */
  struct  hwa_info  *hwa_next;	/* next of these structures */
};



/* function prototypes */
struct hwa_info	*get_hw_addrs();
struct hwa_info	*Get_hw_addrs();
void	free_hwa_info(struct hwa_info *);

