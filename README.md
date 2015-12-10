Address-Resolution-Protocol
Network Programming Assignment 4

In this assignment we have implemented :

1)An application that uses raw IP sockets to ‘walk’ around an ordered list of nodes given as a command line argument at the ‘source’ node.
2)At each node, the application pings the preceding node in the tour.
3)Finally, when the ‘walk’ is completed, the group of nodes visited on the tour will exchange multicast messages.

The application contains two modules

tour.c : Usage after make and deploy at source node: ./tour_astayal <node1> <node2> etc
Usage after make and deploy and other nodes: ./tour_astayal

arp.c : Usage after make and deploy: ./arp_astayal

Tour module :

Sockets : 

IP Raw:
rt(route traversal) - IP_HDRINCL option is set . Protocol Value 10
pg(ping socket) - Used to receive ping replies . Protocol value IPPROTO_ICMP
pf_packet - SOCK_DGRAM type. Protocol value : ETH_P_IP
Two UDP sockets. Multicast read and write. 


Implemented Features:

From the Assignment Requirement 1) - Implemented :

When evoking the application on the source node, the user supplies a sequence of vm node names (not IP
addresses) to be visited in order. This command line sequence starts with the next node to be visited from the
source node (i.e., it does not start with the source node itself). 
The sequence can include any number of repeated visits to the same node. For example, suppose that the source node is vm3 and the executable is called tour_astayal
[root@vm3/root]# ./tour_astayal vm2 vm10 vm4 vm7 vm5 vm2 vm6 vm2 vm9 vm4 vm7 vm2 vm6 vm5 vm1 vm10 vm8
1) Check to see if the source node is the first node. If so abort with appropriate message.
2) Check to see if two nodes are continuous. If so abort.


The application turns the sequence into a list of IP addresses for source routing. It also adds the IP address of
the source node itself to the beginning of the list. The list thus produced will be carried as the payload of an IP
packet, not as a SSRR option in the packet header. 
Application ensures that every node in the sequence is visited in order.
The source node adds to the  list an IP multicast address and a port number. It also joins the multicast group at that address and port number on its UDP socket. The TTL for outgoing multicasts is set to 1.

The application then fills in the header of an IP packet, designating itself as the IP source, and the next node
to be visited as the IP destination. The packet is sent out on the rt socket. Identification field is set to 222.

When a node receives an IP packet on its rt socket, it should first check that the identification field carries the right
value.If the identification field value does not check out, the packet is ignored. For a valid packet :
The following message is printed.
<time> received source routing packet from <hostname>

If this is the first time the node is visited, the application should use the multicast address and port number in
the packet received to join the multicast group on its UDP socket. 
The TTL for outgoing multicasts is set to 1.


