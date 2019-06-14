#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <unistd.h>


/*  Broadcast mac address 
#define DEST_MAC0    0xFF
#define DEST_MAC1    0xFF
#define DEST_MAC2    0xFF
#define DEST_MAC3    0xFF
#define DEST_MAC4    0xFF
#define DEST_MAC5    0xFF
*/   

// Standard address 01 0C CD 01 03 FF
#define DEST_MAC0    0x01
#define DEST_MAC1    0x0C
#define DEST_MAC2    0xCD
#define DEST_MAC3    0x01
#define DEST_MAC4    0x03
#define DEST_MAC5    0xFF
 
	

#define IF_NAME     "eno1"
#define BUF_SIZ     2048


 /* GOOSE payload fields */

char APPID_1 =0x00;                   
char APPID_2 =0x01; 
char length_1 =0x00;                  
char length_2=0x91;
char resrv1_1=0x00; 		     
char resrv1_2=0x00;                   
char resrv2_1=0x00;		     
char resrv2_2=0x00;                  
char goosePDU_tag1=0x61;
char goosePDU_tag2=0x81;
char goosePDU_length=0x86;
char gocbRef_tag=0x80;
char gocbRef_length=0x1A;
char gocbRef_value1=0x46;
char gocbRef_value2=0x52;
char gocbRef_value3=0x45;
char gocbRef_value4=0x41;
char gocbRef_value5=0x2D;
char gocbRef_value6=0x47;
char gocbRef_value7=0x6F;
char gocbRef_value8=0x53;
char gocbRef_value9=0x56;
char gocbRef_value10=0x2D;
char gocbRef_value11=0x31;
char gocbRef_value12=0x20;
char gocbRef_value13=0x2F;
char gocbRef_value14=0x4C;
char gocbRef_value15=0x4C;
char gocbRef_value16=0x4E;
char gocbRef_value17=0x30;
char gocbRef_value18=0x24;
char gocbRef_value19=0x47;
char gocbRef_value20=0x4F;
char gocbRef_value21=0x24;
char gocbRef_value22=0x67;
char gocbRef_value23=0x63;
char gocbRef_value24=0x62;
char gocbRef_value25=0x30;
char gocbRef_value26=0x31; 
char timeAllowedtoLive_tag=0x81;
char timeAllowedtoLive_length=0x03;
char timeAllowedtoLive_value1=0x00;
char timeAllowedtoLive_value2=0x9C;
char timeAllowedtoLive_value3=0x40;
char dataset_tag=0x82;
char dataset_length=0x18;
char dataset_value1=0x46;
char dataset_value2=0x52;
char dataset_value3=0x45;
char dataset_value4=0x41;
char dataset_value5=0x2D;
char dataset_value6=0x47;
char dataset_value7=0x6F;
char dataset_value8=0x53;
char dataset_value9=0x56;
char dataset_value10=0x2D;
char dataset_value11=0x31;
char dataset_value12=0x20;
char dataset_value13=0x2F;
char dataset_value14=0x4C;
char dataset_value15=0x4C;
char dataset_value16=0x4E;
char dataset_value17=0x30;
char dataset_value18=0x24;
char dataset_value19=0x47;
char dataset_value20=0x4F;
char dataset_value21=0x4F;
char dataset_value22=0x53;
char dataset_value23=0x45;
char dataset_value24=0x31;
char goID_tag=0x83;
char goID_length=0x0B;
char goID_value1=0x46;
char goID_value2=0x52;
char goID_value3=0x45;
char goID_value4=0x41;
char goID_value5=0x2D;
char goID_value6=0x47;
char goID_value7=0x6F;
char goID_value8=0x53;
char goID_value9=0x56;
char goID_value10=0x2D;
char goID_value11=0x31;
char time_tag=0x84;
char time_length=0x08;
char time_value1=0x38;
char time_value2=0x6E;
char time_value3=0xBB;
char time_value4=0xF3;
char time_value5=0x42;
char time_value6=0x17;
char time_value7=0x28;
char time_value8=0x0A;
char st_Num_tag=0x85;
char st_Num_length=0x01;
char st_Num_value=0x01;
char sq_Num_tag=0x86;
char sq_Num_length=0x01;
char sq_Num_value=0x0A;
char test_tag=0x87;
char test_length=0x01;
char test_value=0x00;
char confRev_tag=0x88;
char confRev_length=0x01;
char confRev_value=0x01;
char ndsCom_tag=0x89;
char ndsCom_length=0x01;
char ndsCom_value=0x00;
char numDatSetEntries_tag=0x8A;
char numDatSetEntries_length=0x01;
char numDatSetEntries_value=0x08;
char alldata_tag=0xAB;
char alldata_length=0x20;
char alldata_value1=0x83;
char alldata_value2=0x01;
char alldata_value3=0x00;
char alldata_value4=0x84;
char alldata_value6=0x03;
char alldata_value5=0x03;
char alldata_value7=0x00;
char alldata_value8=0x00;
char alldata_value9=0x83;
char alldata_value10=0x01;
char alldata_value11=0x00;
char alldata_value12=0x84;
char alldata_value13=0x03;
char alldata_value14=0x03;
char alldata_value15=0x00;
char alldata_value16=0x00;
char alldata_value17=0x83;
char alldata_value18=0x01;
char alldata_value19=0x00;
char alldata_value20=0x84;
char alldata_value21=0x03;
char alldata_value22=0x03;
char alldata_value23=0x00;
char alldata_value24=0x00;
char alldata_value25=0x83;
char alldata_value26=0x01;
char alldata_value27=0x00;
char alldata_value28=0x84;
char alldata_value29=0x03;
char alldata_value30=0x03;
char alldata_value31=0x00;
char alldata_value32=0x00;

int main(int argc, char *argv[])
{
    int sfd;
    int i=0;
    struct ifreq if_idx;
    struct ifreq if_mac;
    int tx_len;
    unsigned char sendbuf[BUF_SIZ];
    struct sockaddr_ll socket_address; /* The sockaddr_ll structure is a device-independent physical-layer address.*/
    char ifName[IFNAMSIZ];

    /* Get interface name */
    strcpy(ifName, IF_NAME);

    /* Open RAW socket to send on */
    if ((sfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) 
    {
        perror("socket");
    }
    printf(" name of the interface is: %s",ifName);
    /* Get the index of the interface to send on */
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
    if (ioctl(sfd, SIOCGIFINDEX, &if_idx) < 0)
        perror("SIOCGIFINDEX");
    printf(" index of the interface is: %s",if_idx.ifr_name);
    // Loop forever
    while(1) {


        /* Buffer of BUF_SIZ bytes we'll construct our frame in.
           First, clear it all to zero. */
        memset(sendbuf, 0, BUF_SIZ);
        tx_len = 0;

        /* Construct the Ethernet header */

        /* Destination address */
        sendbuf[tx_len++] = DEST_MAC0;
        sendbuf[tx_len++] = DEST_MAC1;
        sendbuf[tx_len++] = DEST_MAC2;
        sendbuf[tx_len++] = DEST_MAC3;
        sendbuf[tx_len++] = DEST_MAC4;
        sendbuf[tx_len++] = DEST_MAC5;

        /* Create the source */
        sendbuf[tx_len++] = 0xA0; 
        sendbuf[tx_len++] = 0xB3; 
        sendbuf[tx_len++] = 0xCC;
        sendbuf[tx_len++] = 0xC5;
        sendbuf[tx_len++] = 0x77;
        sendbuf[tx_len++] = 0xA1;

        /* Ethertype field GOOSE protocol*/
        sendbuf[tx_len++] = 0x88;
        sendbuf[tx_len++] = 0xB8;

        /*  PDU fields */
        sendbuf[tx_len++] = APPID_1;                  
        sendbuf[tx_len++] = APPID_2; 
        sendbuf[tx_len++] = length_1;                 
        sendbuf[tx_len++] = length_2;
        sendbuf[tx_len++] = resrv1_1;
	sendbuf[tx_len++] = resrv1_2;                   
	sendbuf[tx_len++] = resrv2_1;
        sendbuf[tx_len++] = resrv2_2;                  
        sendbuf[tx_len++] = goosePDU_tag1;
        sendbuf[tx_len++] = goosePDU_tag2;
        sendbuf[tx_len++] = goosePDU_length;
        sendbuf[tx_len++] = gocbRef_tag;
        sendbuf[tx_len++] = gocbRef_length;
        sendbuf[tx_len++] = gocbRef_value1;
        sendbuf[tx_len++] = gocbRef_value2;
        sendbuf[tx_len++] = gocbRef_value3;
        sendbuf[tx_len++] = gocbRef_value4;
        sendbuf[tx_len++] = gocbRef_value5;
        sendbuf[tx_len++] = gocbRef_value6;
        sendbuf[tx_len++] = gocbRef_value7;
        sendbuf[tx_len++] = gocbRef_value8;
        sendbuf[tx_len++] = gocbRef_value9;
        sendbuf[tx_len++] = gocbRef_value10;
	sendbuf[tx_len++] = gocbRef_value11;
	sendbuf[tx_len++] = gocbRef_value12;
	sendbuf[tx_len++] = gocbRef_value13;
	sendbuf[tx_len++] = gocbRef_value14;
	sendbuf[tx_len++] = gocbRef_value15;
	sendbuf[tx_len++] = gocbRef_value16;
	sendbuf[tx_len++] = gocbRef_value17;
	sendbuf[tx_len++] = gocbRef_value18;
	sendbuf[tx_len++] = gocbRef_value19;
	sendbuf[tx_len++] = gocbRef_value20;
	sendbuf[tx_len++] = gocbRef_value21;
	sendbuf[tx_len++] = gocbRef_value22;
	sendbuf[tx_len++] = gocbRef_value23;
	sendbuf[tx_len++] = gocbRef_value24;
	sendbuf[tx_len++] = gocbRef_value25;
	sendbuf[tx_len++] = gocbRef_value26;
	sendbuf[tx_len++] = timeAllowedtoLive_tag;
	sendbuf[tx_len++] = timeAllowedtoLive_length;
	sendbuf[tx_len++] = timeAllowedtoLive_value1;
	sendbuf[tx_len++] = timeAllowedtoLive_value2;
	sendbuf[tx_len++] = timeAllowedtoLive_value3;
	sendbuf[tx_len++] = dataset_tag;
	sendbuf[tx_len++] = dataset_length;
	sendbuf[tx_len++] = dataset_value1;
	sendbuf[tx_len++] = dataset_value2;
	sendbuf[tx_len++] = dataset_value3;
	sendbuf[tx_len++] = dataset_value4;
	sendbuf[tx_len++] = dataset_value5;
	sendbuf[tx_len++] = dataset_value6;
	sendbuf[tx_len++] = dataset_value7;
	sendbuf[tx_len++] = dataset_value8;
	sendbuf[tx_len++] = dataset_value9;
	sendbuf[tx_len++] = dataset_value10;
	sendbuf[tx_len++] = dataset_value11;
	sendbuf[tx_len++] = dataset_value12;
	sendbuf[tx_len++] = dataset_value13;
	sendbuf[tx_len++] = dataset_value14;
	sendbuf[tx_len++] = dataset_value15;
	sendbuf[tx_len++] = dataset_value16;
	sendbuf[tx_len++] = dataset_value17;
	sendbuf[tx_len++] = dataset_value18;
	sendbuf[tx_len++] = dataset_value19;
	sendbuf[tx_len++] = dataset_value20;
	sendbuf[tx_len++] = dataset_value21;
	sendbuf[tx_len++] = dataset_value22;
	sendbuf[tx_len++] = dataset_value23;
	sendbuf[tx_len++] = dataset_value24;
	sendbuf[tx_len++] = goID_tag;
	sendbuf[tx_len++] = goID_length;
	sendbuf[tx_len++] = goID_value1;
	sendbuf[tx_len++] = goID_value2;
	sendbuf[tx_len++] = goID_value3;
	sendbuf[tx_len++] = goID_value4;
	sendbuf[tx_len++] = goID_value5;
	sendbuf[tx_len++] = goID_value6;
	sendbuf[tx_len++] = goID_value7;
	sendbuf[tx_len++] = goID_value8;
	sendbuf[tx_len++] = goID_value9;
	sendbuf[tx_len++] = goID_value10;
	sendbuf[tx_len++] = goID_value11;
	sendbuf[tx_len++] = time_tag;
	sendbuf[tx_len++] = time_length;
	sendbuf[tx_len++] = time_value1;
	sendbuf[tx_len++] = time_value2;
	sendbuf[tx_len++] = time_value3;
	sendbuf[tx_len++] = time_value4;
	sendbuf[tx_len++] = time_value5;
	sendbuf[tx_len++] = time_value6;
	sendbuf[tx_len++] = time_value7;
	sendbuf[tx_len++] = time_value8;
	sendbuf[tx_len++] = st_Num_tag;
	sendbuf[tx_len++] = st_Num_length;
	sendbuf[tx_len++] = st_Num_value;
	sendbuf[tx_len++] = sq_Num_tag;
	sendbuf[tx_len++] = sq_Num_length;
	sendbuf[tx_len++] = sq_Num_value;
	sendbuf[tx_len++] = test_tag;
	sendbuf[tx_len++] = test_length;
	sendbuf[tx_len++] = test_value;
	sendbuf[tx_len++] = confRev_tag;
	sendbuf[tx_len++] = confRev_length;
	sendbuf[tx_len++] = confRev_value;
	sendbuf[tx_len++] = ndsCom_tag;
	sendbuf[tx_len++] = ndsCom_length;
	sendbuf[tx_len++] = ndsCom_value;
	sendbuf[tx_len++] = numDatSetEntries_tag;
	sendbuf[tx_len++] = numDatSetEntries_length;
	sendbuf[tx_len++] = numDatSetEntries_value;
	sendbuf[tx_len++] = alldata_tag;
	sendbuf[tx_len++] = alldata_length;
	sendbuf[tx_len++] = alldata_value1;
	sendbuf[tx_len++] = alldata_value2;
	sendbuf[tx_len++] = alldata_value3;
	sendbuf[tx_len++] = alldata_value4;
	sendbuf[tx_len++] = alldata_value6;
	sendbuf[tx_len++] = alldata_value5;
	sendbuf[tx_len++] = alldata_value7;
	sendbuf[tx_len++] = alldata_value8;
	sendbuf[tx_len++] = alldata_value9;
	sendbuf[tx_len++] = alldata_value10;
	sendbuf[tx_len++] = alldata_value11;
	sendbuf[tx_len++] = alldata_value12;
	sendbuf[tx_len++] = alldata_value13;
	sendbuf[tx_len++] = alldata_value14;
	sendbuf[tx_len++] = alldata_value15;
	sendbuf[tx_len++] = alldata_value16;
	sendbuf[tx_len++] = alldata_value17;
	sendbuf[tx_len++] = alldata_value18;
	sendbuf[tx_len++] = alldata_value19;
	sendbuf[tx_len++] = alldata_value20;
	sendbuf[tx_len++] = alldata_value21;
	sendbuf[tx_len++] = alldata_value22;
	sendbuf[tx_len++] = alldata_value23;
	sendbuf[tx_len++] = alldata_value24;
	sendbuf[tx_len++] = alldata_value25;
	sendbuf[tx_len++] = alldata_value26;
	sendbuf[tx_len++] = alldata_value27;
	sendbuf[tx_len++] = alldata_value28;
	sendbuf[tx_len++] = alldata_value29;
	sendbuf[tx_len++] = alldata_value30;
	sendbuf[tx_len++] = alldata_value31;
	sendbuf[tx_len++] = alldata_value32;


        /* Index of the network device */
        socket_address.sll_ifindex = if_idx.ifr_ifindex;  /* Network Interface number */

        /* Address length*/
        socket_address.sll_halen = ETH_ALEN; /* Length of Ethernet address */

        /* Destination MAC */
        socket_address.sll_addr[0] = DEST_MAC0;
        socket_address.sll_addr[1] = DEST_MAC1;
        socket_address.sll_addr[2] = DEST_MAC2;
        socket_address.sll_addr[3] = DEST_MAC3;
        socket_address.sll_addr[4] = DEST_MAC4;
        socket_address.sll_addr[5] = DEST_MAC5;

        /* Send packet */
        if (sendto(sfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
            printf("Send failed\n");
        else {
            printf("\n GOOSE Message values Sent :\n");
            for (i=0; i < tx_len; i++)
                printf("%02x:", sendbuf[i]);
            printf("\n");
        }
        /* Wait specified number of microseconds
           1,000,000 microseconds = 1 second
           */
        usleep(1000000);
    }
    return 0;
}

