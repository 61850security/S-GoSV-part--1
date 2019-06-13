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

#define DEST_MAC0    0x01
#define DEST_MAC1    0x0C
#define DEST_MAC2    0xCD
#define DEST_MAC3    0x01
#define DEST_MAC4    0x03
#define DEST_MAC5    0xFF
 
// Standard address 01 0C CD 01 03 FF


#define DEFAULT_IF  "eno1"
#define BUF_SIZ     2048

/* Measurement values matrix 
char a[64][10]={0};  */

char a[64][10]= { 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                  0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                  0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
                  0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 
                  0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
                  0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 
                  0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 
                  0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,
                  0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 
		  0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                  0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                  0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
                  0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 
                  0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
                  0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 
                  0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 
                  0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,
                  0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 
		  0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                  0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                  0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
                  0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 
                  0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
                  0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 
                  0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 
                  0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,
                  0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 
		  0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                  0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                  0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
                  0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 
                  0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
                  0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 
                  0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 
                  0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,
                  0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16 };


char APPID_1 =0x40;                   /* char APPID_1=0x40; int16_t   Application identifier */
char APPID_2 =0x00; 
char length_1 =0x00;                  /* int16_t length=0x006E; int16_t length=110;    */
char length_2=0x6e;
char resrv1_1=0x00; 		     /* int16_t resrv1;  */
char resrv1_2=0x00;                   
char resrv2_1=0x00;		     /* int16_t resrv2 */
char resrv2_2=0x00;                  
char sav_PDU_tag=0x60;               /* int8_t sav_PDU_tag  */
char sav_PDU_length=0x64; 	     /* int8_t sav_PDU_length; size of APDU */
char noASDU_tag=0x80;		     /* int16_t sav_PDU_tag */ 
char noASDU_length=0x01;              /* int8_t noASDU_length  size of noASDU */
char noASDU=0x01;                     /* int8_t noASDU  */
char SequenceofASDU_tag=0xA2;         /* int8_t SequenceofASDU_tag   */
char SequenceofASDU_length=0x5F;      /* int8_t SequenceofASDU_length  size of all ASDU  */
char ASDU_tag=0x30;
char ASDU_length=0x5D; 
char svID_tag =0x80;                  /* int8_t svID_tag = 128; 0x80 hexa decimal */
char svID_length =0x0C;               /* int8_t svID_length= 12; 0x0C hexa decimal */
char svID_1=0x46;                     /* int8_t svID[12]= {0}; naming  */
char svID_2=0x52;
char svID_3=0x45;
char svID_4=0x41;
char svID_5=0x2D;
char svID_6=0x47;
char svID_7=0x6F;
char svID_8=0x53;
char svID_9=0x56;
char svID_10=0x2D;  
char svID_11=0x30;
char svID_12=0x31;
char smpCnt_tag=0x82;                     /* int8_t smpCnt_tag=130; 0x82 hexa decimal */
char smpCnt_length =0x02;             /* int8_t smpCnt_length =2; 0 x02 hexa decimal */
char smpCnt_1=0x0C;                   /* int16_t smpCnt=0;  /* counter specification */
char smpCnt_2=0xA4;
char confRev_tag=0x83;                /* int8_t confRev_tag =131;  0x83 hexa decimal */
char confRev_length=0x04;             /* int8_t confRev_length=4;  0x04 hexa decimal */
char confRev1=0x00;
char confRev2=0x00; 	      /* int32_t confRev=1; Configuration revision number */
char confRev3=0x00;
char confRev4=0x01;                   
char smpSynch_tag = 0x85;             /* int8_t smpSynch_tag= 133;  0 x85 hexa decimal */
char smpSynch_length =0x01;           /* int8_t smpSynch_length=1; 0 x01 hexa decimal */
char smpSynch =0x00; 		     /* int8_t smpSynch=0; Synchronization identifier */
char SequenceofData_tag =0x87;            /* int8_t SequenceofData_tag=135;     0x87 hexa decimal */
char SequenceofData_length=0x40;      /* int8_t SequenceofData_length=64;  0 x40 hexa decimal */


int main(int argc, char *argv[])
{
    int sockfd;
    int i=0,j,k;
    struct ifreq if_idx;
    struct ifreq if_mac;
    int tx_len;
    unsigned char sendbuf[BUF_SIZ];
    struct sockaddr_ll socket_address; /* The sockaddr_ll structure is a device-independent physical-layer address.*/
    char ifName[IFNAMSIZ];

    /* Get interface name */
    if (argc > 1)
        strcpy(ifName, argv[1]);
    else
        strcpy(ifName, DEFAULT_IF);

    /* Open RAW socket to send on */
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) 
    {
        perror("socket");
    }
    printf(" name of the interface is: %s",ifName);
    /* Get the index of the interface to send on */
    memset(&if_idx, 0, sizeof(struct ifreq));
    printf("\n memset interface index-%d",if_idx.ifr_ifindex);
    strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
    printf("\n strcpy interface index-%d",if_idx.ifr_ifindex);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
        perror("SIOCGIFINDEX");
     /* if ( ioctl(sockfd, SIOCGIFHWADDR,&if_idx) < 0)
        perror("SIOCGIFHWADDR"); */
    printf("\n ioctl interface index-%d",if_idx.ifr_ifindex);
    printf(" index of the interface is: %s",if_idx.ifr_name);
    // Loop forever
    while(1) {


        /* Buffer of BUF_SIZ bytes we'll construct our frame in.
           First, clear it all to zero. */
        memset(sendbuf, 0, BUF_SIZ);
        tx_len = 0;

        /* Construct the Ethernet header */

      
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
	
        sendbuf[tx_len++] = 0x81;
        sendbuf[tx_len++] = 0x00;
        sendbuf[tx_len++] = 0x80;
        sendbuf[tx_len++] = 0x00;

        /* Ethertype field */
        sendbuf[tx_len++] = 0x88;
        sendbuf[tx_len++] = 0xBA;


        /*  PDU fields */
        sendbuf[tx_len++] = APPID_1;
        sendbuf[tx_len++] = APPID_2;
        sendbuf[tx_len++] = length_1;
        sendbuf[tx_len++] = length_2;
        sendbuf[tx_len++] = resrv1_1;
	sendbuf[tx_len++] = resrv1_2; 
        sendbuf[tx_len++] = resrv2_1;
        sendbuf[tx_len++] = resrv2_2;
     

        /* APDU fields */
        sendbuf[tx_len++] = sav_PDU_tag;
        sendbuf[tx_len++] = sav_PDU_length;
	sendbuf[tx_len++] = noASDU_tag;
	sendbuf[tx_len++] = noASDU_length;
	sendbuf[tx_len++] = noASDU;
	sendbuf[tx_len++] = SequenceofASDU_tag;
	sendbuf[tx_len++] = SequenceofASDU_length;

	/* ASDU fields */
	sendbuf[tx_len++] = ASDU_tag;
	sendbuf[tx_len++] = ASDU_length;
	sendbuf[tx_len++] = svID_tag;        
        sendbuf[tx_len++] = svID_length;
        sendbuf[tx_len++] = svID_1;
        sendbuf[tx_len++] = svID_2;
	sendbuf[tx_len++] = svID_3;
	sendbuf[tx_len++] = svID_4;
	sendbuf[tx_len++] = svID_5;
	sendbuf[tx_len++] = svID_6;
	sendbuf[tx_len++] = svID_7;
	sendbuf[tx_len++] = svID_8;
	sendbuf[tx_len++] = svID_9;
	sendbuf[tx_len++] = svID_10;
	sendbuf[tx_len++] = svID_11;
	sendbuf[tx_len++] = svID_12;
	sendbuf[tx_len++] = smpCnt_tag;
	sendbuf[tx_len++] = smpCnt_length;
	sendbuf[tx_len++] = smpCnt_1;
	sendbuf[tx_len++] = smpCnt_2;	
        sendbuf[tx_len++] = confRev_tag;	
	sendbuf[tx_len++] = confRev_length;
	sendbuf[tx_len++] = confRev1;
        sendbuf[tx_len++] = confRev2;
	sendbuf[tx_len++] = confRev3;
	sendbuf[tx_len++] = confRev4;
	sendbuf[tx_len++] = smpSynch_tag;
	sendbuf[tx_len++] = smpSynch_length;
        sendbuf[tx_len++] = smpSynch;	
        sendbuf[tx_len++] = SequenceofData_tag;
	sendbuf[tx_len++] = SequenceofData_length;
        for(j=0;j<=63;j++)
           sendbuf[tx_len++]= a[j][i];
      
        i++;
        if ( i == 9 )
           i=0;

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
        if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
            printf("Send failed\n");
        else {
            printf("\n Sample Value (SV) Message Sent :\n");
            for (k=0; k < tx_len; k++)
                printf("%02x:", sendbuf[k]);
            printf("\n");
        }
        /* Wait specified number of microseconds
           1,000,000 microseconds = 1 second
           */
        usleep(1000000);
    }
    return 0;
}

