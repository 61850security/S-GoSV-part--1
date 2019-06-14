#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
 
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
char gocbRef_value1=0x47;
char gocbRef_value2=0x45;
char gocbRef_value3=0x44;
char gocbRef_value4=0x65;
char gocbRef_value5=0x76;
char gocbRef_value6=0x69;
char gocbRef_value7=0x63;
char gocbRef_value8=0x65;
char gocbRef_value9=0x46;
char gocbRef_value10=0x36;
char gocbRef_value11=0x35;
char gocbRef_value12=0x30;
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
char dataset_value1=0x47;
char dataset_value2=0x45;
char dataset_value3=0x44;
char dataset_value4=0x65;
char dataset_value5=0x76;
char dataset_value6=0x69;
char dataset_value7=0x63;
char dataset_value8=0x65;
char dataset_value9=0x46;
char dataset_value10=0x36;
char dataset_value11=0x35;
char dataset_value12=0x30;
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
char goID_value2=0x36;
char goID_value3=0x35;
char goID_value4=0x30;
char goID_value5=0x5F;
char goID_value6=0x47;
char goID_value7=0x4F;
char goID_value8=0x4F;
char goID_value9=0x53;
char goID_value10=0x45;
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
int main()
{
  unsigned char key[14] = { 0x0A, 0x23, 0x45, 0x56, 0x56, 0x54, 0x76, 0x0A, 0x23, 0x45, 0x56, 0x56, 0x54, 0x76 };
  
   /*unsigned char goosePDU[137]= 
  	{ 
            0x61, 0x81, 0x86, 0x80, 0x1A, 0x47, 0x45, 0x44, 0x65, 0x76, 
            0x69, 0x63, 0x65, 0x46, 0x36, 0x35, 0x30, 0x2F, 0x4C, 0x4C,
	    0x4E, 0x30, 0x24, 0x47, 0x4F, 0x24, 0x67, 0x63, 0x62, 0x30, 
            0x31, 0x81, 0x03, 0x00, 0x8C, 0x40, 0x82, 0x18, 0x47, 0x45,
            0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x46, 0x36, 0x35, 0x30,
            0x2F, 0x4C, 0x4C, 0x4E, 0x30, 0x24, 0x47, 0x4F, 0x4F, 0x53,
            0x45, 0x31, 0x83, 0x0B, 0x46, 0x36, 0x35, 0x30, 0x5F, 0x47,
            0x4F, 0x4F, 0x53, 0x45, 0x31, 0x84, 0x08, 0x38, 0x6E, 0xBB, 
            0xF3, 0x42, 0x17, 0x28, 0x0A, 0x85, 0x01, 0x01, 0x86, 0x01, 
            0x0A, 0x87, 0x01, 0x00, 0x88, 0x01, 0x01, 0x89, 0x01, 0x00,
            0x8A, 0x01, 0x08, 0xAB, 0x20, 0x83, 0x01, 0x00, 0x84, 0x03, 
            0x03, 0x00, 0x00, 0x83, 0x01, 0x00, 0x84, 0x03, 0x03, 0x00, 
            0x00, 0x83, 0x01, 0x00, 0x84, 0x03, 0x03, 0x00, 0x00, 0x83,
            0x01, 0x00, 0x84, 0x03, 0x03, 0x00, 0x00

	}; */
/*unsigned char goosePDU[274] = "618186801A4745446576696365463635302F4C4C4E3024474F2467636230318103009C4082184745446576696365463635302F4C4C4E3024474F4F534531830B463635305F474F4F5345318408386EBBF34217280A85010186010A8701008801018901008A0108AB208301008403030000830100840303000083010084030300008301008403030000"; 
*/
unsigned char goosePDU[274] = "618186801A4745446576696365463635302F4C4C4E3024474F2467636230318103009C4082184745446576696365463635302F4C4C4E3024474F4F534531830B463635305F474F4F5345318408386EBBF34217280A85010186010A8701008801018901008A0108AB208301008403030000830100840303000083010084030300008301008403030000"; 


  unsigned char data[274];
  
  unsigned char *result;
  int result_len = 32;
  int i=0,j=0,num=274,k;
  double begin,end,time_first,time_second,time_third;
  static char res_hexstring[32];
  
  	for( i=0; i<274; i++)
       		data[i]=goosePDU[j++];

       
        result = HMAC(EVP_sha256(), key, strlen((char *)key), data, strlen((char *)data), NULL, NULL);
	
	
        for (i = 0; i < result_len; i++)
        	sprintf(&(res_hexstring[i * 2]), "%02x", result[i]);
        printf("\n Hash: %s \n", res_hexstring);
        
  
  return 0;
}

/* compilation steps */
// sudo apt-get install libssl-dev
//$gcc -o g1 g1-HMAC-SHA256.c -L/usr/local/lib/ -lssl -lcrypto 
//$./g1

/* the output of the program is 
Hash value: 43aab4d94557e6c805b1b0282d67b7c80e32357d8780720681cb300e767c00eb
 */
