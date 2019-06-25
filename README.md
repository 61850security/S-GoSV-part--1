# S-GoSV-part-1

### Citing S-GoSV-part-1
We request that publications derived from the use of S-GoSV-part-1, explicitly acknowledge that fact by citing the appropriate paper and the library itself.

#### Papers:

S.M. Suhail Hussain, S.M. Farooq and Taha Selim Ustun, “Analysis and Implementation of Message Authentication Code (MAC) Algorithms for GOOSE Message Security”,  IEEE Access, 2019. DOI:10.1109/ACCESS.2019.2923728


## Documentation
Signature generation programs:
1. RSA_PKCS1_V1_5.sh
	This program contains collection of openSSL statements that generates pair of RSA private and public keys with 1024 key sizes. Then GOOSE APDU data is taken as a text file to generate hash using Secure Hash Algorithm (SHA256). The size of GOOSE APDU is 137 bytes. Further, the generated hash is signed by RSA private key to produce signature of length 128 bytes. Shell program prints the final signature in hexadecimal form. Finally, it is verified by corresponding RSA public key. 

Command to execute the program at terminal
$ sh RSA_PKCS1_V1_5.sh

2. RSA_PKCS1_V1_5.py and 3. keygen.sh
	This python program imports python libraries of RSA PKCS #1 , v1.5  (PKCS1_v1_5) to generated digital signature for the GOOSE APDU data. RSA private and public keys are generated indepently using keygen.sh program. Then GOOSE APDU data is taken in message as string data type. The size of the GOOSE APDU is 137 bytes. It is used to generate hash value (h). Further, hash value is signed by RSA private key (pr_key) which produces signature of length 128 bytes. Finally, the generated code can be verified using RSA public key (pub_key). 


Command to execute the programs at terminal
$ sh keygen.sh // To generate private and public key pairs
$ python RSA_PKCS1_V1_5.py

4. HMAC-SHA256.c 
	This C program make use of openSSL libraries (openssl/hmac.h and openssl/evp.h) to generate digital signature using Hash based Message Authentication Code – Secure Hash Algorithm (HMAC-SHA256). It takes 137 bytes of GOOSE APDU message and a symmetric key to generate 32 bytes of digital signature. 

Commands to execute the program at terminal
Install openssl library if not installed using the following command. 
$ sudo apt-get install libssl-dev
Compilation of program
$ gcc -o hmacsha256 HMAC-SHA256.c -L/usr/local/lib/ -lssl -lcrypto 
To run the code
$./hmacsha256

5. GOOSE_RSAPKCS1_V1_5_send.c
	This C program make  use of network interface libraries to send GOOSE APDU message and its digital signature by adding proper security information in to the network. 

Commands to execute the program at terminal
sudo allows users to run programs with the security privileges of another user (normally the superuser, or root). 
$ sudo bash 
Compilation of program
$ gcc -o goose_pkcs1_send GOOSE_RSAPKCS1_V1_5_send.c
To run the program
$./goose_pkcs1_send

6. GOOSE_HMACSHA256_send.c
	This C program make  use of network interface libraries to send GOOSE APDU message and its digital signature by adding proper security information in to the network. 


$ sudo bash 
sudo allows users to run programs with the security privileges of another user (normally the superuser, or root). 

Compilation of program
$ gcc -o goose_hmac_send GOOSE_HMACSHA256_send.c
To run the program
$./goose_hmac_send

7. GoSV_GOOSE.c
	This C program make  use of network interface libraries to send plain GOOSE APDU message with out any security information.  

$ sudo bash 
sudo allows users to run programs with the security privileges of another user (normally the superuser, or root). 

Compilation of program
$ gcc -o GoSV_goose_send GoSV_GOOSE.c
To run the program
$./GoSV_goose_send

8. GoSV_SV.c
	This C program make  use of network interface libraries to send plain SV APDU message with out any security information.  

$ sudo bash 
sudo allows users to run programs with the security privileges of another user (normally the superuser, or root). 

Compilation of program
$ gcc -o GoSV_sv_send GoSV_SV.c
To run the program
$./GoSV_sv_send
