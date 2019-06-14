#generate private key with 1024 bit key size
echo `openssl genrsa -out myprivate.pem 1024`

#generate public key 
echo `openssl rsa -in myprivate.pem -pubout > mypublic.pem`

#printing of private and public keys
echo `cat myprivate.pem`
echo `cat mypublic.pem`

#signing of GOOSEAPDU.txt with RSA private key 
echo `openssl dgst -sha256 -sign myprivate.pem -out sha256.sign GOOSEAPDU.txt`

#printing of generated signature of 128 bytes size
echo `hexdump sha256.sign`

#verifying the generated signature with the shared RSA public key 
echo `openssl dgst -sha256 -verify mypublic.pem -signature sha256.sign GOOSEAPDU.txt`
