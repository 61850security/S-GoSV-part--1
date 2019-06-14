echo `openssl genrsa -out private_key1024.pem 1024`



echo `openssl rsa -in private_key1024.pem -outform PEM -pubout -out public_key1024.pem`

