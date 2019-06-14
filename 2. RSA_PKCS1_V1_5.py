import time
from base64 import ( b64encode, b64decode,)

from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA

# GOOSE APDU data of 137 bytes 
message = "\x61\x81\x86\x80\x1A\x46\x52\x45\x41\x2D\x47\x6F\x53\x56\x2D\x31\x20\x2F\x4C\x4C\x4E\x30\x24\x47\x4F\x24\x67\x63\x62\x30\x31\x81\x03\x00\x9C\x40\x82\x18\x46\x52\x45\x41\x2D\x47\x6F\x53\x56\x2D\x31\x20\x2F\x4C\x4C\x4E\x30\x24\x47\x4F\x4F\x53\x45\x31\x83\x0B\x46\x52\x45\x41\x2D\x47\x6F\x53\x56\x2D\x31\x84\x08\x38\x6E\xBB\xF3\x42\x17\x28\x0A\x85\x01\x01\x86\x01\x0A\x87\x01\x00\x88\x01\x01\x89\x01\x00\x8A\x01\x08\xAB\x20\x83\x01\x00\x84\x03\x03\x00\x00\x83\x01\x00\x84\x03\x03\x00\x00\x83\x01\x00\x84\x03\x03\x00\x00\x83\x01\x00\x84\x03\x03\x00\x00";

print("size of message",len(message))

#sender side signing code
pr_key = RSA.importKey(open('private_key1024.pem').read())
start_time = time.time()
h = SHA256.new(message)
signature = PKCS1_v1_5.new(pr_key).sign(h)
print("Type of signature",type(signature))
print("Signature",len(signature))
print("--- %s signing seconds ---" % (time.time() - start_time))
print("Generated Signature=",signature)


#receiver side verification code
pub_key = RSA.importKey(open('public_key1024.pem').read())
start_time = time.time()
h = SHA256.new(message)
try:
	PKCS1_v1_5.new(pub_key).verify(h, signature)
	print("--- %s verification seconds ---" % (time.time() - start_time))
	print "The signature is valid."
except (ValueError, TypeError):
	print "The signature is not valid."

