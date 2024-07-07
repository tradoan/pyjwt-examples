import jwt
import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

payload = {"sub": "someone", "exp": datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(seconds=30), "iss": "urn:foo"}
print(payload)

# The difference between RS256 and HS256: https://auth0.com/blog/rs256-vs-hs256-whats-the-difference/
# Note: With PEM format we can just open the key files without using cryptography.hazmat.primitives.serialization.load_pem_public_key()
# PEM - OpenSSL Keys
# https://blog.miguelgrinberg.com/post/json-web-tokens-with-public-key-signatures/page/2#comments
# https://stackoverflow.com/questions/29650495/how-to-verify-a-jwt-using-python-pyjwt-with-public-key
# openssl genpkey -out mykey.pem -algorithm rsa -pkeyopt rsa_keygen_bits:2048 
# openssl rsa -in mykey.pem -out mykey.pub -pubout

# Load the key we created
# https://cryptography.io/en/3.1/hazmat/primitives/asymmetric/serialization/?highlight=openssh%20import%20rsa#pem
# with open("mykey.pem", "rb") as key_file:
#     private_key = serialization.load_pem_private_key(
#         key_file.read(),
#         password=None,
#         backend=default_backend()
#     )

# with open("mykey.pub", "rb") as key_file:
#     public_key = serialization.load_pem_public_key(
#         key_file.read(),
#         backend=default_backend()
# )

# with open('mykey.pem') as key_file:
#     private_key = key_file.read()

# with open('mykey.pub') as key_file:
#     public_key = key_file.read()

# openssl genrsa -out rsa 4096
# openssl rsa -in jwt-key -pubout > jwt-key.pub 
# or: openssl rsa -in jwt-key -out jwt-key.pub -pubout
# You can create rsa keys with ssh-keygen:  ssh-keygen -m PEM -t rsa -b 4096 -C "your_email@example.com" -f ssh_pem
# then generate the public key from the private key to try out at jwt.io: openssl rsa -in ssh_pem -out ssh_rsa.pub -pubout

with open('rsa') as key_file:
    private_key = key_file.read()
# print(private_key)
with open('rsa.pub') as key_file:
    public_key = key_file.read()

encoded = jwt.encode(payload, private_key, algorithm="RS256")
# We can try the endcoded token out at https://jwt.io/ with rsa_1.pub
# rsa_1.pub is created as follows: openssl rsa -in rsa -out rsa_1.pub -pubout
print(encoded)
decoded = jwt.decode(encoded, public_key, algorithms=["RS256"], issuer="urn:foo", options={"require": ["exp", "sub"]})
print(decoded)


# OpenSSH Keys
# Note: With PEM format we can just open the key files without using cryptography.hazmat.primitives.serialization.load_ssh_public_key()
# ssh-keygen -t rsa -b 4096 -m pem -f ssh_pem
# with open('ssh_pem') as key_file:
#     ssh_private_key = key_file.read()
# print(private_key)

# with open('ssh_pem.pub') as key_file:
#     ssh_public_key = key_file.read()


# ssh-keygen -t rsa -b 4096 -f ssh_key_new    
# https://cryptography.io/en/3.1/hazmat/primitives/asymmetric/serialization/?highlight=openssh%20import%20rsa#openssh-public-key
with open("ssh_key", "rb") as key_file:
    # print(key_file.read())
    ssh_private_key = serialization.load_ssh_private_key(
        # key data must be a bytes-like object
        key_file.read(),
        password=None,
        backend=default_backend()
    )

with open("ssh_key.pub", "rb") as key_file:
    ssh_public_key = serialization.load_ssh_public_key(
        key_file.read(),
        backend=default_backend()
    ) 
# # it works as well
# with open('ssh_key.pub') as key_file:
#     ssh_public_key = key_file.read()
# print(ssh_public_key)

encoded = jwt.encode(payload, ssh_private_key, algorithm="RS256")
# To try it out at jwt.io we have to convert the OPENSSH private key to an RSA private key:
# ssh-keygen -p -m PEM -f ssh_key
print(encoded)
decoded = jwt.decode(encoded, ssh_public_key, algorithms=["RS256"], options={"require": ["exp", "sub"]})
print(decoded)