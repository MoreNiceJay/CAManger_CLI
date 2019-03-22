import sys, pycurl,json, random, hashlib, calendar,time, datetime, os, random,OpenSSL
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption,load_pem_private_key


from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime
from os.path import exists, join


def generate_RSA_private_key(KEY_SIZE):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE,
        backend=default_backend()
    )
    return private_key

def generate_ECP384_private_key():
    private_key = ec.generate_private_key(
    ec.SECP384R1(), default_backend()
    )
    return private_key

def generate_ECP256_private_key():
    private_key = ec.generate_private_key(
    ec.SECP384R1(), default_backend()
    )
    return private_key

def generate_pub_key(private_key):
    public_key = private_key.public_key()
    return public_key

def encode_RSA_pem_format():
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
#def encode_EC_pem_format():


def sign_with_RSA2048(message, private_key):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature
def open_existed_key(filepath):
    with open(filepath, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
        return private_key
def serialize_existed_key(private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
    )
    pem.splitlines()[0]
    return pem
def verify_sign(signature, message,public_key):
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )




def main():
    command = sys.argv[1]
    if command in ("generatekeypair"):
        path = os.getcwd()
        print("Choose the key algorithm for your keypair")
        key_algorithm = input("1. RSA 2048	 2. RSA 4096	3. ECDSA P256 	4. ECDSA P384 \n")
        if int(key_algorithm) == 1:
            private_key = generate_RSA_private_key(2048)
        elif int(key_algorithm) == 2:
            print("RSA 4096 choosed")
            private_key = generate_RSA_private_key(4096)
        elif int(key_algorithm) == 3:
            print("ECDSA P256")
            private_key = generate_ECP256_private_key()
        elif int(key_algorithm) == 4:
            print("ECDSA P384")
            private_key = generate_ECP384_private_key()
        else :
            print("please type number between 1-4")
            sys.exit()

        try:
            YOUR_DIRECTORY_NAME = "user_key"

            if not (os.path.isdir(YOUR_DIRECTORY_NAME)):
                os.makedirs(os.path.join(YOUR_DIRECTORY_NAME))
        except OSError as e:
            if e.errno != errno.EEXIST:
                print("Failed to create directory!!!!!")
                raise

        with open(b"./user_key/private_key.pem", "wb") as key_file:
            pem = private_key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm = serialization.NoEncryption()
            )
            key_file.write(pem)

        with open(b"./user_key/public_key.pem", "wb") as key_file:
            public_key = generate_pub_key(private_key)
            pem = public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            key_file.write(pem)

        print("Keys are generated in " + path)
        print("Please keep it safe and don't share it with anyone")

    elif command in ("requestcert"):

        with open("./CA_key/CA_private_key.pem", "rb") as f:
            private_key_pem = f.read()
            CA_key = load_pem_private_key(private_key_pem, password=None, backend=default_backend())

        print("Do you have existed pem file?")
        keys_are_existed = input("1. yes       2. no \n:")
        if (keys_are_existed) == "yes" or (keys_are_existed) == "1" :
            keypath = input("Type your publickey path \n:")
            #with open(keypath, "rb") as key_file:
            with open(".\public_key.pem", "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend = default_backend()
                )
            print("publickey selected.")
            print("\n")
        elif (keys_are_existed) == "no" or (keys_are_existed) == "2":
            path = os.getcwd()
            print("Choose the key algorithm for your keypair")
            key_algorithm = input("1. RSA 2048	 2. RSA 4096	3. ECDSA P256 	4. ECDSA P384 \n")
            if int(key_algorithm) == 1:
                private_key = generate_RSA_private_key(2048)
            elif int(key_algorithm) == 2:
                print("RSA 4096 choosed")
                private_key = generate_RSA_private_key(4096)
            elif int(key_algorithm) == 3:
                print("ECDSA P256")
                private_key = generate_ECP256_private_key()
            elif int(key_algorithm) == 4:
                print("ECDSA P384")
                private_key = generate_ECP384_private_key()
            else:
                print("please type number between 1-4")
                sys.exit()

            try:
                YOUR_DIRECTORY_NAME = "user_key"

                if not (os.path.isdir(YOUR_DIRECTORY_NAME)):
                    os.makedirs(os.path.join(YOUR_DIRECTORY_NAME))
            except OSError as e:
                if e.errno != errno.EEXIST:
                    print("Failed to create directory!!!!!")
                    raise

            with open(b"./user_key/private_key.pem", "wb") as key_file:
                pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
                key_file.write(pem)

            with open(b"./user_key/public_key.pem", "wb") as key_file:
                public_key = generate_pub_key(private_key)
                pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                key_file.write(pem)

            print("Keys are generated in " + path)
            print("Please keep it safe and don't share it with anyone")




        country = input("Country Name (2 letter code) [GB]:").capitalize()
        state = input("State or Province Name (full name) [Berkshire]:")
        local = input("Locality Name (eg, city) [Newbury]:")
        organization =      input("Organization Name (eg, company) [My Company Ltd]:")
        organization_unit = input("Organization Unit Name (eg, section) []:")
        name_of_CA =        input("Common Name (eg, your name or your server's hostname) []:")

        one_day = datetime.timedelta(1, 0, 0)

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, name_of_CA),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organization_unit),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, name_of_CA),
        ]))
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + one_day * 365 * 10)
        builder = builder.serial_number(random.randint(1,9999999))
        builder = builder.public_key(public_key)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )
        certificate = builder.sign(
            private_key=CA_key, algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        print(isinstance(certificate, x509.Certificate))


        with open(organization + ".crt", "wb") as f:
            f.write(certificate.public_bytes(
                encoding=serialization.Encoding.PEM,
            ))














if  __name__ =='__main__':
    main()
