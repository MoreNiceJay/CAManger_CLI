import sys, pycurl,json, random, hashlib, calendar,time, datetime, os, random,OpenSSL
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_csr
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption,load_pem_private_key
from os import walk
from cryptography import x509

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

def search_dir(dir):
    try:
        files = os.listdir(dir)
        for file in files:
            #fullFilename = os.path.join(dir, file)

            if os.path.isdir(file):
                print(file)
    except PermissionError:
        pass




def main():
    command = sys.argv[1]
    if command in ("generatekey"):
        path = os.getcwd()
        print("Choose the key algorithm for your keypair")
        key_algorithm = input("1. RSA 2048	 2. RSA 4096	3. ECDSA P256 	4. ECDSA P384 \n")
        if int(key_algorithm) == 1:
            private_key = generate_RSA_private_key(2048)
            print("RSA 2048 choosed")
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
            print("Please type number between 1-4")
            sys.exit()
        key_name = input("Type your key name \n")

        try:
            YOUR_DIRECTORY_NAME =  key_name + "_key_directory"
            if not (os.path.isdir(YOUR_DIRECTORY_NAME)):
                os.makedirs(os.path.join(YOUR_DIRECTORY_NAME))
        except OSError as e:
            if e.errno != errno.EEXIST:
                print("Failed to create directory!!!!!")
                raise
        private_key_path = "./" + YOUR_DIRECTORY_NAME + "/"+ key_name  + "_private_key.pem"
        with open(private_key_path, "wb") as key_file:
            pem = private_key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm = serialization.NoEncryption()
            )
            key_file.write(pem)
        public_key_path = "./" + YOUR_DIRECTORY_NAME + "/"+ key_name  + "_public_key.pem"
        with open(public_key_path, "wb") as key_file:
            public_key = generate_pub_key(private_key)
            pem = public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            key_file.write(pem)
        print("Keys are generated in " + YOUR_DIRECTORY_NAME + " directory")

    elif command in ("generatecsr"):
        key_path = input("enter your private key pem file path \n:")

        with open(key_path, "rb") as f:
            private_key_pem = f.read()
            private_key = load_pem_private_key(private_key_pem, password=None, backend=default_backend())
            print("private key selected")

        pub_path = input("enter your public key pem file path \n:")
        with open(pub_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
            print("publick key selected")

            country = input("Country Name (2 letter code) [GB]:").capitalize()
            state = input("State or Province Name (full name) [Berkshire]:")
            local = input("Locality Name (eg, city) [Newbury]:")
            organization = input("Organization Name (eg, company) [My Company Ltd]:")
            name_of_us = input("Common Name (eg, your name or your server's hostname) []:")
            domain_url = input("Domain URL (eg, www.mofas.io) []:")

            csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
                x509.NameAttribute(NameOID.LOCALITY_NAME, local),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.COMMON_NAME, name_of_us),
                ])).add_extension(
                x509.SubjectAlternativeName([
                    # Describe what sites we want this certificate for.
                    x509.DNSName(domain_url),
                ]),
                critical = False,
            # Sign the CSR with our private key.
            ).sign(private_key, hashes.SHA256(), default_backend())
            # Write our CSR out to disk.
            filepath = os.getcwd() + "/csr.pem"

            with open(filepath, "wb") as f:
                f.write(csr.public_bytes(serialization.Encoding.PEM))
            print("CSR file save in " , filepath)

    elif command in ("requestcert"):
        csr_path = input("enter your csr pem file path \n:")

        with open(csr_path, "rb") as f:
            csr_pem = f.read()
            csr = load_pem_x509_csr(csr_pem,  backend=default_backend())
            print("csr selected.")
        print("\n")


        subject_country = csr.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value.capitalize()
        subject_common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        subject_organization = csr.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        subject_locality = csr.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value
        subject_state = csr.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, subject_country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject_state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, subject_locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_organization),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_common_name),
        ])

        search_dir(os.getcwd())
        choosed_CA = input("choose your CA :")
        path = os.getcwd() + "/" + choosed_CA
        private_key_path = path + "/private_key.pem"
        public_key_path = path + "/public_key.pem"

        with open(private_key_path, "rb") as f:
            private_key_pem = f.read()
            CA_private_key = load_pem_private_key(private_key_pem, password=None, backend=default_backend())
            print("private key selected")

        with open(public_key_path, "rb") as key_file:
            CA_public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        CA_path = path + "/ca.conf"
        with open(CA_path, "rt") as f:
            lines = f.readlines()
            for line in lines:
                if line.split(':')[0] == "COUNTRY_NAME":
                    print(line.split(':')[1])
                    issuer_country = line.split(':')[1][:2]
                elif line.split(':')[0] == "COMMON_NAME":
                    issuer_common_name = line.split(':')[1]
                elif line.split(':')[0] == "ORGANIZATION_NAME":
                    issuer_organization = line.split(':')[1]
                elif line.split(':')[0] == "LOCALITY_NAME":
                    issuer_locality = line.split(':')[1]
                elif line.split(':')[0] == "STATE_OR_PROVINCE_NAME":
                    issuer_state = line.split(':')[1]
                    print("::" + issuer_country + "::")
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, issuer_country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, issuer_state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, issuer_locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_organization),
            x509.NameAttribute(NameOID.COMMON_NAME, issuer_common_name),
        ])

        issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, subject_country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject_state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, subject_locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_organization),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_common_name),
        ])

        one_day = datetime.timedelta(1, 0, 0)

        cert = x509.CertificateBuilder().subject_name(
        subject
        ).issuer_name(
        issuer
        ).public_key(
        CA_public_key
        ).serial_number(
        x509.random_serial_number()
        ).not_valid_before(
        datetime.datetime.utcnow()
        ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical = False,
        # Sign our certificate with our private key
        ).sign(CA_private_key, hashes.SHA256(), default_backend())
        # Write our certificate out to disk.


        with open('./' + subject_common_name + ".crt", "wb") as f:
            f.write(cert.public_bytes(
                encoding=serialization.Encoding.PEM,
            ))
        print("Your certificate has been published, you can have it in the path " +path + '/' + subject_common_name + ".crt" )


if  __name__ =='__main__':
    main()
