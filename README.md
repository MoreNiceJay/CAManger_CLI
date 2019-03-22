# CAManger_CLI

###### **예제 파일도 함께 들어있으니 그대로 따라 하시면 됩니다**.



# 키생성

#### 목적

4가지 알고리즘으로 개인의  프라이빗 키와 그에 파생되는 퍼블릭 키를 만듭니다.

#### 명령어

```python
python CAManager.py generatekey
```

#### 인자

Choose the key algorithm for your keypair

RSA 2048  2. RSA 4096   3. ECDSA P256  4. ECDSA P384

//넘버로 알고리즘을 선택합니다.

Type your key name

//키와 디렉토리의 이름을 짓습니다.

//디렉토리는 현재 작업중인 path에 만들어 집니다.

#### 아웃풋

디렉토리에 프라이빗 키와 퍼블릭 키를 만듭니다.



# CSR 생성

#### 목적

인증서를 요청하기 위해 필요한 정보가 담긴 CSR을 생성합니다.

#### 명령어

```
python CAManager.py requestcert
```

#### 인자

enter your private key pem file path

//나의 프라이빗 파일의 path를 적습니다. 없을 경우, 키생성을 선행 합니다

//예)./user_key_1/1_private_key.pem

enter your public key pem file path

//나의 퍼블릭 파일의 path를 적습니다. 없을 경우, 키생성을 선행 합니다

//예)./user_key_1/1_public_key.pem



Country Name (2 letter code) [GB]:

State or Province Name (full name) [Berkshire]:

Locality Name (eg, city) [Newbury]:

Organization Name (eg, company) [My Company Ltd]:

Organization Unit Name (eg, section) []:

Common Name (eg, your name or your server's hostname) []:

Domain URL (eg, www.mofas.io) []:

//각각의 정보를 적습니다

//**주의 국가는 2글자의 코드를 적습니다

//예) Korea = KR,  United States = US

#### 아웃풋

현재경로에  csr.pem이라는 CSR을 생성 합니다.

# 인증서 발급

#### 목적

인증서를 발급 받습니다.

#### 명령어

```python
python CAManager.py generatekey
```

#### 필요조건

CA의 정보가 담긴 텍스트 파일(ca.conf), CA의 프라이빗키(private_key.pem), CA의 퍼블릭키(public_key.pem) 들이 한 디렉토리에 담겨 있어야 합니다. 이름이 정확해야 합니다.

CA_directory(private_key.pem, public_key, ca.conf )

**ca.conf**

ca.conf는 규격을 지켜줘야 합니다

(예)

COUNTRY_NAME:KR
COMMON_NAME:mofas.io
ORGANIZATION_NAME:mofas
LOCALITY_NAME:seocho
STATE_OR_PROVINCE_NAME:Seoul
DOMAIN:mofas.io



#### 인자

enter your csr.pem file path

//CSR의 파일 경로를 적어줍니다. CSR이 없을 경우, CSR 생성을 선행 합니다.

// 예) ./csr.pem

choose your CA

//CA 폴더를 선택합니다

//예) CA1

#### 아웃풋

현재 경로에 회사이름으로 인증서가 생성됩니다.

mofas.crt
