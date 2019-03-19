# CAManger_CLI
 Generate keypair and certificate for user using RSA and Eliptic Curve algorithm.
# 키생성

#### 예제

```python
python CAManager.py generatekeypair
```

Keys are generated in (path)



# 사인 요청

#### 예제

```
python CAManager.py requestcert
```

Do you have existed pem file?

1. yes 	2. no

-> If yes is selected,

​	-> can't find key

​	can't find a key file

​	please place key files in the (path)

-> If no is selected,

​	Keys are generated in (path)



Country Name (2 letter code) [GB]:

State or Province Name (full name) [Berkshire]:

Locality Name (eg, city) [Newbury]:

Organization Name (eg, company) [My Company Ltd]:

Organization Unit Name (eg, section) []:

Common Name (eg, your name or your server's hostname) []:

Email Address []:



Requesting certificate.....	



Your certificate has been provided in the path 

/path/
