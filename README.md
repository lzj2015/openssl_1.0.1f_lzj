## Openssl_1.0.1f_lzj 


This openssl, based on openssl-1.0.1f, is an open source cryptographic toolkit that provide some support of Chinese national cryptographic algorithms and protocols which specified in the GM/T serial standards.


## Features

 - Support Chinese GM/T cryptographic standards.
 - Maintained by the Zhijie Liu. 

## GM/T Algorithms

This openssl will support all the following GM/T cryptographic algorithms:

 - SM3 (GM/T 0004-2012): cryptographic hash function with 256-bit digest length.
 - SM4 (GM/T 0002-2012): block cipher with 128-bit key length and 128-bit block size.
 - SM2 (GM/T 0003-2012): elliptic curve cryptographic schemes including digital signature scheme, public key encryption, (authenticated) key exchange protocol and one recommended 256-bit prime field curve `SM2`.

## GM/T Protocols

The GM/T standards cover 1 protocols:

 - TLS VPN Protocol  (GM/T 0024-2014)

The GM/T 0024-2014 TLS VPN protocol is different from TLS1.0 in the follows aspects:

 - Current version of TLS is 1.0 (0x0300) while GM/T SSL version is 1.1 (0x0101), but in this implementation, i did not change the version, so it still (0x0300).
 - The handshake protocol of GM/T SSL is different from TLS handshake. The client point has to send his certificate. 


This openssl supports the standard TLS 1.0 protocol with SM2/SM3/SM4 ciphersuites. Currently the following ciphersuites are supported:

```
SM2DH_WITH_SMS4_SM3
```

## Quick Start

The building of the project is the same sa the ([openssl-1.0.1f](https://www.openssl.org/source/old/1.0.1/)).

Download ([openssl_1.0.1f_lzj-master.zip](https://github.com/lzj2015/openssl_1.0.1f_lzj.git)), uncompress it and go to the source code folder. On Windows(mingw), Linux or MacOS, run the following commands:

 ```sh
 $ ./config
 $ make
 $ sudo make install
 ```
 
## Some example
Using GM/T 0024-2014 TLS VPN protocol.

$ ./ssltest -tls1 -named_curve "SM2" -client_auth -server_auth -CAfile ../sm2ssltest/CA.pem  -cert ../sm2ssltest/SS.pem -key ../sm2ssltest/SS.pem -c_cert ../sm2ssltest/CS.pem -c_key ../sm2ssltest/CS.pem
Available compression methods:  NONE
client authentication
server authentication
depth=1 /C=CN/ST=BJ/L=GUANGZHOU/O=LZJ Technology LTD./OU=SORB of openssl/CN=Test CA (SM2)
depth=0 /C=CN/ST=BJ/L=GUANGZHOU/O=LZJ Technology LTD./OU=BSRC of openssl/CN=server sign (SM2)
depth=1 /C=CN/ST=BJ/L=GUANGZHOU/O=LZJ Technology LTD./OU=SORB of openssl/CN=Test CA (SM2)
depth=0 /C=CN/ST=BJ/L=GUANGZHOU/O=LZJ Technology LTD./OU=BSRC of openssl/CN=client sign (SM2)
TLSv1, cipher TLSv1/SSLv3 SM2DH-WITH-SM4-SM31 handshakes of 256 bytes done


You will get some example in test folder for using sm3, sm4, sm2 signature sm2 decryption or sm2 encryption as well.



mail: liuzhj28@gmail.com
