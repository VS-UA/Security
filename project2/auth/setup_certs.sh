#!/bin/bash

# https://www.thomasvitale.com/https-spring-boot-ssl-certificate/

keytool -genkeypair \
        -alias springboot \
        -keyalg RSA \
        -keysize 8192 \
        -storetype PKCS12 \
        -keystore springboot.p12 \
        -validity 3650 \
        -storepass password

keytool -import \
        -alias springboot \
        -file myCertificate.crt \
        -keystore springboot.p12 \
        -storepass password

#keytool -export \
#        -keystore springboot.p12 \
#        -alias springboot \
#        -file myCertificate.crt
