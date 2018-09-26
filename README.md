# LDAPExamples-JavaWithSSL
Sample Java Code - LDAP Authentication using SSL

This is a quick command line example using Java to authenticate users via an LDAP directory. 

The connection between the application and the directory server is SSL encrypted. As few directory servers have
publically signed certificates, this requires configuring a trust between your application and the issuer of
the directory's certificate. 

Ideally, the directory certificate was signed by a certificate authority (CA). Establishing a trust with the issuing
CA requires a copy of the CA server's public key. You can use openssl to obtain the keychain from the LDAP server. 

 `echo "" | openssl s_client -connect directoryserver.domain.ccTLD:636 -showcerts`
 
 Look for
`-----BEGIN CERTIFICATE-----`

The first entry will be the directory server cert public key -- two lines above "BEGIN CERTIFICATE", you will see 
a line with CN=directoryserver.domain.ccTLD (assuming the directory server cert name matches the hostname used for
connections -- the hostname *may* be a SAN instead of the cert CN)

The remaining "BEGIN CERTIFICATE" through "END CERTIFICATE" sections are public keys for the chain of servers that issued
the domain controller cert. Copy each section into a file -- include both the "-----BEGIN CERTIFICATE-----" and
"-----END CERTIFICATE-----" lines. 

Import the public key file(s) into a trust store to be used within your application:
`keytool -import -file CAPublicKeyFile.cer -keystore trustStoreFile`

Once the truststore has been created, supply the appropriate values to the "Editable Variables" to establish a connection
to *your* LDAP server. 
