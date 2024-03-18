# Crypto-File-Safe

Encrypt files with delayed decryption time.
This is a command line interface application.

## Start application

To run the application, you need Java 11 or higher.

You may start the application by executing this command:

```
java -jar Crypto-File-Safe-1.0.jar
```

## Encrypt a file

Here you have an example of how you can encrypt a file with ``test.pdf`` as name.

```
Choose an action:
0 - Encrypt a file
1 - Decrypt a file
Enter action: 0
Enter file name: test.pdf
Enter difficulty: 2
Enter passphrase: Password123
Public Key: MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApiNTYFh
Private Key: MIIJQQIBADANBgkqhkiG9w0BAQEFAASCCSswggknAgEAAoICAQCmI1NgWH+KI8mHp0JF5Dv1LL
Encrypted: test.pdf finished in 352 ms.
```

## Decrypt a file

This example shows you how to decrypt the file ``test.pdf.zip`` from last example.

```
Choose an action:
0 - Encrypt a file
1 - Decrypt a file
Enter action: 1
Enter file name: test.pdf.zip
Enter passphrase: Password123
Decrypted: test.pdf.rsa finished in 11901 ms.
```

