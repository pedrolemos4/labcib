# Lab 1 - Embedded

## Students

- 1190830: Luís Correia
- 1191526: Pedro Torres
- 1190974: Pedro Lemos

## Introduction

This file documents all of the work that was developed in the scope of the [Lab 1 project](https://github.com/labcib/lab-embedded) for the LABCIB course unit.

As requested, this introduction describes all files that are delivered, as well as execution instructions for each of them where applicable. We have also compiled the requested [TARGETS folder](./TARGETS/), whose contents will be expanded further on this report.

Before proceeding any further, the vending machine used in this assignment is **Vending Machine 6**.

The included files and directories are the following:
- [findLength.py](findLength.py): script used in Target 1 to obtain the length of the developer's password.
    - Before executing, it's necessary to verify to which port the Arduino is connected, and on Linux systems it's also necessary to grant execution permissions on that device. The path used for all of the scripts was `/dev/ttyUSB0`, but this can be different on other computers. 
    - To execute, grant the permissions specified above, install the requirements found in [requirements.txt](./requirements.txt) and execute it through python:

```
sudo chmod 777 /dev/ttyUSB0 
pip install -r requirements.txt 
python3 findLength.py
```

- [timingAttack.py](timingAttack.py): script used in Target 1 to crack the developer's password, having obtained its length with the previous script. Execution instructions are the same.
- [dump.py](dump.py): script used in Target 2 to dump the firmware of the vending machine. Execution instructions are the same as the previously presented, with the note that the developer password is statically specified in the code, so for a different vending machine it'd have to be changed.
- [crackOTP.py](crackOTP.py): script used to crack the OTP generator in Target 6. Same execution instructions as above with the note that, as with the script above, the admin and C&C passwords are statically used in the code.
- [secrets.csv](./TARGETS/secrets.csv): The requested file that contains Dans' password; Alans' password; c&c password; and the Final secret.
- [firmwares directory](./TARGETS/firmwares/): Contains all of the memory regions that were dumped from the vending machine.
- [keysSigs directory](./TARGETS/keysSigs/): Contains the cryptographic assets that were extracted and identified, as well as the resulting decrypted message. Each will be described in the appropriate section.

# PART 1: Initial targets

## Development password

**TARGET 1: Developer password**

To determine the developer password, we began by identifying its length. We achieved this by sending passwords of varying lengths to the Nano device and measuring the response time for each attempt - thus, a timing attack. This approach allowed us to determine that the password has a length of 13 characters. The script to achieve this can be checked in the [Find Length](findLength.py) file.

![alt text](./images/lengthDiscover.png)

By plotting the time taken by each attempt, and being that each attempt is a string with N characters, we can discover the password's length by measuring for which N the time taken by the vending machine to process the user input is higher. This graph is presented below:

![lengthDiscoverPlot](./images/lengthDiscoverPlot.png)

This clearly confirms what was stated previously - that the password is 13 characters long.

After obtaining the password length, we conducted another timing attack. We initialized the password with 13 "a" characters and iterated through each letter position, testing all possibilities from 'a' to 'z' for the one that resulted in the longest response time. We then saved this letter and repeated the process for the next position. By identifying the letter that caused the longest response at each position, we obtained the correct password.
The script to achieve this can be checked in the [Timing Attack](timingAttack.py) file.

![alt text](./images/timingAttack.png)

For demonstration purposes, we also plotted relevant information for the first three characters that were discovered. In each plot, we present: on the X axis the character that was attempted for the position specified in the label (0, 1 or 2, since we're only presenting the first three); on the Y axis we show the time that the vending machine took to interpret the character presented on the X axis.

![firstCharTimes.png](./images/firstCharTimes.png)

![secondCharTimes.png](./images/secondCharTimes.png)

![thirdCharTimes.png](./images/thirdCharTimes.png)

From these plots, we can infer that Dan's password for vending machine 6 starts with "dan", which is indeed true, since our script led us to the password "`danoazojnoird`". Testing this password interactively through the serial interface leads us past the login stage, confirming the validity of our findings.

## Firmware

**TARGET 2: The dumped firmware in a binary file**

For this stage, the [dump.py](dump.py) was developed. What it does is login into the console with the developer password (discovered in the previous step), and then use the console to dump the firmwares. Firstly, we programatically input "1" on the console to instruct that we want to dump a region of memory. Then, a prompt that asks us what memory region we want to access is answered with a number from 0 to 2. We do this on a loop so that we can dump all available memory regions. The dumped firmwares can be seen in the folder [Firmwares](firmwares).

## Confidential Information

**TARGET 3: Confidential strings**

By using the `strings` command with the dumped firmware (`strings ./TARGETS/firmwares/firmware_dump0`), we located two strings that could be important.

First string : 
```
MIIEpAIBAAKCAQEArCmtJqLxkN2/FaeamA1J5HtuZcuGW9eO5r9mGrsr6vgQ2JqRdu13Mzxaj/kWrvsk94x6jcwGPyC5dAucRvEpNLQFA4Dm4IlTJhi2Ll9nnQi3//2rozIwJZ36aDG1rooJ8kfhp01+W3GwnqpcX3MIvCcd4qclrl1ShOi9AyC5jZSdPFfdVpsG7lc8Z8/ThNPGynJLRWPf6qDs+slk4YKkhaDtWo54ZOSVfv6mUeFEAhZlowQavfUCejqYRaiP7CJry7f0O9+1AWIvzS0Tp3OZyEsd+YKNzYKSkhof3cTr7+OqqpUKiyW4xHiiyHOZgmuOTP+iRffYO4mnKv+/MzNujQIDAQABAoIBACTnShZeFynWXn9lzd2J+6zeSGvJlKNbMWaE4H4aYO+c/P9xIn07qbFx3ne+DP61Ftd5ZUu/0Bb4DMizNGyAhTSm4ew+VT8MMKaZ5XNLQAqJM+fLmF8DAw8NLf/np+oh7L/iaJxUICG53QIlwmczYUvzlpRe/9TAbE/RE7L38M5IEk5nR96lNwxdjSYKAU+LZr37k0JPLZI6JV/KAqevpXDgcchscKFiqwaNDF2vT4TB6/MgkN5SzxE8XXULfHH8/5q2RwjsO1kerWFJ6MGr53Y7WEk2H1e6nqEU+g8RjrkjqFfdOZPH92KRYFMCyjiM9xReCgSEAa2p2HLZN8oKZIECgYEA6++x/05LkM1aPVFJCnAeNTjykQbEpWLNPBZAoX29ZhrBTaa9XMFVMQUzYYk8QbG/I2msR7w4MxwfgTKlfZu2WQ1nRmMTFDAvwrGLRa9XLXkfkzW5a6x0ts2S1Mz6JsLftZe9nlm9BD3uyO44uHKmzhoW7HEXzfq/3klp9vuvBPcCgYEAus2jtkVNURIIxwpxE0H2eX0L825lNUG1hUR4+UyxwsgRuchCXUg88W2xRAFJzEyGMFia0Bx+wLceUjzV2cuVvSwhaaI3Q//1E+M50mxc/E6JKeFDcASXEqlYuvSW6SLEXh78bQykkMMGl0tNlxZYAFIDkHa7xbQKZvksCg19u5sCgYEA0vWM23I/gOcMw/z1aT7c08vqoCBEHnkcd5iSC5OpkS1lIDBx6wj3SpCS46hY14i+FkT7hVzXh2OjC9ukO47KWg/xAu+9dHStj9E+bX2dXoyJ3g/QjmUyKu3fVyU8mwHuE6ntIzSsHKnf44uV7d6eJXUQgDOTDFsjyfcsp2ldkfsCgYAY/eopOJxffEowVvVJ3klbd59hsiNYPLJMYhzNPbWKmbnFYUV/tWpx4nsU3hdBfft1/GS58xYCMn2cAweZW+Nsq7rMpyc9scDYKE5UGKtYFinDsJ+VHQgZNw7n9FE8X6pl7T9YV5isxWrcUvbOf+7GHDLd4QS+Lpg1rqB1t9hagQKBgQCrUeiPnwIDscnzWGAxzvL7UM1o+44AI2PSHwaT4KHHJ5EVJp6dFAz1DG+2u5qecQYCxFkhgSeVSRct1yE5aoVz1cFoPrZO80Rc8gln8I4Q+wxi0yB6LqNF51Pv9Afy/8lN8Egy5wdwyebhe9LaCMIA6NHLZpscns5Eyee5wKFkbQ==
```
Second string : 
```
ksIK1+Q31rnBZbDVkxSqgKPC32KuzGpE0UmnZRAYUS0Xh8q9sOnB1h/d02UIFs6EcXLLJtMJTXQ4ySF1G2lz5UxlBF3b7WJpRzFKLUHyLz9R57qgpbEMDCBJEGmPTArDYsn6i7bRDUNL+NDH95o2LTapA+KIG1fUgAZMlYik5Jjn7nkTFCKHi8i8DxRV+HeJlUUSYIz+k/LPJLuxCuy3Fz/RzlNDtOKh8cd0FoWmYOxi+lKBOLbWGpMFaDp02Ozk5KPBm2JgIqdd0Hnqy+48YnOUaL/44RF3HYPbCW4tMxjAsItim0ULfCM1k1xa1220N8178A7IeoO/pvdTd4m2Sw==
```

The relevance of these strings will be discussed in the next part, as they pertain to cryptographic assets. Aditionally, we're able to locate the password for Admin Alan in these firmwares, which is "`alancqoclrkwjejwvkuxguwpgxckjumvdgiyyzzvvevwsnwpcpcwrs`".

# PART 2: Final Boss

## Identify Cryptographic Assets

**TARGET 4: Identify the cryptographic data**

After analyzing the previous data, we could conclude that the first string is a private key and the second string is a signature. At first sight, we are able to conclude that they are encoded in Base64, so they'll have to be decoded in order for us to explore their contents and figure out what message is present on the provided signature.

## Find the pot of gold

**TARGET 5: c&c password**

With the private key and signature obtained in the previous step, we proceeded by decoding them from Base64 format in order to reveal the hash. We saved each string to a file, and then used the necessary commands to decode that string from Base64 to a binary file.

For each operating system, we have used the following commands:

LINUX:
```
cat key | base64 -d > key.bin
cat sig | base64 -d > sig.bin
```

WINDOWS: 
```
certutil -decode key key.bin  
certutil -decode sig sig.bin  
```

After some attempts with the openssl command, we were able to conclude that the key is an RSA key, and thus the message is signed with this key. We're further able to validate this by using openssl to inspect the key:

```
$ openssl rsa -in key.bin -check -noout -text
Private-Key: (2048 bit, 2 primes)
modulus:
    00:ac:29:ad:26:a2:f1:90:dd:bf:15:a7:9a:98:0d:
    49:e4:7b:6e:65:cb:86:5b:d7:8e:e6:bf:66:1a:bb:
    2b:ea:f8:10:d8:9a:91:76:ed:77:33:3c:5a:8f:f9:
    16:ae:fb:24:f7:8c:7a:8d:cc:06:3f:20:b9:74:0b:
    9c:46:f1:29:34:b4:05:03:80:e6:e0:89:53:26:18:
    b6:2e:5f:67:9d:08:b7:ff:fd:ab:a3:32:30:25:9d:
    fa:68:31:b5:ae:8a:09:f2:47:e1:a7:4d:7e:5b:71:
    b0:9e:aa:5c:5f:73:08:bc:27:1d:e2:a7:25:ae:5d:
    52:84:e8:bd:03:20:b9:8d:94:9d:3c:57:dd:56:9b:
    06:ee:57:3c:67:cf:d3:84:d3:c6:ca:72:4b:45:63:
    df:ea:a0:ec:fa:c9:64:e1:82:a4:85:a0:ed:5a:8e:
    78:64:e4:95:7e:fe:a6:51:e1:44:02:16:65:a3:04:
    1a:bd:f5:02:7a:3a:98:45:a8:8f:ec:22:6b:cb:b7:
    f4:3b:df:b5:01:62:2f:cd:2d:13:a7:73:99:c8:4b:
    1d:f9:82:8d:cd:82:92:92:1a:1f:dd:c4:eb:ef:e3:
    aa:aa:95:0a:8b:25:b8:c4:78:a2:c8:73:99:82:6b:
    8e:4c:ff:a2:45:f7:d8:3b:89:a7:2a:ff:bf:33:33:
    6e:8d
publicExponent: 65537 (0x10001)
privateExponent:
    24:e7:4a:16:5e:17:29:d6:5e:7f:65:cd:dd:89:fb:
    ac:de:48:6b:c9:94:a3:5b:31:66:84:e0:7e:1a:60:
    ef:9c:fc:ff:71:22:7d:3b:a9:b1:71:de:77:be:0c:
    fe:b5:16:d7:79:65:4b:bf:d0:16:f8:0c:c8:b3:34:
    6c:80:85:34:a6:e1:ec:3e:55:3f:0c:30:a6:99:e5:
    73:4b:40:0a:89:33:e7:cb:98:5f:03:03:0f:0d:2d:
    ff:e7:a7:ea:21:ec:bf:e2:68:9c:54:20:21:b9:dd:
    02:25:c2:67:33:61:4b:f3:96:94:5e:ff:d4:c0:6c:
    4f:d1:13:b2:f7:f0:ce:48:12:4e:67:47:de:a5:37:
    0c:5d:8d:26:0a:01:4f:8b:66:bd:fb:93:42:4f:2d:
    92:3a:25:5f:ca:02:a7:af:a5:70:e0:71:c8:6c:70:
    a1:62:ab:06:8d:0c:5d:af:4f:84:c1:eb:f3:20:90:
    de:52:cf:11:3c:5d:75:0b:7c:71:fc:ff:9a:b6:47:
    08:ec:3b:59:1e:ad:61:49:e8:c1:ab:e7:76:3b:58:
    49:36:1f:57:ba:9e:a1:14:fa:0f:11:8e:b9:23:a8:
    57:dd:39:93:c7:f7:62:91:60:53:02:ca:38:8c:f7:
    14:5e:0a:04:84:01:ad:a9:d8:72:d9:37:ca:0a:64:
    81
prime1:
    00:eb:ef:b1:ff:4e:4b:90:cd:5a:3d:51:49:0a:70:
    1e:35:38:f2:91:06:c4:a5:62:cd:3c:16:40:a1:7d:
    bd:66:1a:c1:4d:a6:bd:5c:c1:55:31:05:33:61:89:
    3c:41:b1:bf:23:69:ac:47:bc:38:33:1c:1f:81:32:
    a5:7d:9b:b6:59:0d:67:46:63:13:14:30:2f:c2:b1:
    8b:45:af:57:2d:79:1f:93:35:b9:6b:ac:74:b6:cd:
    92:d4:cc:fa:26:c2:df:b5:97:bd:9e:59:bd:04:3d:
    ee:c8:ee:38:b8:72:a6:ce:1a:16:ec:71:17:cd:fa:
    bf:de:49:69:f6:fb:af:04:f7
prime2:
    00:ba:cd:a3:b6:45:4d:51:12:08:c7:0a:71:13:41:
    f6:79:7d:0b:f3:6e:65:35:41:b5:85:44:78:f9:4c:
    b1:c2:c8:11:b9:c8:42:5d:48:3c:f1:6d:b1:44:01:
    49:cc:4c:86:30:58:9a:d0:1c:7e:c0:b7:1e:52:3c:
    d5:d9:cb:95:bd:2c:21:69:a2:37:43:ff:f5:13:e3:
    39:d2:6c:5c:fc:4e:89:29:e1:43:70:04:97:12:a9:
    58:ba:f4:96:e9:22:c4:5e:1e:fc:6d:0c:a4:90:c3:
    06:97:4b:4d:97:16:58:00:52:03:90:76:bb:c5:b4:
    0a:66:f9:2c:0a:0d:7d:bb:9b
exponent1:
    00:d2:f5:8c:db:72:3f:80:e7:0c:c3:fc:f5:69:3e:
    dc:d3:cb:ea:a0:20:44:1e:79:1c:77:98:92:0b:93:
    a9:91:2d:65:20:30:71:eb:08:f7:4a:90:92:e3:a8:
    58:d7:88:be:16:44:fb:85:5c:d7:87:63:a3:0b:db:
    a4:3b:8e:ca:5a:0f:f1:02:ef:bd:74:74:ad:8f:d1:
    3e:6d:7d:9d:5e:8c:89:de:0f:d0:8e:65:32:2a:ed:
    df:57:25:3c:9b:01:ee:13:a9:ed:23:34:ac:1c:a9:
    df:e3:8b:95:ed:de:9e:25:75:10:80:33:93:0c:5b:
    23:c9:f7:2c:a7:69:5d:91:fb
exponent2:
    18:fd:ea:29:38:9c:5f:7c:4a:30:56:f5:49:de:49:
    5b:77:9f:61:b2:23:58:3c:b2:4c:62:1c:cd:3d:b5:
    8a:99:b9:c5:61:45:7f:b5:6a:71:e2:7b:14:de:17:
    41:7d:fb:75:fc:64:b9:f3:16:02:32:7d:9c:03:07:
    99:5b:e3:6c:ab:ba:cc:a7:27:3d:b1:c0:d8:28:4e:
    54:18:ab:58:16:29:c3:b0:9f:95:1d:08:19:37:0e:
    e7:f4:51:3c:5f:aa:65:ed:3f:58:57:98:ac:c5:6a:
    dc:52:f6:ce:7f:ee:c6:1c:32:dd:e1:04:be:2e:98:
    35:ae:a0:75:b7:d8:5a:81
coefficient:
    00:ab:51:e8:8f:9f:02:03:b1:c9:f3:58:60:31:ce:
    f2:fb:50:cd:68:fb:8e:00:23:63:d2:1f:06:93:e0:
    a1:c7:27:91:15:26:9e:9d:14:0c:f5:0c:6f:b6:bb:
    9a:9e:71:06:02:c4:59:21:81:27:95:49:17:2d:d7:
    21:39:6a:85:73:d5:c1:68:3e:b6:4e:f3:44:5c:f2:
    09:67:f0:8e:10:fb:0c:62:d3:20:7a:2e:a3:45:e7:
    53:ef:f4:07:f2:ff:c9:4d:f0:48:32:e7:07:70:c9:
    e6:e1:7b:d2:da:08:c2:00:e8:d1:cb:66:9b:1c:9e:
    ce:44:c9:e7:b9:c0:a1:64:6d
RSA key ok
```

Once we had the decoded files (private key and signature), we used the following commands to decrypt the signature and retrieve its content, saving it in a file named decrypted_hash:

LINUX:
```
openssl rsautl -decrypt -inkey key.bin -in sig.bin -out decrypted_hash
```
WINDOWS: 
```
openssl rsa -inform DER -in key.bin -out key.pem 
openssl rsautl -decrypt -inkey key.pem -in sig.bin -out decrypted_hash 
```

By running these commands, we obtained the following message:

```
{"hash": "6ae39cd257a906859040b930551c1cb2"}
```

Using the provided rainbow table (not included in this folder due to its size) to match the hashes, we extracted the C&C password (using the command `cat rainbow.table | grep '6ae39cd257a906859040b930551c1cb2'`), and concluded that the C&C password for vending machine 6 is "`cncywkiyucctbmwruzcrmpiauhaikrptatuwbemwxfbtnivrqklwe`"

## Crack the code

**TARGET 6: Crack the OTP generator**

To bypass the OTP authentication, we utilized a brute-force approach that attempts to match the OTP by submitting numbers until the expected OTP matches one previously provided.
After sending the initial credentials to the Arduino to reach the OTP phase, we sent the 100 number (it's arbitrary, as it could be any valid number) to get a expecting value from Arduino and after that we will extract the value and use that value until the response isn't incorrect and the authentication is completed. The script to achieve this can be checked in the [Crack OTP](crackOTP.py) file. The logic behind this is that, since there's "a bug that leads to the code repeating after some attempts", we extract the code that was expected on the first attempt, and then always provide that one, since we know that, after some time, it will be repeated.

![crackOTP.png](./images/crackOTP.png)

By running this script, we were able to crack the OTP system of the vending machine, and discover the final secret.

![ccLogin.png](./images/ccLogin.png)

## Connect to the C&C
**TARGET 7: Final secret**

With all passwords and the cracked OTP, we could access the C&C, where the final secret was displayed as being "`windowiguanabeachsun`".
