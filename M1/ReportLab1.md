# PART 1: Initial targets

## Development password

**TARGET 1: Developer password**

To determine the developer password, we began by identifying its length. We achieved this by sending passwords of varying lengths to the Nano device and measuring the response time for each attempt. This approach allowed us to determine that the password has a length of 13 characters. The script to achieve this can be checked in the [Find Length](findLength.py) file.

![alt text](./images/lengthDiscover.png)

After obtaining the password length, we conducted a timing attack. We initialized the password with 13 "a" characters and iterated through each letter position, testing all possibilities from 'a' to 'z' for the one that resulted in the longest response time. We then saved this letter and repeated the process for the next position. By identifying the letter that caused the longest response at each position, we obtained the correct password.
The script to achieve this can be checked in the [Timing Attack](timingAttack.py) file.

![alt text](./images/timingAttack.png)

DAN's Password for each Nano:
- 16: dandjggpsucpg
- 29: danfffxcqpfxt
- Y: 

## Firmware

**TARGET 2: The dumped firmware in a binary file**

The dumped firmwares can be seen in the folder [Firmwares](firmwares)

## Confidential Information

**TARGET 3: Confidential strings**

In the dumped firmware, we located two strings that could be important.

First string : "MIIEpAIBAAKCAQEAt6+wHPNmpQdJzN5eeNvFITwwf8D81MN8rPp8dfP6s9HTVZCvgmRwwvw7wwgyWyDrAfgGU/vfzFMxXto6fANlEPORinlkgExQjV+XNg+SHnNCd72FtS09UAMHulFW9vpRLVTBFAyP7tpjbz9cV/0Tak/pI9lM58aHeJrsH9IFubXoBJ+odNElkieWVGZdB0P09ArXe2wTO4rF/rxklr8jv4TQmVAh1TyiqaNGZ2ftLSre7HK1F9KVFxYeR7vCvb/9uk4IkATpC8cFQYkesyYeRCozhO6J16nPpn/Q8GijUF1jH8Ipz9n5oJ/CvHkFKVLS+8Z8TjDH6GQqx6ufpcUInwIDAQABAoIBAATGw0LFdjEADa8PmzpI+151X7d6umMCoFPT1veu5qEqvsmV+me0GpXfaY2/6/tK/FbFRHjbma1eU8V+fDssUBekQG/ENKpSEbLTaQMFXaHVZ8WQU+aVrLykujHh7+vP2jDeaCo6zLqudXEiSdGZ6Zl/8XU2ryrEZ/0UCOQnmcbYmjs6vj6Tkq6xiAAgM9Seen0stm/KomsiHqPdQ6oxUQua1Hq23OKf2AyfgwU1fEVExVCLE+BqERxYT9vv/TU+5oIMdMcPWd2gd+QMhv2ySdlg2hYXhsBpTh42eQBOLZ4NY9yl6u+dyIyrSYQCLkrP7PFNf7q1Lf6kYzuUMjrDdjkCgYEA88BwXjzRtgawh5MZU8EcBKmLpkSCZxutiGTTKmLMLI9kln/rF86OnMxgV+7bilkHpb/vdw4IyXthYYSfxWUynkGqHfRsvM42fIrFV/TN1Wmd1t/oB0IHbTzh9YOUoh7W9sQ8hKROzfAGiiTdvzy+I3DNeyPmAFQYoF81tyQ1OXkCgYEAwOqVEWM2pxx4bjirmzbv9ycwnEVMVduiMCivPPA6SMtY0n2j5Cws4fd3Nir1d9JA7eqh380obiJwockECGB4+uGsriq1s8Rv4jFBp51HjaEiT9WUZDMIB2bMhLTU6ua24dLnrRoCkhjTYOgrihM0aA3MTyxoqwOgNV0N9a5y5NcCgYEAxjZt6eQRMLE96fFvfhEhpJTur7U0SX5TXf+HTAdtOqscQ9ofpYtdoxn7GmZs9pKxSlLK+whZkuYW6UL83XsOb2y8VoGFzv7thdce5Qh4PRwWsz3+o7BI88a3hHuMaU0kxyQKhl5KiuKtnrad774IbC91mLY3eXrpT7g8qQHzmhkCgYEAkWpBozGd6KlVPgAJmp32k94+jgzOVYmQ36xLKywJQwXEliWOfFewHURj37jR/tfFiZDrI7+JUjszmz/igk3142Zou4AGJtNTYrSuQKIVZXSoYHUlvcGZs7qRPxbvx4DRKbfIWnrYpTeBXfKjnxiK0ERWVPesjfvVr2PNOfudL1ECgYA7ZoAD+QECO8Wl/WrGl68tjVpcaQYJM3nRubxIvzyMtMDqWbIi0Rsgp3qApTxjacisI23JN+bAtsOua2UFRQ4Tk0aL3Dq2+1PoBZRxftdZuTkKmbtGBbnPsoMJi26MJg9tdc5ZaxR+Q4jPKkQTAorNoLWwcz9MEnmBUz2EVhe8DA=="

Second string : rPNQEzD6kXTQCyqoofQsdj4aCcVbe9T8gzo5WRdoCeDV7f+tCZDoAayci4bi8hGJ8Zbv6EOIeKtL8Se3bvA5Q1CS/YxHZHAYLNiu5AiVeoguHURZoORlxDxhdcD1hSL0QpQwnzvaSqajOztOEUnvt8QmcEReJOjTXGkJEeDray670Y6Yb9jm6CpOXE5xsEtL+s8kzpGBlKLBzPXheUpKGB9N4hWAWjLrc67Mw4zUscpZn58abTiGcZZhImKd7tge0OknalQZpP/vQpCJ3C0tWC+maqeJcctuugqyhIDx5I4bxRTHFuxHQE7MmZlfGUgBKRUBbCTtPBi1RItV3HJLPg==

# PART 2: Final Boss

## Identify Cryptographic Assets

**TARGET 4: Identify the cryptographic data**

After analyzing the previous data, we could conclude that the first string is a private key and the second string is a signature, and with both, we can retrieve

## Find the pot of gold

**TARGET 5: c&c password**

With the private key and signature obtained in the previous step, we proceeded by decoding them from Base64 format in order to reveal the hash.

For each operating system, we have used the following commands:

LINUX:
 - cat key | base64 -d > key.bin
 - cat sig | base64 -d > sig.bin

WINDOWS : 
 - certutil -decode key key.bin  
 - certutil -decode sig sig.bin  

Once we had the decoded files, we used the following commands to decrypt the signature and retrieve the hash, saving it in a file named decrypted_hash:

LINUX:
 - openssl rsautl -decrypt -inkey key.bin -in sig.bin -out decrypted_hash

WINDOWS : 
 - openssl rsa -inform DER -in key.bin -out key.pem 
 - openssl rsautl -decrypt -inkey key.pem -in sig.bin -out decrypted_hash 


Obtained hashes:

16 : {"hash": "6b02ef89ca11e91dace39a97bfde1f77"}
29 : {"hash": "c2af16f5bd21ac77ec01c7e81a9be0eb"}

Using the provided rainbow table to match the hashes, we extracted the C&C passwords (using the command ***cat rainbow.table | grep 'HASH'***) as follows:

C&C password : 
- 16: cncyrkfptyydqqzykjqkpzhexhsrrcjjfztkvponwrblpfgwxcsdc
- 29: cncvdmwhcuabfafahvqfntetnyavetaqpyancathfmiwihbefngkx
- Y: 


## Crack the code

**TARGET 6: Crack the OTP generator**

To bypass the OTP authentication, we utilized a brute-force approach that attempts to match the OTP by submitting numbers until the expected OTP matches one previously provided.
After sending the initial credentials to the Arduino to reach the OTP phase, we sent the 100 number to get a expecting value from Arduino and after that we will extract the value and use that value until the response isn't incorrect and the authentication is completed. The script to achieve this can be checked in the [Crack OTP](crackOTP.py) file.

![alt text](./images/crackOTP.png)

## Connect to the C&C
**TARGET 7: Final secret**

With all passwords and the cracked OTP, we could access the C&C, where the following secrets were displayed:

- 16: monkeytigeroaktape
- 29: niceeaglewonderfulboat