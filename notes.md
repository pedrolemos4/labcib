sacar os firmwares com o script dump.py
fazer $ strings firmware_dumpX para sacar as strings desse firmware
encontrar numa troca de mensagens uma chave privada e uma signature
com isto podemos sacar a pubkey se quisermos, nao sei se sera util: openssl rsa -in key -pubout > pubkey


para descobrir o hash: ambas a assinatura e a chave estao em base64, portanto para dar decode
cat key | base64 -d > key.bin
cat sig | base64 -d > sig.bin

WINDOWS : 
certutil -decode key key.bin  
certutil -decode sig sig.bin  

com estes dois, e POR SE TRATAR DE RSA (nao sei como explicamos a forma de descobrir mas enfim), podemos fazer:  

openssl rsautl -decrypt -inkey key.bin -in sig.bin -out decrypted_hash

WINDOWS : 
openssl rsa -inform DER -in key.bin -out key.pem 
openssl rsautl -decrypt -inkey key.pem -in sig.bin -out decrypted_hash 

isto vai dar o hash codificado no ficheiro decrypted_hash:

29 : {"hash": "c2af16f5bd21ac77ec01c7e81a9be0eb"}
16 : {"hash": "6b02ef89ca11e91dace39a97bfde1f77"}

com a rainbow table:

cat rainbow.table | grep c2af16f5bd21ac77ec01c7e81a9be0eb
cncvdmwhcuabfafahvqfntetnyavetaqpyancathfmiwihbefngkx c2af16f5bd21ac77ec01c7e81a9be0eb
portanto a password do c&c é: cncvdmwhcuabfafahvqfntetnyavetaqpyancathfmiwihbefngkx

PASS DO ALAN:
- 16: alangmrseagepzqajipejuqsgksoufwldsqclpsoakfqhppuwqhtna
- 29: alanqyxcyqnqeerixzcgocmrcsyhimdskcuscddfgkdityzzzbkuda
- Y: 

PASS DO CC : 
- 16: cncyrkfptyydqqzykjqkpzhexhsrrcjjfztkvponwrblpfgwxcsdc
- 29: cncvdmwhcuabfafahvqfntetnyavetaqpyancathfmiwihbefngkx
- Y: 

PASS DO DAN:
- 16: dandjggpsucpg
- 29: danfffxcqpfxt
- Y: 
