sacar os firmwares com o script dump.py
fazer $ strings firmware_dumpX para sacar as strings desse firmware
encontrar numa troca de mensagens uma chave privada e uma signature
encapsular a chave com (antes e dps do texto, separado c/ enters)
-----BEGIN RSA PRIVATE KEY-----
-----END RSA PRIVATE KEY-----
com isto podemos sacar a pubkey se quisermos, nao sei se sera util: openssl rsa -in key -pubout > pubkey