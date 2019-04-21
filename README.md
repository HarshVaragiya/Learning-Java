# Learning-Java
Collection of Cool Codes while learning Java
### Note:
The Deterministic RSA Keygen has a limited entropy of 64 bits (8 bytes), limited due to setSeed() function in SecureRandom.
Hence there are only a total of 2^64  = 18446744073709551616 different RSA Keys possible.
Need to mitigate this is necessary, as this is not very hard to bruteforce for Nation States.
For common password based Brute force attacks, PBKDF2 has been used to slow the attacker down.
If PrivateKey cannot be stored Securely on the host device then either it needs to be deterministic or stored in encrypted form(commonly used. will be added later.)
