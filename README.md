# Project-INFO-F-514

This repository contains three standalone C++ demos around Paillier:

- `main.cpp`: base functionality, CRT decryption and CRT fault attack
- `notINDCCA.cpp`: malleability / non-IND-CCA demonstration
- `bit_security_main.cpp`: Catalano et al. bit-security experiments

Build commands:

```bash
g++ -std=c++17 -O2 -o main.exe main.cpp paillier.cpp CRTattack.cpp -lgmp -lgmpxx -lssl -lcrypto
g++ -std=c++17 -O2 -o indcca.exe notINDCCA.cpp paillier.cpp -lgmp -lgmpxx -lssl -lcrypto
g++ -std=c++17 -O2 -o bit_security.exe bit_security_main.cpp BitSecurity.cpp paillier.cpp -lgmp -lgmpxx -lssl -lcrypto
```
