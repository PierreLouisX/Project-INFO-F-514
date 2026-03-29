#include "paillier.hpp"
#include <iostream>
// g++ -o indcca notINDCCA.cpp paillier.cpp -lgmp -lgmpxx -lssl -lcrypto

int main(int argc, char* argv[]){

    Group g1(generate_prime_openssl(1024),generate_prime_openssl(1024));

    Paillier scheme(g1);

    Encryption enc(scheme.getPublicKey());
    Decryption dec(scheme.getPublicKey(),scheme.getPrivateKey());

    
    mpz_class m1 = random_number_generator(scheme.getPublicKey().n);

    // We want to know the plaintext m1 but we only have the cypertext c1
    mpz_class c1 = enc.generate_cyphertext(m1);


    // Wa know m2 and we ask for Enc(m2)
    mpz_class m2 = 42;
    mpz_class c2 = enc.generate_cyphertext(m2);

    // Then we can find Enc(m1+m2) = Enc(m1)*Enc(m2) 
    mpz_class m3 = dec.return_plaintext((c1*c2)%(scheme.getPublicKey().n * scheme.getPublicKey().n));
    // Then we found m1 = m3 - m2
    m3 = m3 - (m2 + scheme.getPublicKey().n) % scheme.getPublicKey().n;


    if(m1 == m3){
        std::cout << "Since paillier is homomorphic, the scheme is not IND-CCA, we found the value m3 = " << m3 << " = m1 = " << m1 << std::endl;
    }

    return 0;
}