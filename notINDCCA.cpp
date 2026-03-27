#include "paillier.hpp"
#include <iostream>
// g++ -o indcca notINDCCA.cpp paillier.cpp -lgmp -lgmpxx -lssl -lcrypto

int main(int argc, char* argv[]){

    Group g1(generate_prime_openssl(128),generate_prime_openssl(128));

    ElementZnSquareStar e1(generate_prime_openssl(128),g1);
    ElementZnSquareStar e2(generate_prime_openssl(128), g1);

    ElementZnSquareStar e3 = e1 * e2;

    Encryption enc(e3.getValue());
    Decryption dec(e1.getValue(),e2.getValue());

    
    mpz_class m1 = random_number_generator(e3.getValue());

    // We want to know the plaintext m1 but we only have the cypertext c1
    mpz_class c1 = enc.generate_cyphertext(m1);


    // Wa know m2 and we ask for Enc(m2)
    mpz_class m2 = 42;
    mpz_class c2 = enc.generate_cyphertext(m2);

    // Then we can find Enc(m1+m2) = Enc(m1)*Enc(m2) 
    mpz_class m3 = dec.find_plaintext((c1*c2)%(e3.getValue()*e3.getValue()));
    // Then we found m1 = m3 - m2
    m3 = m3 - m2;
    std::cout << m1 << m3 <<std::endl;
    if(m1 == m3){
        std::cout << "Since paillier is homomorphic, the scheme is not IND-CCA, we found the value m3 = " << m3 << " = m1 = " << m1 << std::endl;
    }

    return 0;
}