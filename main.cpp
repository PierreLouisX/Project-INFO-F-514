#include <iostream>
#include "paillier.hpp"
#include <cmath>



int main(int argc, char* argv[]){

    // Mathematical integrity 
    Group g1(generate_prime_openssl(128),generate_prime_openssl(128));

    ElementZnSquareStar e1(generate_prime_openssl(128),g1);
    std::cout << "Value of e1 : " << e1.getValue() << std::endl;
    ElementZnSquareStar e2(generate_prime_openssl(128), g1);
    std::cout << "Value of e2 : " << e2.getValue() << std::endl;


    ElementZnSquareStar e3 = e1 * e2;
    std::cout << "Value of e1 * e2 = " << e3.getValue() << std::endl;



    // Test of Encryption and decryption
    mpz_class m = 42;

    Encryption enc(e3.getValue());
    Decryption dec(e1.getValue(),e2.getValue());

    mpz_class c = enc.generate_cyphertext(m);
    std::cout << " cyphertext = " << c << std::endl;
    mpz_class m1 = dec.find_plaintext(c);

    std::cout << " orignal message = " << m << " decrypted message = " << m1 << std::endl;



    mpz_class c1 = enc.generate_cyphertext(123);
    // Homomorphic propriety
    std::cout << dec.find_plaintext((c*c1)%(e3.getValue()*e3.getValue())) << std::endl;
    

    return 0;
}