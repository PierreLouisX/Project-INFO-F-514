#include <iostream>
#include "paillier.hpp"
#include "CRTattack.hpp"
#include <cmath>



int main(int argc, char* argv[]){

    // Mathematical integrity 
    Group g1(generate_prime_openssl(1024),generate_prime_openssl(1024));

    ElementZnSquareStar e1(generate_prime_openssl(128),g1.get_n());
    std::cout << "Value of e1 : " << e1.getValue() << std::endl;
    ElementZnSquareStar e2(generate_prime_openssl(128), g1.get_n());
    std::cout << "Value of e2 : " << e2.getValue() << std::endl;


    ElementZnSquareStar e3 = e1 * e2;
    std::cout << "Value of e1 * e2 = " << e3.getValue() << std::endl;

    Paillier scheme(g1);



    // Test of Encryption and decryption
    mpz_class m = 42;

    Encryption enc(scheme.getPublicKey());
    Decryption dec(scheme.getPublicKey(),scheme.getPrivateKey());
    DecryptionCRT deccrt(scheme.getPublicKey(), scheme.getPrivateKey());

    mpz_class c = enc.generate_ciphertext(m);
    std::cout << " ciphertext = " << c << std::endl;
    mpz_class m1 = dec.return_plaintext(c);
    mpz_class m2 = deccrt.return_plaintext(c);

    std::cout << " orignal message = " << m << " decrypted message = " << m1 << " decrypted message with CRT = " << m2 << std::endl;





    mpz_class c1 = enc.generate_ciphertext(123);
    // Homomorphic propriety
    mpz_class n_square = scheme.getPublicKey().n * scheme.getPublicKey().n;
    std::cout << " homomorphic sum test = "
              << dec.return_plaintext((c * c1) % n_square)
              << " (expected 165)" << std::endl;



    // CRT Attack
    FaultyDecryptionCRT fdec(scheme.getPublicKey(),scheme.getPrivateKey());
    mpz_class faulty_plaintext = fdec.return_faulty_plaintext(c);
    PrivateKey sk = retrieve_key(scheme.getPublicKey(),faulty_plaintext, m);

    std::cout << " PrivateKey (p) : " << scheme.getPrivateKey().p << " & " << scheme.getPrivateKey().q << " The key we retrieved is : " <<
    sk.p << " & " << sk.q << std::endl;
    

    return 0;
}
