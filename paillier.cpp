#include <iostream>
#include <gmpxx.h>
#include <cmath>
#include <stdexcept>
#include <openssl/rand.h>
#include <vector>
#include "paillier.hpp"

// compiling : g++ -o exemple_gmp exemple_gmp.cpp -lgmp -lgmpxx



// generate a prime number using OpenSSL librairie
mpz_class generate_prime_openssl(int bits){
    
    BIGNUM* big_num = BN_new(); 
    if (!BN_generate_prime_ex(big_num, bits, 1, NULL, NULL, NULL)) {
        BN_free(big_num);
        throw std::runtime_error("Prime generation failed");
    }

    char* hex = BN_bn2hex(big_num); 
    mpz_class result(hex, 16);
    OPENSSL_free(hex);
    BN_free(big_num);

    return result;
}



/**
 * @brief Rgn generator based on RAND_bytes fonction from OpenSSL, using OS entropy to generate random numbers
 * 
 * @param n we generate a random number between [0,n[
 */

mpz_class random_number_generator(const mpz_class& n){


    size_t n_bits = mpz_sizeinbase(n.get_mpz_t(),2);
    size_t n_bytes = (n_bits + 7)/8;

    std::vector<unsigned char> buffer(n_bytes);
    mpz_class r;

    do {
        if (RAND_bytes(buffer.data(), n_bytes) != 1){
            throw(std::runtime_error("RNG failed"));
        }
        mpz_import(r.get_mpz_t(),n_bytes,1,1,0,0,buffer.data());
    } while (r >= n );
    return r;
}







/**
 * @brief Miller rabin primality test (probabilistic test)
 * Error probability ≤ (1/4)^bound
 * OpenSSL recommandations -> 64 rounds 
 * 
 * @param n the number we want to test
 * @param bound the number of tests we want to do
 */
bool miller_rabin_primality_test(const mpz_class& n, int bound){


    // limits cases
    if(n == 2){return true;}
    if(n % 2 == 0){return false;}
    if(n<2) {return false;}

    mpz_class d = n - 1;
    int s = 0;
    while(d%2 == 0){
        d /= 2;
        s++;
    }

    // Here we have 2^s * d = n-1

    mpz_class x;
    mpz_class random_num;

    
    for (int k = 0; k < bound; k++){
        int s_count = 0;
        // test on random basis
        do{
            random_num = random_number_generator(n);
        }while((random_num < 2) || (random_num > n-2));
        mpz_powm(x.get_mpz_t(),random_num.get_mpz_t(),d.get_mpz_t(),n.get_mpz_t());

        if ((x != 1) && (x != n-1)){
            while((x != n-1)&&(s_count < s-1)){
                s_count ++;
                mpz_mul(x.get_mpz_t(),x.get_mpz_t(),x.get_mpz_t());
                mpz_mod(x.get_mpz_t(),x.get_mpz_t(),n.get_mpz_t());
                // If we got 1 without passing by -1 we have find the anomaly
                if(x == 1){
                    return false;
                }
            }
            if((s_count >= s-1)&&(x != n-1)){ // if we didnt found the -1 then after s-1 try n is not prime
                return false; 
            }
        }
    }
    return true;
}





/**
 * @brief Represents the multiplicative group Z*_{n^2}
 * n = p*q where p and q are prime
 * 
 * @param p non trivial prime divisor of n
 * @param q non trivial prime divisor of n
 * 
 */
Group::Group(const mpz_class& p1,const mpz_class& q1){
    if(!miller_rabin_primality_test(p1,64)){
        throw std::invalid_argument("p is not a prime number");
        }
    if(!miller_rabin_primality_test(q1,64)){
        throw std::invalid_argument("q is not a prime number");
    }
    p = p1;
    q = q1;
    n = p*q;
    n_square = n*n;
}

const mpz_class& Group::get_n() const {return n;}
const mpz_class& Group::get_n_square() const {return n_square;}
const mpz_class& Group::get_p() const {return p;}
const mpz_class& Group::get_q() const {return q;}






/**
 * @brief Represent an element of Z*_{n²}, i.e., invertible modulo n²
 * Ensures gcd(value, n²) = 1
 * 
 * @param v is the value we want to test
 * @param n
 * @param n_square group Z*_{n^2}
 */

ElementZnSquareStar::ElementZnSquareStar(const mpz_class& v,const mpz_class& n1) : value(v), n(n1), n_square(n1*n1) {
    mpz_mod(value.get_mpz_t(),v.get_mpz_t(),n_square.get_mpz_t());

    mpz_class gcd;
    mpz_gcd(gcd.get_mpz_t(),value.get_mpz_t(),n_square.get_mpz_t());

    if(gcd != 1){
        throw std::invalid_argument("The value is not inversible in G");
    }
}

const mpz_class& ElementZnSquareStar::getGroupValue() const {return n;}
const mpz_class& ElementZnSquareStar::getValue() const {return value;}

ElementZnSquareStar ElementZnSquareStar::operator*(const ElementZnSquareStar& e) const {
    if(n != e.getGroupValue()){
        throw std::invalid_argument("Thoses elements are from different groups");
    }

    mpz_class result;
    mpz_mul(result.get_mpz_t(),value.get_mpz_t(),e.value.get_mpz_t());
    
    mpz_mod(result.get_mpz_t(),result.get_mpz_t(),n_square.get_mpz_t());

    return ElementZnSquareStar(result,n);
}

ElementZnSquareStar ElementZnSquareStar::pow(const mpz_class& exponent) const {
    mpz_class result;
    mpz_powm(result.get_mpz_t(),value.get_mpz_t(),exponent.get_mpz_t(), n_square.get_mpz_t());

    return ElementZnSquareStar(result, n);
}







Encryption::Encryption(const PublicKey& pk1) : pk(pk1), n_square(pk1.n*pk1.n) {

    if (mpz_sizeinbase(pk.n.get_mpz_t(),2) < 1024){
        throw std::invalid_argument("The key is too small < 1024 bits");
    }

}


/**
 * @brief Encrypt a plaintext using Paillier cryptosystem
 * We compute c = g^m * r^n mod n²
 * 
 * @param plaintext value in Z_n
 * @return ciphertext in Z*_{n^2}
 * 
 * 
 * Optimisation :
 * - we choose : g = (n+1)
 * - Ensuring g^m mod n^2 = (1 + n)^m ≡ 1 + m*n mod n^2
 * - This avoids modular exponentiation during encryption.
 * 
 * Security warning :
 * Reusing r for two encryptions leaks information:
 * c1 / c2 = g^(m1 - m2)
 */

mpz_class Encryption::generate_ciphertext(const mpz_class& plaintext) const{
    if((plaintext < 0) || (plaintext >= pk.n)){
        throw std::invalid_argument("plaintext out of range");
    }
    mpz_class r;
    mpz_class gcd;
    do {
        r = random_number_generator(pk.n);
        mpz_gcd(gcd.get_mpz_t(),r.get_mpz_t(),pk.n.get_mpz_t());
    }while(gcd != 1);
    mpz_class factor1;
    mpz_class factor2;
    // optimisation with g = n+1 
    factor1 = plaintext*pk.n +1; 
    mpz_powm(factor2.get_mpz_t (),r.get_mpz_t(),pk.n.get_mpz_t(),n_square.get_mpz_t());
    mpz_class ciphertext;
    ciphertext = factor1 * factor2;
    mpz_mod(ciphertext.get_mpz_t(),ciphertext.get_mpz_t(),n_square.get_mpz_t());

    return ciphertext;
}





/**
 * @brief Constructor of the Decryption class
 * 
 * @param pk1 the PublicKey
 * @param sk1 the PrivateKey
 */

Decryption::Decryption(const PublicKey& pk1, const PrivateKey& sk1) : pk(pk1), sk(sk1), n_square(pk.n*pk.n){}

// L fonction from paillier's paper
// Defined only for u such that u ≡ 1 mod n

mpz_class Decryption::L(const mpz_class& u) const{
    // Check if u is well defined
    if((u%pk.n != 1) || (u>= n_square)){
        throw std::invalid_argument("the value of u is not valid");
    }
    return (u-1)/pk.n;
}


/**
 * @brief Decrypt a ciphertext using Paillier cryptosystem
 * We compute m = L(c^λ mod n²) * μ mod n
 * 
 * @param p 
 * @param q are prime numbers such that n = p*q
 * @return plaintext in Z_n
 * 
 * 
 * 
 * Optimisation :
 * - we choose : g = (n+1)
 * - Ensuring g^m mod n^2 = (1 + n)^m ≡ 1 + m*n mod n^2
 * - This avoids modular exponentiation during encryption.
 */

mpz_class Decryption::return_plaintext(const mpz_class& ciphertext) const{

    if((ciphertext < 0)||(ciphertext >= n_square)){
        throw std::invalid_argument("ciphertext out of range");
    }

    mpz_class plaintext;
    mpz_class val1;

    mpz_powm(val1.get_mpz_t(), ciphertext.get_mpz_t(), sk.lambda.get_mpz_t(), n_square.get_mpz_t());
    val1 = L(val1);

    plaintext = (val1*sk.mu)%pk.n;

    return plaintext;   
}



/**
 * @brief constructor of the paillier scheme, generate the PublicKey and PrivateKey for Encryption and Decryption
 * 
 * @param G1 : a valide Group with n = p * q > 1024 bits, with p and q large prime numbers
 */


Paillier::Paillier(const Group& G1) : G(G1){

    if (mpz_sizeinbase(G.get_n().get_mpz_t(),2) < 1024){
        throw std::invalid_argument("The key is too small < 1024 bits");
    }

    pk.n = G1.get_n();
    pk.g = G1.get_n() + 1; // Allow optimization during the Encryption


    mpz_class p1 = G.get_p() -1;
    mpz_class q1 = G.get_q() -1;

    mpz_lcm(sk.lambda.get_mpz_t(),p1.get_mpz_t(), q1.get_mpz_t());
    mpz_class gcd_check;
    mpz_gcd(gcd_check.get_mpz_t(), sk.lambda.get_mpz_t(), pk.n.get_mpz_t());
    if(gcd_check != 1){
        throw std::runtime_error("Invalid parameters: gcd(lambda, n) != 1");
    }
    mpz_invert(sk.mu.get_mpz_t(),sk.lambda.get_mpz_t(),pk.n.get_mpz_t());
}


const PrivateKey& Paillier::getPrivateKey() const {return sk;}
const PublicKey& Paillier::getPublicKey() const {return pk;}