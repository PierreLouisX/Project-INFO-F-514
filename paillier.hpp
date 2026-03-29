#ifndef PAILLIER_HPP
    #define PAILLIER_HPP
    #include <gmpxx.h>
    #include <vector>
    #include <string>

    mpz_class generate_prime_openssl(int bits);

    mpz_class random_number_generator(const mpz_class& n);

    bool miller_rabin_primality_test(const mpz_class& n, int bound);


    struct PublicKey {
        mpz_class n;
        mpz_class g; // Always set at n+1
    };

    struct PrivateKey {
        mpz_class lambda;
        mpz_class mu;
    };
    

    // Represents Z_n*² (multiplicative group modulo n²)
    // n = p*q where p and q are prime
    class Group {

        private:
            mpz_class p;
            mpz_class q;
            mpz_class n;
            mpz_class n_square;

        public:
            Group(const mpz_class& p1,const mpz_class& q1);
            const mpz_class& get_n() const;
            const mpz_class& get_n_square()const; 
            const mpz_class& get_p() const;
            const mpz_class& get_q() const;
    };





    // Element of Z*_{n²}, i.e., invertible modulo n²
    // Ensures gcd(value, n²) = 1
    class ElementZnSquareStar {

        private:
            mpz_class value;
            const mpz_class n;
            const mpz_class n_square;

        public:
            ElementZnSquareStar(const mpz_class& v,const mpz_class& n1);

            const mpz_class& getGroupValue() const;
            const mpz_class& getValue() const;
            

            ElementZnSquareStar operator*(const ElementZnSquareStar& e) const;

            
            ElementZnSquareStar pow(const mpz_class& exponent) const;
    };



    class Encryption {
        private :
            PublicKey pk;
            mpz_class n_square;

        public :
            Encryption(const PublicKey& pk1);
            mpz_class generate_ciphertext(const mpz_class& plaintext) const;
    };


    class Decryption {
        private :
            PublicKey pk;
            PrivateKey sk;
            mpz_class n_square;

            mpz_class L(const mpz_class& u) const;

        public :
        Decryption(const PublicKey& pk1, const PrivateKey& sk1);
        mpz_class return_plaintext(const mpz_class& ciphertext) const;
    };


    class Paillier {
        private :
            const Group G;
            PublicKey pk;
            PrivateKey sk;

        public:
            Paillier(const Group& G1);
            const PrivateKey& getPrivateKey() const;
            const PublicKey& getPublicKey() const;
    };

#endif