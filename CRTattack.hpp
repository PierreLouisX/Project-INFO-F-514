#include "paillier.hpp"

class FaultyDecryptionCRT {
    private :
        PublicKey pk;
        PrivateKey sk;
        mpz_class n_square;
        mpz_class hp;
        mpz_class hq;
        mpz_class q_inv;
        mpz_class Lx(const mpz_class& u,const mpz_class& x) const;

    public :
        FaultyDecryptionCRT(const PublicKey& pk1, const PrivateKey& sk1);
        mpz_class return_faulty_plaintext(const mpz_class& ciphertext) const;

};


PrivateKey retrieve_key(const PublicKey& pk, const mpz_class& faulty_plaintext,const mpz_class& plaintext);
