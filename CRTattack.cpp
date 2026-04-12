#include "CRTattack.hpp"



/**
 * @brief Constructor of the Decryption class
 * 
 * @param pk1 the PublicKey
 * @param sk1 the PrivateKey with p and q
 */


FaultyDecryptionCRT::FaultyDecryptionCRT(const PublicKey& pk1, const PrivateKey& sk1) : pk(pk1), sk(sk1), n_square(pk.n*pk.n){
    mpz_class p1 = sk.p -1;
    mpz_class q1 = sk.q -1;
    mpz_class p_square = sk.p * sk.p;
    mpz_class q_square = sk.q * sk.q;
    mpz_powm(hp.get_mpz_t(), pk.g.get_mpz_t(), p1.get_mpz_t(), p_square.get_mpz_t());
    mpz_powm(hq.get_mpz_t(), pk.g.get_mpz_t(), q1.get_mpz_t(), q_square.get_mpz_t());
    hp = Lx(hp,sk.p)%sk.p;
    hq = Lx(hq,sk.q)%sk.q;

    if (hp < 0) hp += sk.p;
    if (hq < 0) hq += sk.q;

    mpz_invert(hp.get_mpz_t(), hp.get_mpz_t(), sk.p.get_mpz_t());
    mpz_invert(hq.get_mpz_t(), hq.get_mpz_t(), sk.q.get_mpz_t());


    mpz_invert(q_inv.get_mpz_t(), sk.q.get_mpz_t(), sk.p.get_mpz_t());
}

// Defined only for u such that u ≡ 1 mod x with x = p or q

mpz_class FaultyDecryptionCRT::Lx(const mpz_class& u,const mpz_class& x) const{
    // Check if u is well defined
    if(u%x != 1){
        throw std::invalid_argument("the value of u is not valid");
    }
    return (u-1)/x;
}


/**
 * @brief The same fonction as the return_plaintext fonction from DecryptionCRT class but this time we make a misscomputation on mp.
 * leading to a wrong solution using the CRT
 * @param ciphertext a ciphertext whose plaintext we know
 */


mpz_class FaultyDecryptionCRT::return_faulty_plaintext(const mpz_class& ciphertext) const{
    mpz_class mp;
    mpz_class mq;
    mpz_class p1 = sk.p-1;
    mpz_class p_square = sk.p*sk.p;
    mpz_class q1 = sk.q-1;
    mpz_class q_square = sk.q*sk.q;
    mpz_powm(mp.get_mpz_t(),ciphertext.get_mpz_t(),p1.get_mpz_t(),p_square.get_mpz_t());
    mpz_powm(mq.get_mpz_t(),ciphertext.get_mpz_t(),q1.get_mpz_t(),q_square.get_mpz_t());
    mp = Lx(mp,sk.p);
    mq = Lx(mq,sk.q);


    mp = (mp*hp)%sk.p + 1;
    mq = (mq*hq)%sk.q;

    // CRT 

    mpz_class t = ((mp - mq) * q_inv) % sk.p;

    mpz_class message = mq + sk.q * t;
    message %= pk.n;
    if(message < 0) {
        message += pk.n;
    }

    return message;
}





PrivateKey retrieve_key(const PublicKey& pk, const mpz_class& faulty_plaintext,const mpz_class& plaintext){
    mpz_class diff = faulty_plaintext - plaintext;
    mpz_class q;
    mpz_gcd(q.get_mpz_t(), diff.get_mpz_t(), pk.n.get_mpz_t());

    mpz_class p = pk.n/q;

    PrivateKey sk;
    sk.p = p;
    sk.q = q;

    return sk;
}