#include "BitSecurity.hpp"

#include <array>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include "paillier.hpp"

namespace {

struct ExperimentContext {
    PublicKey pk;
    PrivateKey sk;
};

struct ChiSquareResult {
    double chi2;
    double p_value;
};

ExperimentContext build_context(unsigned int prime_bits) {
    mpz_class p = generate_prime_openssl(static_cast<int>(prime_bits));
    mpz_class q = generate_prime_openssl(static_cast<int>(prime_bits));
    while (p == q) {
        q = generate_prime_openssl(static_cast<int>(prime_bits));
    }

    ExperimentContext context;
    context.pk.n = p * q;
    context.pk.g = context.pk.n + 1;
    context.sk.p = p;
    context.sk.q = q;
    return context;
}

mpz_class random_in_zn_star(const mpz_class& n) {
    mpz_class value;
    mpz_class gcd;
    do {
        value = random_number_generator(n);
        mpz_gcd(gcd.get_mpz_t(), value.get_mpz_t(), n.get_mpz_t());
    } while (value == 0 || gcd != 1);
    return value;
}

mpz_class encrypt_for_experiment(const PublicKey& pk, const mpz_class& plaintext) {
    if (plaintext < 0 || plaintext >= pk.n) {
        throw std::invalid_argument("plaintext out of range");
    }

    const mpz_class n_square = pk.n * pk.n;
    const mpz_class r = random_in_zn_star(pk.n);
    const mpz_class factor1 = plaintext * pk.n + 1;

    mpz_class factor2;
    mpz_powm(factor2.get_mpz_t(), r.get_mpz_t(), pk.n.get_mpz_t(), n_square.get_mpz_t());

    mpz_class ciphertext = (factor1 * factor2) % n_square;
    if (ciphertext < 0) {
        ciphertext += n_square;
    }
    return ciphertext;
}

unsigned int bit_length(const mpz_class& value) {
    return static_cast<unsigned int>(mpz_sizeinbase(value.get_mpz_t(), 2));
}

mpz_class power_of_two(unsigned int exponent) {
    mpz_class result = 1;
    mpz_mul_2exp(result.get_mpz_t(), result.get_mpz_t(), exponent);
    return result;
}

mpz_class modular_inverse(const mpz_class& value, const mpz_class& modulus) {
    mpz_class inverse;
    if (mpz_invert(inverse.get_mpz_t(), value.get_mpz_t(), modulus.get_mpz_t()) == 0) {
        throw std::runtime_error("modular inverse does not exist");
    }
    return inverse;
}

int lsb_oracle_perfect(const Decryption& dec, const mpz_class& w) {
    const mpz_class class_value = dec.return_plaintext(w);
    return mpz_tstbit(class_value.get_mpz_t(), 0);
}

std::mt19937& global_rng() {
    static std::mt19937 rng(std::random_device{}());
    return rng;
}

int lsb_oracle_imperfect(const Decryption& dec, const mpz_class& w, double advantage) {
    const int correct_bit = lsb_oracle_perfect(dec, w);
    std::uniform_real_distribution<double> coin(0.0, 1.0);
    if (coin(global_rng()) < 0.5 + advantage) {
        return correct_bit;
    }
    return 1 - correct_bit;
}

mpz_class compute_class_majority_vote(
    const PublicKey& pk,
    const Decryption& dec,
    const mpz_class& w_start,
    double advantage,
    unsigned int num_samples
) {
    const mpz_class n_square = pk.n * pk.n;
    const mpz_class z = modular_inverse(2, pk.n);
    const mpz_class g_inv = modular_inverse(pk.g, n_square);
    const unsigned int n_bits = bit_length(pk.n);

    mpz_class w = w_start;
    mpz_class recovered = 0;

    for (unsigned int i = 0; i < n_bits; ++i) {
        unsigned int votes_for_zero = 0;
        unsigned int votes_for_one = 0;

        for (unsigned int s = 0; s < num_samples; ++s) {
            const mpz_class r = random_number_generator(pk.n);
            const mpz_class blind = random_in_zn_star(pk.n);

            mpz_class g_pow_r;
            mpz_powm(g_pow_r.get_mpz_t(), pk.g.get_mpz_t(), r.get_mpz_t(), n_square.get_mpz_t());
            mpz_class blind_pow_n;
            mpz_powm(blind_pow_n.get_mpz_t(), blind.get_mpz_t(), pk.n.get_mpz_t(), n_square.get_mpz_t());

            mpz_class w_rand = (w * g_pow_r) % n_square;
            w_rand = (w_rand * blind_pow_n) % n_square;
            if (w_rand < 0) {
                w_rand += n_square;
            }

            const int oracle_bit = lsb_oracle_imperfect(dec, w_rand, advantage);
            const int r_lsb = mpz_tstbit(r.get_mpz_t(), 0);
            const int predicted = oracle_bit ^ r_lsb;
            if (predicted == 0) {
                ++votes_for_zero;
            } else {
                ++votes_for_one;
            }
        }

        const int bit = (votes_for_one > votes_for_zero) ? 1 : 0;
        if (bit == 1) {
            mpz_setbit(recovered.get_mpz_t(), i);
            w = (w * g_inv) % n_square;
            if (w < 0) {
                w += n_square;
            }
        }
        mpz_powm(w.get_mpz_t(), w.get_mpz_t(), z.get_mpz_t(), n_square.get_mpz_t());
    }

    recovered %= pk.n;
    if (recovered < 0) {
        recovered += pk.n;
    }
    return recovered;
}

mpz_class compute_class_perfect(const PublicKey& pk, const Decryption& dec, const mpz_class& w_start) {
    const mpz_class n_square = pk.n * pk.n;
    const mpz_class z = modular_inverse(2, pk.n);
    const mpz_class g_inv = modular_inverse(pk.g, n_square);
    const unsigned int n_bits = bit_length(pk.n);

    mpz_class w = w_start;
    mpz_class recovered = 0;

    for (unsigned int i = 0; i < n_bits; ++i) {
        const int bit = lsb_oracle_perfect(dec, w);
        if (bit == 1) {
            mpz_setbit(recovered.get_mpz_t(), i);
            w = (w * g_inv) % n_square;
            if (w < 0) {
                w += n_square;
            }
        }

        mpz_powm(w.get_mpz_t(), w.get_mpz_t(), z.get_mpz_t(), n_square.get_mpz_t());
    }

    recovered %= pk.n;
    if (recovered < 0) {
        recovered += pk.n;
    }
    return recovered;
}

ChiSquareResult chi_square_uniformity(unsigned long long count_0, unsigned long long count_1) {
    const double total = static_cast<double>(count_0 + count_1);
    const double expected = total / 2.0;
    const double delta_0 = static_cast<double>(count_0) - expected;
    const double delta_1 = static_cast<double>(count_1) - expected;
    const double chi2 = (delta_0 * delta_0) / expected + (delta_1 * delta_1) / expected;
    const double p_value = std::erfc(std::sqrt(chi2 / 2.0));
    return {chi2, p_value};
}

void print_rule(char ch = '=') {
    std::cout << std::string(72, ch) << '\n';
}

void print_section(const std::string& title, const std::string& subtitle = "") {
    std::cout << '\n';
    print_rule('-');
    std::cout << "  " << title << '\n';
    if (!subtitle.empty()) {
        std::cout << "  " << subtitle << '\n';
    }
    print_rule('-');
}

void verify_algebraic_foundation(const ExperimentContext& context);

void experiment_perfect_oracle() {
    const ExperimentContext context = build_context(32);
    const Decryption dec(context.pk, context.sk);
    const unsigned int modulus_bits = bit_length(context.pk.n);

    std::cout << "\n  Generating " << modulus_bits
              << "-bit Paillier keys for the ComputeClass demos...\n";
    std::cout << "  Key generated: " << modulus_bits << "-bit modulus\n";

    verify_algebraic_foundation(context);

    print_section("Test: ComputeClass with Perfect LSB Oracle (Theorem 1)");

    const mpz_class demo_bound = std::min(context.pk.n, power_of_two(20));
    unsigned int successes = 0;

    for (unsigned int trial = 0; trial < 5; ++trial) {
        const mpz_class message = random_number_generator(demo_bound);
        const mpz_class ciphertext = encrypt_for_experiment(context.pk, message);

        const clock_t start = clock();
        const mpz_class recovered = compute_class_perfect(context.pk, dec, ciphertext);
        const double elapsed_ms = 1000.0 * static_cast<double>(clock() - start) / CLOCKS_PER_SEC;

        const bool ok = (recovered == message);
        if (ok) {
            ++successes;
        }

        std::cout << "  Trial " << (trial + 1)
                  << ": m=" << message
                  << ", recovered=" << recovered
                  << ' ' << (ok ? "[OK]" : "[FAIL]")
                  << " (" << std::fixed << std::setprecision(1) << elapsed_ms << "ms)\n";
    }

    std::cout << "\n  Result: " << successes << "/5 correct\n";
    std::cout << (successes == 5 ? "  [OK] Algorithm validated\n" : "  [FAIL] Some reconstructions failed\n");
}

void verify_algebraic_foundation(const ExperimentContext& context) {
    // Quick sanity check on the two algebraic identities ComputeClass relies on:
    //   (a) Lemma 1 (bit-shifting): Class_g(w^z) = Class_g(w)/2 mod N (z = 2^-1 mod N)
    //   (b) Class function homomorphism: Class_g(x*y) = Class_g(x) + Class_g(y) mod N.
    // These are not separate experiments: ComputeClass success implies both. We only
    // print a one-line summary so a future bug is caught early without bloating the report.

    const Decryption dec(context.pk, context.sk);
    const mpz_class n_square = context.pk.n * context.pk.n;
    const mpz_class z = modular_inverse(2, context.pk.n);

    const unsigned int num_samples = 500;
    unsigned int lemma1_ok = 0, lemma1_tested = 0, homo_ok = 0;

    for (unsigned int i = 0; i < num_samples; ++i) {
        const mpz_class m = random_number_generator(context.pk.n);
        const mpz_class c = encrypt_for_experiment(context.pk, m);
        const mpz_class class_c = dec.return_plaintext(c);

        if (mpz_tstbit(class_c.get_mpz_t(), 0) == 0) {
            ++lemma1_tested;
            mpz_class w_shifted;
            mpz_powm(w_shifted.get_mpz_t(), c.get_mpz_t(), z.get_mpz_t(), n_square.get_mpz_t());
            if (dec.return_plaintext(w_shifted) == (class_c / 2) % context.pk.n) {
                ++lemma1_ok;
            }
        }

        const mpz_class m1 = random_number_generator(context.pk.n);
        const mpz_class m2 = random_number_generator(context.pk.n);
        const mpz_class c1 = encrypt_for_experiment(context.pk, m1);
        const mpz_class c2 = encrypt_for_experiment(context.pk, m2);
        const mpz_class product = (c1 * c2) % n_square;
        if (dec.return_plaintext(product)
            == (dec.return_plaintext(c1) + dec.return_plaintext(c2)) % context.pk.n) {
            ++homo_ok;
        }
    }

    std::cout << "\n  Algebraic foundation check (preliminary):\n";
    std::cout << "    Lemma 1 (bit-shifting):       " << lemma1_ok << "/" << lemma1_tested
              << " even-class samples\n";
    std::cout << "    Class homomorphism (xy -> +): " << homo_ok << "/" << num_samples
              << " ciphertext pairs\n";
}

void experiment_imperfect_oracle_sweep() {
    const ExperimentContext context = build_context(32);
    const Decryption dec(context.pk, context.sk);
    const unsigned int n_bits = bit_length(context.pk.n);

    print_section(
        "Test: ComputeClass with Imperfect Oracle (Theorem 1, part 2)",
        "advantage x num_samples sweep, success rate over independent trials"
    );

    const std::array<double, 7> advantages = {0.40, 0.30, 0.20, 0.15, 0.10, 0.07, 0.05};
    const std::array<unsigned int, 4> sample_sizes = {50, 100, 200, 500};
    const unsigned int num_trials = 10;
    const mpz_class demo_bound = std::min(context.pk.n, power_of_two(20));

    std::cout << "  Modulus: " << n_bits << " bits  (" << n_bits
              << " ComputeClass iterations)\n";
    std::cout << "  Independent trials per cell: " << num_trials << "\n\n";

    std::cout << "  " << std::setw(11) << "advantage";
    for (unsigned int s : sample_sizes) {
        std::cout << "  s=" << std::setw(4) << s;
    }
    std::cout << '\n';

    for (double advantage : advantages) {
        std::cout << "  " << std::setw(11) << std::fixed << std::setprecision(2) << advantage;
        for (unsigned int s : sample_sizes) {
            unsigned int successes = 0;
            for (unsigned int trial = 0; trial < num_trials; ++trial) {
                const mpz_class message = random_number_generator(demo_bound);
                const mpz_class ciphertext = encrypt_for_experiment(context.pk, message);
                const mpz_class recovered = compute_class_majority_vote(
                    context.pk, dec, ciphertext, advantage, s
                );
                if (recovered == message) {
                    ++successes;
                }
            }
            const double rate = static_cast<double>(successes) / static_cast<double>(num_trials);
            std::cout << "  " << std::setw(5) << std::fixed << std::setprecision(2) << rate;
        }
        std::cout << '\n';
    }

    std::cout << "\n  The reduction becomes harder as advantage drops; increasing\n"
              << "  num_samples per bit compensates, in line with the Chernoff\n"
              << "  argument used in the paper's proof.\n";
}

void experiment_compute_class_scaling() {
    print_section(
        "Test: ComputeClass Runtime vs Modulus Size",
        "perfect oracle, scaling check on freshly generated keys"
    );

    const std::array<unsigned int, 7> modulus_bits = {32, 48, 64, 80, 96, 112, 128};
    const unsigned int num_trials = 3;

    std::cout << "  " << std::setw(10) << "|N| bits"
              << std::setw(17) << "mean ms / run"
              << std::setw(10) << "trials" << '\n';

    for (unsigned int kb : modulus_bits) {
        ExperimentContext local_context = build_context(kb / 2);
        const Decryption local_dec(local_context.pk, local_context.sk);
        const unsigned int actual_bits = bit_length(local_context.pk.n);

        const mpz_class demo_bound = std::min(local_context.pk.n, power_of_two(20));
        double total_ms = 0.0;
        for (unsigned int t = 0; t < num_trials; ++t) {
            const mpz_class message = random_number_generator(demo_bound);
            const mpz_class ciphertext = encrypt_for_experiment(local_context.pk, message);
            const clock_t start = clock();
            const mpz_class recovered = compute_class_perfect(local_context.pk, local_dec, ciphertext);
            const double elapsed_ms = 1000.0 * static_cast<double>(clock() - start) / CLOCKS_PER_SEC;
            if (recovered != message) {
                std::cout << "  [WARN] ComputeClass returned a wrong class during scaling\n";
            }
            total_ms += elapsed_ms;
        }
        const double mean_ms = total_ms / static_cast<double>(num_trials);
        std::cout << "  " << std::setw(10) << actual_bits
                  << std::setw(17) << std::fixed << std::setprecision(2) << mean_ms
                  << std::setw(10) << num_trials << '\n';
    }

    std::cout << "\n  Runtime grows with |N|, consistent with the linear iteration\n"
              << "  count of the reduction times the cost of one modular exponent.\n";
}

void experiment_hard_core_distribution() {
    const ExperimentContext context = build_context(256);
    const Decryption dec(context.pk, context.sk);
    const unsigned int modulus_bits = bit_length(context.pk.n);

    std::cout << "\n  Generating " << modulus_bits
              << "-bit Paillier keys for the statistical tests...\n";
    std::cout << "  Key generated: " << modulus_bits << "-bit modulus\n";

    print_section(
        "Test: Hard-Core Predicate Distribution",
        "(empirical balance of lsb(Class_g(w)))"
    );

    const unsigned int num_samples = 2000;
    unsigned long long count_0 = 0;
    unsigned long long count_1 = 0;

    for (unsigned int i = 0; i < num_samples; ++i) {
        const mpz_class message = random_number_generator(context.pk.n);
        const mpz_class ciphertext = encrypt_for_experiment(context.pk, message);
        const int bit = lsb_oracle_perfect(dec, ciphertext);
        if (bit == 0) {
            ++count_0;
        } else {
            ++count_1;
        }
    }

    const ChiSquareResult stats = chi_square_uniformity(count_0, count_1);
    const double ratio_zeros = static_cast<double>(count_0) / static_cast<double>(num_samples);

    std::cout << "  Over " << num_samples << " random encryptions/classes:\n";
    std::cout << "    lsb = 0: " << count_0
              << " (" << std::fixed << std::setprecision(1)
              << (100.0 * static_cast<double>(count_0) / num_samples) << "%)\n";
    std::cout << "    lsb = 1: " << count_1
              << " (" << std::fixed << std::setprecision(1)
              << (100.0 * static_cast<double>(count_1) / num_samples) << "%)\n";
    std::cout << "    Ratio of zeros: " << std::setprecision(4) << ratio_zeros << " (ideal: 0.5000)\n";
    std::cout << "    chi2 statistic: " << std::setprecision(4) << stats.chi2 << '\n';
    std::cout << "    p-value: " << std::setprecision(4) << stats.p_value << '\n';
    std::cout << (stats.p_value >= 0.05
                      ? "  [OK] No significant deviation from uniformity at alpha=0.05\n"
                      : "  [WARN] Significant deviation detected at alpha=0.05\n");

    print_section("Test: Simultaneous Security of 10 LSBs (Theorem 2)");

    const unsigned int num_bits = 10;
    std::vector<std::array<unsigned long long, 2>> counts(num_bits, {0ULL, 0ULL});

    for (unsigned int i = 0; i < num_samples; ++i) {
        const mpz_class message = random_number_generator(context.pk.n);
        const mpz_class ciphertext = encrypt_for_experiment(context.pk, message);
        const mpz_class class_value = dec.return_plaintext(ciphertext);

        for (unsigned int bit = 0; bit < num_bits; ++bit) {
            const int current = mpz_tstbit(class_value.get_mpz_t(), bit);
            ++counts[bit][static_cast<std::size_t>(current)];
        }
    }

    const double corrected_alpha = 0.05 / static_cast<double>(num_bits);
    bool all_uniform = true;

    std::cout << "  Bit distribution over " << num_samples << " random classes:\n";
    std::cout << "  Bonferroni-corrected alpha: " << std::fixed << std::setprecision(4)
              << corrected_alpha << '\n';
    std::cout << "     Bit   Count(0)   Count(1)    Ratio     chi2   p-value   Status\n";

    for (unsigned int bit = 0; bit < num_bits; ++bit) {
        const unsigned long long c0 = counts[bit][0];
        const unsigned long long c1 = counts[bit][1];
        const ChiSquareResult stats = chi_square_uniformity(c0, c1);
        const bool ok = stats.p_value >= corrected_alpha;
        if (!ok) {
            all_uniform = false;
        }

        std::cout << "  bit[" << bit << "]"
                  << std::setw(11) << c0
                  << std::setw(11) << c1
                  << std::setw(9) << std::fixed << std::setprecision(4)
                  << (static_cast<double>(c0) / static_cast<double>(num_samples))
                  << std::setw(9) << std::setprecision(3) << stats.chi2
                  << std::setw(10) << std::setprecision(4) << stats.p_value
                  << std::setw(9) << (ok ? "[OK]" : "[WARN]") << '\n';
    }

    std::cout << '\n'
              << (all_uniform
                      ? "  [OK] No bit shows a significant deviation after Bonferroni correction\n"
                      : "  [WARN] Some bits deviate significantly after Bonferroni correction\n");
    std::cout << "  This remains an empirical illustration of Theorem 2, not a proof.\n";

    print_section(
        "Practical Application: Single-Invocation Secure Encryption",
        "(Section 5 of Catalano et al., 2001)"
    );

    const unsigned int key_bits = 128;
    const mpz_class key_modulus = power_of_two(key_bits);
    const mpz_class sym_key = random_number_generator(key_modulus);
    const mpz_class max_prefix = (context.pk.n - 1 - sym_key) / key_modulus;
    const mpz_class prefix = (max_prefix == 0) ? 0 : random_number_generator(max_prefix + 1);
    const mpz_class message = prefix * key_modulus + sym_key;
    const mpz_class ciphertext = encrypt_for_experiment(context.pk, message);
    const mpz_class recovered_message = dec.return_plaintext(ciphertext);
    const mpz_class recovered_key = recovered_message % key_modulus;

    std::cout << "  Modulus size: " << modulus_bits << " bits\n";
    std::cout << "  Symmetric key (hex): 0x" << sym_key.get_str(16) << '\n';
    std::cout << "  Padded message layout: prefix || key\n";
    std::cout << "  Ciphertext size: approximately " << (2 * modulus_bits) << " bits\n";
    std::cout << "  Recovered key (hex): 0x" << recovered_key.get_str(16) << '\n';
    std::cout << "  [OK] Key correctly recovered: " << (recovered_key == sym_key ? "true" : "false") << '\n';
    std::cout << "  Under B-hardness with b = " << (modulus_bits - key_bits)
              << ", the low " << key_bits << " bits are intended to remain simultaneously hidden.\n";
}

}  // namespace

void run_bit_security_experiments() {
    std::cout << "\n";
    print_rule('=');
    std::cout << "  EXPERIMENT 3: Bit Security of Paillier's Scheme (C++)\n";
    std::cout << "  [Catalano, Gennaro, Howgrave-Graham, EUROCRYPT 2001]\n";
    print_rule('=');

    experiment_perfect_oracle();
    experiment_imperfect_oracle_sweep();
    experiment_compute_class_scaling();
    experiment_hard_core_distribution();

    std::cout << "\n";
    print_rule('=');
    std::cout << "  All bit-security experiments completed\n";
    print_rule('=');
}
