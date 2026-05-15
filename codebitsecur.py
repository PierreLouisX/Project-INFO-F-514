import math
import random
import secrets
import time

from paillier import PaillierCryptosystem, random_in_Zn_star


def cc_parfait(ps, c):
    # oracle parfait pour le thm 1
    n = ps.pk.n
    n_sq = ps.pk.n_sq
    g = ps.pk.g
    n_bits = ps.pk.bits

   
    z = (n + 1) // 2
    g_inv = pow(g, -1, n_sq)

    bits = []
    for _ in range(n_bits):
        b = ps.decrypt(c) & 1
        bits.append(b)
        if b == 1:
            c = (c * g_inv) % n_sq
        # print("step", _, "bit", b)
        c = pow(c, z, n_sq)

    # res = sum(bits)
    res = 0
    for i in range(len(bits)):
        res = res + bits[i] * 2**i
    res = res % n
    return res


def cc_bruite(ps, c, adv=0.1, ns=100):
    n = ps.pk.n
    n_sq = ps.pk.n_sq
    g = ps.pk.g
    n_bits = ps.pk.bits

    z = (n + 1) // 2
    g_inv = pow(g, -1, n_sq)

    bits = []
    for _ in range(n_bits):
        cpt0 = 0
        cpt1 = 0
        for _ in range(ns):
            r = secrets.randbelow(n)
            s = random_in_Zn_star(n)
            w_rand = (c * pow(g, r, n_sq) * pow(s, n, n_sq)) % n_sq
          
                
            t = ps.decrypt(w_rand) & 1
            if random.random() >= 0.5 + adv:
                t = 1 - t
            b = t ^ (r & 1)
            if b == 0:
                cpt0 += 1
            else:
                cpt1 += 1
        bit = 0 if cpt0 > cpt1 else 1
        bits.append(bit)
        if bit == 1:
            c = (c * g_inv) % n_sq
        c = pow(c, z, n_sq)

    res = 0
    for i in range(len(bits)):
        res = res + bits[i] * 2**i
    res = res % n
    return res


def test_oracle(ps, num_tests=5):
    print()
    print("test oracle1")
    cpt_ok = 0
    for t in range(num_tests):
        m = secrets.randbelow(ps.pk.n)
        c = ps.encrypt(m)[0]
        t0 = time.perf_counter()
        m_rec = cc_parfait(ps, c)
        elapsed = time.perf_counter() - t0
        ok = (m_rec == m)
        if ok:
            cpt_ok += 1
            tag = "ok"
        else:
            tag = "rate"
        ms = str(m)
        m_disp = ms[:16] + ("..." if len(ms) > 16 else "")
        print(f"  essai {t+1}: m={m_disp}  {tag}  ({elapsed*1000:.1f}ms)")
    print(f"  -> {cpt_ok}/{num_tests} bons")
    if cpt_ok != num_tests:
        print("attention: cpt=/numtest")


def run_imperfect_grid(ps, advantages, sample_sizes, num_trials):
    grid = {}
    for adv in advantages:
        grid[adv] = {}
        for s in sample_sizes:
            ok = 0
            for _ in range(num_trials):
                # cap, cf wrap (dans cc_bruite)
                m = secrets.randbelow(min(ps.pk.n, 2**20))
                c = ps.encrypt(m)[0]
                m_back = cc_bruite(ps, c, adv=adv, ns=s)
                if m_back == m:
                    ok += 1
            grid[adv][s] = ok / num_trials
    return grid


def essai_grille(ps,
                 advantages=(0.4, 0.2, 0.1, 0.05),
                 sample_sizes=(50, 200, 500),
                 num_trials=10):
    print()
    print("test grille 1")
    print("le bits mod", ps.pk.bits)

    grid = run_imperfect_grid(ps, advantages, sample_sizes, num_trials)
    # print(grid)

    for adv in advantages:
        for s in sample_sizes:
            print("adv=", adv, "s=", s, "taux=", grid[adv][s])
    return grid


def stats_lsb(ps, num_samples=2000, num_bits=10):

    print()
    print("stats sur le lsb")
    cpt0 = 0
    cpt1 = 0
    counts = []
    for i in range(num_bits):
        counts.append([0, 0])
    for _ in range(num_samples):
        m = secrets.randbelow(ps.pk.n)
        c = ps.encrypt(m)[0]
        cl = ps.decrypt(c)
        if cl % 2 == 0:
            cpt0 += 1
        else:
            cpt1 += 1
        for b in range(num_bits):
            counts[b][(cl // 2**b) % 2] += 1

    # 3.841, chi2 5%
    exp = num_samples / 2.0
    chi2 = (cpt0 - exp) ** 2 / exp + (cpt1 - exp) ** 2 / exp
    print("valeur de :")
    print("samples", num_samples)
    print("lsb0", cpt0, "lsb1", cpt1)
    print("chi2", chi2)
    if chi2 < 3.841:
        print("ok")
    else:
        print("deviationch")
    seuil = 7.88  
    print()
    all_ok = True
    for b in range(num_bits):
        c0 = counts[b][0]
        c1 = counts[b][1]
        chi2b = (c0 - exp) ** 2 / exp + (c1 - exp) ** 2 / exp
        if chi2b < seuil:
            tag = "ok"
        else:
            tag = "att"
            all_ok = False
        print("bit", b, c0, c1, "chi2", chi2b, tag)
    if not all_ok:
        print("att : au moins un bit qui devie")


def test_algebre(ps, num_samples=1000):
    n = ps.pk.n
    n_sq = ps.pk.n_sq
    z = (n + 1) // 2

    l1_ok = 0
    l1_tested = 0
    h_ok = 0

    for _ in range(num_samples):
        m = secrets.randbelow(n)
        c = ps.encrypt(m)[0]
        cl = ps.decrypt(c)
        if cl % 2 == 0:
            l1_tested += 1
            valeur = ps.decrypt(pow(c, z, n_sq))
            if valeur == (cl // 2) % n:
                l1_ok += 1

        m1 = secrets.randbelow(n)
        m2 = secrets.randbelow(n)
        c1 = ps.encrypt(m1)[0]
        c2 = ps.encrypt(m2)[0]
        somme = (ps.decrypt(c1) + ps.decrypt(c2)) % n
        prod_chiff = ps.decrypt((c1 * c2) % n_sq)
        if prod_chiff == somme:
            h_ok += 1

    return l1_ok, l1_tested, h_ok, num_samples


def bench_taille(modulus_bits=(32, 48, 64, 80, 96, 112, 128), num_trials=3):
    print()
    print("mesure du temps par taille de N")
    out = {}
    for kb in modulus_bits:
        ps = PaillierCryptosystem(key_bits=kb // 2)
        times = []
        for k in range(num_trials):
            m = secrets.randbelow(min(ps.pk.n, 2**20))
            c = ps.encrypt(m)[0]
            t0 = time.perf_counter()
            m_back = cc_parfait(ps, c)
            times.append(time.perf_counter() - t0)
            assert m_back == m
        mean_ms = 1000.0 * sum(times) / len(times)
        out[ps.pk.bits] = mean_ms
        print(ps.pk.bits, mean_ms)
    return out


def essai_cle(ps, num_runs=100):
    # demo test
    print()
    print("application section 5 (cle sym 128 bits)")

    n = ps.pk.n
    n_bits = ps.pk.bits
    key_bits = 128
    key_mask = 2**key_bits - 1

    key0 = None
    rec0 = None
    ok_count = 0

    for run in range(num_runs):
        sym_key = secrets.randbits(key_bits)
        max_prefix = (n - 1 - sym_key) // (2**key_bits)
        if max_prefix <= 0:
            print("modulus trop petit pr 128 bits")
            return
        prefix = secrets.randbelow(max_prefix + 1)
        m = prefix * (2**key_bits) + sym_key
        # assert m < n

        c = ps.encrypt(m)[0]
        m_back = ps.decrypt(c)
        recup = m_back % (2**key_bits)

        if recup == sym_key:
            ok_count += 1
        if run == 0:
            key0 = sym_key
            rec0 = recup

    print("taille N", n_bits)
    print("nb tirages", num_runs)
    #print("cle ex", hex(key0))
    #print("recup", hex(rec0))
    print("recup ok", ok_count, "/", num_runs)


if __name__ == "__main__":
    print("test")
    ps_small = PaillierCryptosystem(key_bits=32)
    print("cle", ps_small.pk.bits, "bits")

    l1, l1t, h, htot = test_algebre(ps_small, num_samples=500)
    print()
    print("verififation alge")
    print("L1", l1, "/", l1t)
    print("h:", h, "/", htot)

    test_oracle(ps_small, num_tests=5)
    essai_grille(ps_small, advantages=(0.4, 0.2, 0.1, 0.05), sample_sizes=(50, 200, 500), num_trials=10)
    bench_taille(modulus_bits=(32, 48, 64, 80, 96, 112, 128), num_trials=3)

    print()
    print("test bits: 256")
    ps = PaillierCryptosystem(key_bits=256)
    print("cle", ps.pk.bits, "bits")

    stats_lsb(ps, num_samples=2000, num_bits=10)
    essai_cle(ps, num_runs=100)
