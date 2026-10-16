import java.math.BigInteger;

/**
 * CS327 Project 2 - RSA Programming with Big Numbers
 *
 * Part 2.2: a better but still flawed RSA key (200-bit N), factored with SageMath.
 * Part 2.3: a real-world RSA key (3072-bit N), with timing of plain and CRT decryption.
 *
 * All big integers are printed in hexadecimal; only bit counts and speeds are decimal.
 *
 * Compile:  javac KimJadenRSA2.java
 * Run:      java KimJadenRSA2
 */
public class KimJadenRSA2 {

    // ---------- Task 2.2: [FLAWED EXAMPLE] (given in decimal) ----------
    static final String FLAWED_N_DEC =
        "1010517893091632587989664773819175360110584414091408545389643";
    static final String FLAWED_E_DEC = "65537";
    // p obtained by factoring N with SageMath: factor(N)
    static final String FLAWED_P_DEC = "863490933159798076360907020927";

    // ---------- Task 2.3: [REAL-WORLD EXAMPLE] (given in hex) ----------
    static final String REAL_P_HEX =
        "c86422b12e3a0c79cbe9f10c47a436fc54a71309214a3455054fca5912e442c32247ffdc782e574c96d7d43e60e383d7f0f091f08909f2629c5ad1bd5ce2427333dedb281abb1bffcbfb2814b402dc29bf5406d6e749ba57e1e6843f0111875a34439aeb2aa6c554d71b8cbaefbe0f6a4c7a0145d75afda323c7520a29d4d3d799a676977a0d3bd0f3411023c3ab106ee5fb0d2fbaa64e85fb71b6b76ebebbbfcd1ffd1de93302e90a3fefe0ffcb95a3da7ce6e2dcdd973873b96dd939763025";
    static final String REAL_Q_HEX =
        "d062fa3d79191304a4a64d39dc3b5ca757b9b740304825b13d05d17ffcf3b1e033dbffbe31eeea0b908f8ed36ebc2d1b1db3a094e2ddd4976549e225981ac6f9586a31f79b90cc41ed4c069d1306482345c8cc61fc4567bd2043484f8ac2fca32d7690c0881889b44a365795b0af07046a6bc468b10570033e2b6ad8d7702266c6d6ca5eec75224039998f719f74ad8fdebe9c4347a71e6cd96e03796b570f459c23c6ca250761e741f957d4b9f24df783e6c2ebe91e64863b710989da81a261";

    static final BigInteger M = BigInteger.valueOf(3);   // message m = 3
    static final int RUNS = 1000;                          // decryptions to time

    static String hex(BigInteger x) { return "0x" + x.toString(16); }

    // ===================== Task 2.2 =====================
    public void flawedExample() {
        System.out.println("***************Part II output begins (Task 2.2: flawed example)***************");
        BigInteger N = new BigInteger(FLAWED_N_DEC, 10);
        BigInteger e = new BigInteger(FLAWED_E_DEC, 10);
        BigInteger p = new BigInteger(FLAWED_P_DEC, 10);
        BigInteger[] qr = N.divideAndRemainder(p);
        BigInteger q = qr[0];
        if (qr[1].signum() != 0) throw new IllegalStateException("p does not divide N");

        System.out.println("N = " + hex(N));
        System.out.println("e = " + hex(e));
        System.out.println("p = " + hex(p));
        System.out.println("q = " + hex(q));
        System.out.println("p * q == N ? " + p.multiply(q).equals(N));
        System.out.println("p prime? " + p.isProbablePrime(50) + ", q prime? " + q.isProbablePrime(50));
        System.out.println("Bit-length of N = " + N.bitLength());
        System.out.println("Bit-length of p = " + p.bitLength());
        System.out.println("Bit-length of q = " + q.bitLength());

        BigInteger z = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        System.out.println("p - 1 = " + hex(p.subtract(BigInteger.ONE)));
        System.out.println("q - 1 = " + hex(q.subtract(BigInteger.ONE)));
        System.out.println("z = (p-1)*(q-1) = " + hex(z));
        System.out.println("gcd(e, z) = " + hex(e.gcd(z)));
        BigInteger d = e.modInverse(z);
        System.out.println("d = e^-1 mod z = " + hex(d));
        System.out.println("check: e*d mod z = " + hex(e.multiply(d).mod(z)));

        System.out.println("m = " + hex(M));
        BigInteger c = M.modPow(e, N);
        System.out.println("c = m^e mod N = " + hex(c));
        BigInteger m2 = c.modPow(d, N);
        System.out.println("m2 = c^d mod N = " + hex(m2));
        System.out.println("m2 == m ? " + m2.equals(M));
        System.out.println();
    }

    // ===================== Task 2.3 =====================
    static BigInteger crtDecrypt(BigInteger c, BigInteger p, BigInteger q,
                                 BigInteger dp, BigInteger dq, BigInteger qInv) {
        BigInteger m1 = c.mod(p).modPow(dp, p);           // c^dp mod p
        BigInteger m2 = c.mod(q).modPow(dq, q);           // c^dq mod q
        BigInteger h = qInv.multiply(m1.subtract(m2)).mod(p);
        return m2.add(h.multiply(q));                     // m = m2 + h*q
    }

    public void realWorldExample() {
        System.out.println("***************Part III output begins (Task 2.3: real-world example)***************");
        BigInteger p = new BigInteger(REAL_P_HEX, 16);
        BigInteger q = new BigInteger(REAL_Q_HEX, 16);
        BigInteger e = BigInteger.ONE.shiftLeft(16).add(BigInteger.ONE);   // 2^16 + 1
        BigInteger N = p.multiply(q);

        System.out.println("p = " + hex(p));
        System.out.println("q = " + hex(q));
        System.out.println("N = p * q = " + hex(N));
        System.out.println("Bit-length of N = " + N.bitLength());
        System.out.println("Bit-length of p = " + p.bitLength());
        System.out.println("Bit-length of q = " + q.bitLength());
        System.out.println("e = " + hex(e));
        System.out.println("Public key (N, e) = (" + hex(N) + ", " + hex(e) + ")");

        BigInteger z = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        System.out.println("z = (p-1)*(q-1) = " + hex(z));
        BigInteger d = e.modInverse(z);
        System.out.println("d = e^-1 mod z = " + hex(d));
        System.out.println("Private key (N, d) = (" + hex(N) + ", " + hex(d) + ")");
        System.out.println("check: e*d mod z = " + hex(e.multiply(d).mod(z)));

        System.out.println("m = " + hex(M));
        BigInteger c = M.modPow(e, N);
        System.out.println("c = m^e mod N = " + hex(c));
        BigInteger m2 = c.modPow(d, N);
        System.out.println("m2 = c^d mod N = " + hex(m2));
        System.out.println("m2 == m ? " + m2.equals(M));

        // ---- Q6: plain RSA decryption speed ----
        c.modPow(d, N);                                   // warm-up
        long start = System.currentTimeMillis();
        for (int i = 0; i < RUNS; i++) c.modPow(d, N);
        long ms = System.currentTimeMillis() - start;
        double secPerDec = (ms / 1000.0) / RUNS;
        double bps = N.bitLength() / secPerDec;
        double kbps = bps / 1000.0;
        double gbps = bps / 1e9;
        System.out.println("RSA Decryptions took " + ms + " milliseconds (" + RUNS + " runs)");
        System.out.printf("RSA Decryptions in terms of kilobits/second = %.3f kbps%n", kbps);
        System.out.printf("This speed is %.9f gigabit/second; %s for 1 gigabit/second Internet speed.%n",
                gbps, gbps >= 1.0 ? "fast enough" : "NOT fast enough (a bottleneck)");

        // ---- Q7: CRT decryption ----
        BigInteger dp = d.mod(p.subtract(BigInteger.ONE));
        BigInteger dq = d.mod(q.subtract(BigInteger.ONE));
        BigInteger qInv = q.modInverse(p);
        System.out.println("dp = d mod (p-1) = " + hex(dp));
        System.out.println("dq = d mod (q-1) = " + hex(dq));
        System.out.println("qInv = q^-1 mod p = " + hex(qInv));
        BigInteger mCrt = crtDecrypt(c, p, q, dp, dq, qInv);
        System.out.println("CRT decrypted cleartext = " + hex(mCrt));
        System.out.println("CRT result == m ? " + mCrt.equals(M));

        crtDecrypt(c, p, q, dp, dq, qInv);                // warm-up
        start = System.currentTimeMillis();
        for (int i = 0; i < RUNS; i++) crtDecrypt(c, p, q, dp, dq, qInv);
        long msCrt = System.currentTimeMillis() - start;
        double bpsCrt = N.bitLength() / ((msCrt / 1000.0) / RUNS);
        System.out.println("CRT Decryptions took " + msCrt + " milliseconds (" + RUNS + " runs)");
        System.out.printf("CRT Decryptions in terms of kilobits/second = %.3f kbps%n", bpsCrt / 1000.0);
        System.out.printf("The CRT speed is %.9f gigabit/second%n", bpsCrt / 1e9);
        System.out.printf("CRT speedup over plain RSA decryption = %.2fx%n", bpsCrt / bps);
    }

    public static void main(String[] args) {
        KimJadenRSA2 rsa = new KimJadenRSA2();
        rsa.flawedExample();
        rsa.realWorldExample();
    }
}