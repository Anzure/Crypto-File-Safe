package no.odit.crypto.util;

import no.odit.crypto.model.PuzzleDetails;

import java.math.BigInteger;
import java.util.concurrent.ThreadLocalRandom;

public class TimeLockPuzzle {

    private static final int P_RANDOM_SEED_LENGTH = getRandomInteger(12, 16);
    private static final int Q_RANDOM_SEED_LENGTH = getRandomInteger(12, 16);
    private static final int RSA_PRIME_LENGTH = 1024;
    private static final BigInteger ONE = new BigInteger("1");
    private static final BigInteger TWO = new BigInteger("2");
    private static final BigInteger DIFFICULTY = new BigInteger("125000");

    public static PuzzleDetails createPuzzle(String secretMessage, BigInteger seconds) {
        BigInteger t = DIFFICULTY.multiply(seconds);

        BigInteger twoPower = (new BigInteger("1")).shiftLeft(RSA_PRIME_LENGTH);

        BigInteger prand = new BigInteger(getRandomBigInteger(P_RANDOM_SEED_LENGTH));
        BigInteger qrand = new BigInteger(getRandomBigInteger(Q_RANDOM_SEED_LENGTH));

        BigInteger p = new BigInteger("5");
        p = getNextPrime(p.modPow(prand, twoPower));

        BigInteger q = new BigInteger("5");
        q = getNextPrime(q.modPow(qrand, twoPower));

        BigInteger n = p.multiply(q);

        BigInteger pm1 = p.subtract(ONE);
        BigInteger qm1 = q.subtract(ONE);
        BigInteger phi = pm1.multiply(qm1);

        BigInteger u = TWO.modPow(t, phi);
        BigInteger w = TWO.modPow(u, n);

        StringBuffer sgen = new StringBuffer(secretMessage);
        BigInteger secret = getBigIntegerFromStringBuffer(sgen);
        if (secret.compareTo(n) > 0) {
            throw new Error("Secret too large!");
        }
        BigInteger z = secret.xor(w);

        return PuzzleDetails.builder().n(n).t(t).z(z).build();
    }

    public static String solvePuzzle(BigInteger n, BigInteger t, BigInteger z) {
        BigInteger w = TWO;
        for (int i = 0; i < t.intValue(); i++) {
            w = w.modPow(TWO, n);
        }
        BigInteger x = w.xor(z);
        return new String(x.toByteArray());
    }

    private static BigInteger getBigIntegerFromStringBuffer(StringBuffer s) {
        BigInteger bigInt = new BigInteger("0");
        for (int i = 0; i < s.length(); i++) {
            int c = s.charAt(i);
            bigInt = bigInt.shiftLeft(8).add(new BigInteger(Integer.toString(c)));
        }
        return bigInt;
    }

    private static int getRandomInteger(int min, int max) {
        return ThreadLocalRandom.current().nextInt(min, max);
    }

    private static String getRandomBigInteger(int length) {
        StringBuilder sb = new StringBuilder();
        String digits = "0123456789";
        for (int i = 0; i < length; i++) {
            int randomDigitIndex = getRandomInteger(0, digits.length());
            sb.append(digits.charAt(randomDigitIndex));
        }
        return sb.toString();
    }

    private static BigInteger getNextPrime(BigInteger startvalue) {
        BigInteger p = startvalue;
        if (!p.and(ONE).equals(ONE)) p = p.add(ONE);
        while (!p.isProbablePrime(40)) p = p.add(TWO);
        return (p);
    }

}