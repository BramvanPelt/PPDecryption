/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp.crypto;

import java.security.MessageDigest;
import java.util.Arrays;

public final class OAEP {

    private static final byte[] LHASH = SHA384.getInstance().digest();

    public static byte[] decode(byte[] message, int pos, int length, int hlen) {
        if (length > 48) {
            throw new CryptoException(String.format("Length of message is too big (%d > 48)", length));
        }
        if (hlen > 48) {
            throw new CryptoException(String.format("Hash length is too big (%d > 48)", hlen));
        }
        if (length <= 2 * hlen) {
            throw new CryptoException(String.format("Message is too short (%d <= 2 * %d)", length, hlen));
        }

        final byte[] seed = mgf1(message, pos + hlen, length - hlen);
        xor(message, pos, seed, hlen);

        final byte[] db = mgf1(seed, 0, hlen);
        xor(message, pos + hlen, db, length - hlen);

        verify(db, hlen);

        return Arrays.copyOfRange(db, hlen + 1, length - hlen);
    }

    private static void verify(byte[] db, int hlen) {
        if (db[hlen] != 1) {
            throw new CryptoException("OAEP decode error, db[hlen] != 1");
        }
        for (int i = 0; i < hlen; i++) {
            if (LHASH[i] != db[i]) {
                throw new CryptoException("OAEP decode error, hash is not equal");
            }
        }
    }

    /**
     * b = a XOR b
     */
    private static void xor(byte[] src, int srcPos, byte[] dest, int length) {
        for (int i = 0; i < length; i++) {
            dest[i] ^= src[srcPos + i];
        }
    }

    /**
     * Single block MGF1 with SHA-384 of input from pos to pos+length-1
     */
    private static byte[] mgf1(byte[] input, int pos, int length) {
        final MessageDigest md = SHA384.getInstance();
        md.update(input, pos, length);
        md.update(new byte[] {0, 0, 0, 0});
        return md.digest();
    }

    private OAEP() {
    }
}
