/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp.crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;

import org.bouncycastle.math.ec.ECPoint;

public class Signature {
    private final BigInteger r;
    private final BigInteger s;

    public Signature(BigInteger r, BigInteger s) {
        this.r = r;
        this.s = s;
    }

    public void verify(ECPoint publicKey, ECPoint G, byte[] message) {
        if (r.bitCount() > 320 || r.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(BrainpoolP320r1.Q) >= 0) {
            throw new CryptoException("Invalid signature");
        }

        final ECPoint q = G.multiply(s).add(publicKey.multiply(r)).normalize();
        if (q.isInfinity()) {
            throw new CryptoException("Invalid signature");
        }

        final MessageDigest md = SHA384.getInstance();
        md.update(message);
        md.update(q.getAffineXCoord().getEncoded());
        // Use only 320 MSB
        final byte[] hash = Arrays.copyOfRange(md.digest(), 0, 40);
        final BigInteger v = new BigInteger(1, hash);
        if (!r.equals(v)) {
            throw new CryptoException("Invalid signature");
        }
    }
}
