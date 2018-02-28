/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp.key;

import java.util.Objects;

import org.bouncycastle.math.ec.ECPoint;

import nl.logius.resource.pp.crypto.Signature;

/**
 * Verifier that can be used to check encrypted entities
 *
 * It uses the public key of the decrypt key and a verification point that is published.
 */
public class EncryptedVerifier {
    private final ECPoint publicKey;
    private final ECPoint verificationPoint;

    EncryptedVerifier(ECPoint publicKey, ECPoint verificationPoint) {
        this.publicKey = publicKey;
        this.verificationPoint = verificationPoint;
    }

    public void verify(byte[] payload, Signature signature) {
        signature.verify(publicKey, verificationPoint, payload);
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof EncryptedVerifier)) return false;
        final EncryptedVerifier that = (EncryptedVerifier) o;
        return Objects.equals(publicKey, that.publicKey) &&
            Objects.equals(verificationPoint, that.verificationPoint);
    }

    @Override
    public final int hashCode() {
        return Objects.hash(publicKey, verificationPoint);
    }
}
