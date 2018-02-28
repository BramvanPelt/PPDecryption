/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp.key;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;

import nl.logius.resource.pp.Identifiable;
import nl.logius.resource.pp.PolyPseudoException;
import nl.logius.resource.pp.crypto.BrainpoolP320r1;
import nl.logius.resource.pp.parser.DecryptKeyParser;

public abstract class DecryptKey implements Identifiable {

    private int schemeVersion;
    private int schemeKeyVersion;
    private final String recipient;
    private final int recipientKeySetVersion;
    private final BigInteger privateKey;
    private final ECPoint publicKey;

    public static DecryptKey fromPem(String pem) {
        final DecryptKeyParser parser = new DecryptKeyParser(pem);
        parser.decode();
        switch (parser.getType()) {
            case IdentityDecryption:
                return new IdentityDecryptKey(parser);
            case PseudonymDecryption:
                return new PseudonymDecryptKey(parser);
            case PseudonymClosing:
                return new PseudonymClosingKey(parser);
            default:
                throw new PolyPseudoException(String.format("Unknown type %s", parser.getType()));
        }
    }

    @SuppressWarnings("unchecked")
    public static <T extends DecryptKey> T fromPem(String pem, Class<T> klass) {
        final DecryptKey key = fromPem(pem);
        if (!klass.isInstance(key)) {
            throw new PolyPseudoException(String.format("Expected instance of %s, got %s",
                klass.getSimpleName(), key.getClass().getSimpleName()));
        }
        return (T) key;
    }

    protected DecryptKey(DecryptKeyParser parser) {
        this.schemeVersion = parser.getSchemeVersion();
        this.schemeKeyVersion = parser.getSchemeKeyVersion();
        this.recipient = parser.getRecipient();
        this.recipientKeySetVersion = parser.getRecipientKeySetVersion();
        this.privateKey = parser.getPrivateKey();
        this.publicKey = parser.getPublicKey();
    }

    @Override
    public int getSchemeVersion() {
        return schemeVersion;
    }

    @Override
    public int getSchemeKeyVersion() {
        return schemeKeyVersion;
    }

    @Override
    public String getRecipient() {
        return recipient;
    }

    @Override
    public int getRecipientKeySetVersion() {
        return recipientKeySetVersion;
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public ECPoint getPublicKey() {
        return publicKey;
    }

    /**
     * Convert decrypt key to encrypted verifier for this key
     */
    public EncryptedVerifier getVerifier(String verificationPoint) {
        final ECPoint point = BrainpoolP320r1.CURVE.decodePoint(Base64.decode(verificationPoint));
        return new EncryptedVerifier(this.publicKey, point);
    }
}
