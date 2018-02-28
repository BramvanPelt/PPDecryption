/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp.entity;

import java.util.Base64;

import nl.logius.resource.pp.Identifiable;
import nl.logius.resource.pp.PolyPseudoException;
import nl.logius.resource.pp.key.EncryptedVerifiers;
import nl.logius.resource.pp.parser.EncryptedEntityParser;

public abstract class EncryptedEntity implements Identifiable {

    private final int schemeVersion;
    private final int schemeKeyVersion;
    private final String creator;
    private final String recipient;
    private final int recipientKeySetVersion;

    public static EncryptedEntity fromBase64(String base64, EncryptedVerifiers verifiers) {
        final byte[] encoded = Base64.getDecoder().decode(base64);
        final EncryptedEntityParser parser = new EncryptedEntityParser(encoded);
        parser.decode(verifiers);
        switch (parser.getBsnkType()) {
            case ENCRYPTED_IDENTITY:
            case SIGNED_ENCRYPTED_IDENTITY:
                return new EncryptedIdentity(parser);
            case ENCRYPTED_PSEUDONYM:
            case SIGNED_ENCRYPTED_PSEUDONYM:
                return new EncryptedPseudonym(parser);
            default:
                throw new PolyPseudoException(String.format("Unexpected type %s", parser.getType()));
        }
    }

    @SuppressWarnings("unchecked")
    public static <T extends EncryptedEntity> T fromBase64(String base64, EncryptedVerifiers verifiers,
                                                           Class<T> klass) {
        final EncryptedEntity key = fromBase64(base64, verifiers);
        if (!klass.isInstance(key)) {
            throw new PolyPseudoException(String.format("Expected instance of %s, got %s",
                klass.getSimpleName(), key.getClass().getSimpleName()));
        }
        return (T) key;
    }

    protected EncryptedEntity(EncryptedEntityParser parser) {
        this.schemeVersion = parser.getSchemeVersion();
        this.schemeKeyVersion = parser.getSchemeKeyVersion();
        this.creator = parser.getCreator();
        this.recipient = parser.getRecipient();
        this.recipientKeySetVersion = parser.getRecipientKeySetVersion();
    }

    @Override
    public int getSchemeVersion() {
        return schemeVersion;
    }

    @Override
    public int getSchemeKeyVersion() {
        return schemeKeyVersion;
    }

    public String getCreator() {
        return creator;
    }

    @Override
    public String getRecipient() {
        return recipient;
    }

    @Override
    public int getRecipientKeySetVersion() {
        return recipientKeySetVersion;
    }
}
