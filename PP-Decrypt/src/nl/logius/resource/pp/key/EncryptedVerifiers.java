/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp.key;

/**
 * Class that holds both a verifier for the encrypted identity and pseudonym
 */
public class EncryptedVerifiers {
    private final EncryptedVerifier identityVerifier;
    private final EncryptedVerifier pseudonymVerifier;

    public EncryptedVerifiers(EncryptedVerifier identityVerifier, EncryptedVerifier pseudonymVerifier) {
        this.identityVerifier = identityVerifier;
        this.pseudonymVerifier = pseudonymVerifier;
    }

    public EncryptedVerifier getIdentityVerifier() {
        return identityVerifier;
    }

    public EncryptedVerifier getPseudonymVerifier() {
        return pseudonymVerifier;
    }
}
