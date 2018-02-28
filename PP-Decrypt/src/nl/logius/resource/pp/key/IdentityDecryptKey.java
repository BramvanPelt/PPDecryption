/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp.key;

import nl.logius.resource.pp.parser.DecryptKeyParser;

public class IdentityDecryptKey extends DecryptKey {

    protected IdentityDecryptKey(DecryptKeyParser parser) {
        super(parser);
    }

    /**
     * Convert decrypt key to encrypted verifiers for the identity only
     * @param verificationPoint Base64 verification point for identity
     */
    public EncryptedVerifiers toVerifiers(String verificationPoint) {
        return new EncryptedVerifiers(getVerifier(verificationPoint), null);
    }
}
