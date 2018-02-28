/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp.key;

import nl.logius.resource.pp.parser.DecryptKeyParser;

public class PseudonymDecryptKey extends DecryptKey {

    protected PseudonymDecryptKey(DecryptKeyParser parser) {
        super(parser);
    }

    /**
     * Convert decrypt key to encrypted verifiers for the pseudonym only
     * @param verificationPoint Base64 verification point for pseudonym
     */
    public EncryptedVerifiers toVerifiers(String verificationPoint) {
        return new EncryptedVerifiers(null, getVerifier(verificationPoint));
    }
}
