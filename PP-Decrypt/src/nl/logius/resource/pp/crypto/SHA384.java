/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class SHA384 {
    public static MessageDigest getInstance() {
        try {
            return MessageDigest.getInstance("SHA-384");
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("No algorithm for SHA-384, add BouncyCastle as provider", e);
        }
    }

    private SHA384() {
    }
}
