/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp.util;

import nl.logius.resource.pp.PolyPseudoException;
import nl.logius.resource.pp.entity.EncryptedEntity;
import nl.logius.resource.pp.entity.EncryptedIdentity;
import nl.logius.resource.pp.entity.EncryptedPseudonym;
import nl.logius.resource.pp.entity.Identity;
import nl.logius.resource.pp.entity.Pseudonym;
import nl.logius.resource.pp.key.EncryptedVerifiers;
import nl.logius.resource.pp.key.IdentityDecryptKey;
import nl.logius.resource.pp.key.PseudonymClosingKey;
import nl.logius.resource.pp.key.PseudonymDecryptKey;

public class DecryptUtil {

    public static String getIdentity(String ei, IdentityDecryptKey decryptKey, EncryptedVerifiers verifiers) throws PolyPseudoException {
        // Decrypt encrypted identity
        EncryptedIdentity encryptedIdentity = EncryptedEntity.fromBase64(ei, verifiers, EncryptedIdentity.class);
        Identity identity = encryptedIdentity.decrypt(decryptKey);
       
        return identity.toString();
    }
    

    public static String getPseudonym(String ep, PseudonymDecryptKey decryptKey, PseudonymClosingKey closingKey, EncryptedVerifiers verifiers) throws PolyPseudoException {
    	// Decrypt encrypted pseudo
		EncryptedPseudonym encryptedPseudo = EncryptedEntity.fromBase64(ep, verifiers, EncryptedPseudonym.class);
		Pseudonym pseudo = encryptedPseudo.decrypt(decryptKey, closingKey);	
		
    	return pseudo.toString();
    }
}
