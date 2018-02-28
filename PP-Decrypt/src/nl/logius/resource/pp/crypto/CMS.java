/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;

import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;

public class CMS {
    public static String read(PrivateKey key, InputStream is) throws IOException {
        try {
            final CMSEnvelopedDataParser parser = new CMSEnvelopedDataParser(is);
            final RecipientInformation info = parser.getRecipientInfos().getRecipients().iterator().next();
            final KeyTransRecipientInformation keyInfo = (KeyTransRecipientInformation) info;
            final byte[] message = keyInfo.getContent(new JceKeyTransEnvelopedRecipient(key).setProvider("BC"));
            return new String(message, StandardCharsets.US_ASCII);
        } catch (CMSException e) {
            throw new CryptoException("Could not read CMS", e);
        }
    }
}
