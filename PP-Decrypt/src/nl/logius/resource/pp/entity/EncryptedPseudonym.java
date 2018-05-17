/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp.entity;

import org.bouncycastle.math.ec.ECPoint;

import nl.logius.resource.pp.key.PseudonymClosingKey;
import nl.logius.resource.pp.key.PseudonymDecryptKey;
import nl.logius.resource.pp.parser.EncryptedEntityParser;

public class EncryptedPseudonym extends EncryptedEntity {

    private final ECPoint[] points;
    private final String diversifier;
    private final char type;

    EncryptedPseudonym(EncryptedEntityParser parser) {
        super(parser);
        this.points = parser.getPoints();
        this.diversifier = parser.getDiversifier();
        this.type = parser.getType();
    }

    public Pseudonym decrypt(PseudonymDecryptKey decryptKey, PseudonymClosingKey closingKey) {
        check(decryptKey, true);
        check(closingKey, false);

        final ECPoint point = points[1].subtract(points[0].multiply(decryptKey.getPrivateKey())).
            multiply(closingKey.getPrivateKey()).normalize();
        return new Pseudonym(closingKey.getRecipientKeySetVersion(), point);
    }

    public String getDiversifier() {
        return diversifier;
    }

    public char getType() {
        return type;
    }
}
