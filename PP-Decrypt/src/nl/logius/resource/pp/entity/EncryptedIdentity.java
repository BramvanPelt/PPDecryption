/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp.entity;

import org.bouncycastle.math.ec.ECPoint;

import nl.logius.resource.pp.key.IdentityDecryptKey;
import nl.logius.resource.pp.parser.EncryptedEntityParser;

public class EncryptedIdentity extends EncryptedEntity {

    private final ECPoint[] points;

    EncryptedIdentity(EncryptedEntityParser parser) {
        super(parser);
        this.points = parser.getPoints();
    }

    public Identity decrypt(IdentityDecryptKey decryptKey) {
        check(decryptKey, true);
        final ECPoint point = points[1].subtract(points[0].multiply(decryptKey.getPrivateKey())).normalize();
        return new Identity(point);
    }
}
