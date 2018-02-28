/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp.entity;

import java.nio.charset.StandardCharsets;

import org.bouncycastle.math.ec.ECPoint;

import nl.logius.resource.pp.PolyPseudoException;
import nl.logius.resource.pp.crypto.OAEP;

public class Identity extends Entity {

    private final int version;
    private final char type;
    private final String identifier;

    Identity(ECPoint point) {
        final byte[] encoded = point.getAffineXCoord().getEncoded();
        final int offset = getZeroOffset(encoded);
        final byte[] decoded = OAEP.decode(encoded, offset, encoded.length - offset, 10);

        version = decoded[0];
        type = (char) decoded[1];
        if (decoded[2] > decoded.length - 3) {
            throw new PolyPseudoException(String.format("Incorrect decoded identifier, length (%d) > %d",
                decoded[2], decoded.length - 3));
        }
        identifier = new String(decoded, 3, decoded[2], StandardCharsets.US_ASCII);
    }

    @Override
    public String getStandard() {
        return type == 'B' ? identifier : String.valueOf(type) + identifier;
    }

    public int getVersion() {
        return version;
    }

    public char getType() {
        return type;
    }

    public String getIdentifier() {
        return identifier;
    }

    private static int getZeroOffset(byte[] encoded) {
        for (int i = 0; i < encoded.length; i++) {
            if (encoded[i] != 0) {
                return i;
            }
        }
        throw new PolyPseudoException("Zero point");
    }
}
