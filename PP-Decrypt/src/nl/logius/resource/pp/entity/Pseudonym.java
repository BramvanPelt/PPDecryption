/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp.entity;

import org.bouncycastle.math.ec.ECPoint;

import nl.logius.resource.pp.util.Base16Util;

public class Pseudonym extends Entity {

    private final int version;
    private final ECPoint point;

    Pseudonym(int version, ECPoint point) {
        this.version = version;
        this.point = point;
    }

    @Override
    public String getStandard() {
        return String.format("%08d%s", version, Base16Util.encode(point.getEncoded(false)));
    }

    @Override
    public String getShort() {
        return String.format("%d|%s", version, Base16Util.encode(point.getEncoded(true)));
    }
}
