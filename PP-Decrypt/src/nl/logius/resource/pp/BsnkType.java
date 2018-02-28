/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp;

public enum BsnkType {
    ENCRYPTED_IDENTITY("2.16.528.1.1003.10.1.2.1"),
    ENCRYPTED_PSEUDONYM("2.16.528.1.1003.10.1.2.2"),
    SIGNED_ENCRYPTED_IDENTITY("2.16.528.1.1003.10.1.2.3"),
    SIGNED_ENCRYPTED_PSEUDONYM("2.16.528.1.1003.10.1.2.4");

    public final String oid;

    BsnkType(String oid) {
        this.oid = oid;
    }

    public static BsnkType fromOid(String oid) {
        for (BsnkType type : values()) {
            if (type.oid.equals(oid)) {
                return type;
            }
        }
        throw new IllegalArgumentException(String.format("Unknown type for object id %s", oid));
    }
}
