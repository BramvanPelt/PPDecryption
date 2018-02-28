/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp.entity;

public abstract class Entity {

    public abstract String getStandard();

    public String getShort() {
        return getStandard();
    }

    @Override
    public String toString() {
        return getStandard();
    }
}
