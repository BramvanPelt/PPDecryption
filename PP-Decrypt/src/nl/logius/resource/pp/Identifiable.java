/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp;

import java.util.Objects;

public interface Identifiable {
    static void check(Identifiable a, Identifiable b, boolean includeKeySetVersion) {
        if (a.getSchemeVersion() != b.getSchemeVersion()) {
            throw new PolyPseudoException(String.format("Scheme version %d is not equal to %d",
                a.getSchemeVersion(), b.getSchemeVersion()));
        }
        if (a.getSchemeKeyVersion() != b.getSchemeKeyVersion()) {
            throw new PolyPseudoException(String.format("Scheme key version %d is not equal to %d",
                a.getSchemeKeyVersion(), a.getSchemeKeyVersion()));
        }
        if (!Objects.equals(a.getRecipient(), b.getRecipient())) {
            throw new PolyPseudoException(String.format("Recipient '%s' is not equal to '%s'",
                a.getRecipient(), b.getRecipient()));
        }
        if (includeKeySetVersion && a.getRecipientKeySetVersion() != b.getRecipientKeySetVersion()) {
            throw new PolyPseudoException(String.format("Recipient key set version %d does not match key %d",
                a.getRecipientKeySetVersion(), b.getRecipientKeySetVersion()));
        }
    }

    default void check(Identifiable other, boolean includeKeySetVersion) {
        check(this, other, includeKeySetVersion);
    }

    int getSchemeVersion();
    int getSchemeKeyVersion();
    String getRecipient();
    int getRecipientKeySetVersion();
}
