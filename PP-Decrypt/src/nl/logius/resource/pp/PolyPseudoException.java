/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp;

/**
 * Base exception for own exceptions thrown in this library
 *
 */
public class PolyPseudoException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public PolyPseudoException(String message) {
        super(message);
    }

    public PolyPseudoException(String message, Throwable throwable) {
        super(message, throwable);
    }
}
