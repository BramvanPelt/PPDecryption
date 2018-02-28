/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp.parser;

import nl.logius.resource.pp.PolyPseudoException;

public class ParsingException extends PolyPseudoException {

    private static final long serialVersionUID = 1L;

    ParsingException(String message) {
        super(message);
    }

    ParsingException(String message, Throwable throwable) {
        super(message, throwable);
    }
}
