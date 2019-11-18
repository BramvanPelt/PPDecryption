/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * SPDX-Licence-Identifier: EUPL-1.2
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp.key;

import nl.logius.resource.pp.parser.DecryptKeyParser;

public class PseudonymClosingKey extends DecryptKey {

    protected PseudonymClosingKey(DecryptKeyParser parser) {
        super(parser);
    }
}
