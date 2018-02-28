/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp.parser;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DERSequenceParser;

import nl.logius.resource.pp.BsnkType;

public class Asn1Parser {
    private final ASN1StreamParser parser;

    public Asn1Parser(byte[] encoded) {
        parser = new ASN1StreamParser(encoded);
    }

    public <T extends ASN1Encodable> T readObject(Class<T> klass) throws IOException {
        final ASN1Encodable obj = readObject();
        return checkObject(obj, klass);
    }

    public ASN1Encodable readObject() throws IOException {
        return parser.readObject();
    }

    @SuppressWarnings("unchecked")
    public static <T extends ASN1Encodable> T checkObject(ASN1Encodable obj, Class<T> klass) {
        if (obj == null) {
            throw new ParsingException(String.format(
                "ASN1 decode error, expected %s, got null", klass.getSimpleName()
            ));
        }
        if (!klass.isInstance(obj)) {
            throw new ParsingException(String.format(
                "ASN1 decode error, expected %s, got %s",
                klass.getSimpleName(), obj.getClass().getSimpleName()));
        }
        return (T) obj;
    }

    public BsnkType checkHeader() throws IOException {
        readObject(DERSequenceParser.class);
        final String oid = readObject(ASN1ObjectIdentifier.class).getId();
        try {
            return BsnkType.fromOid(oid);
        } catch (IllegalArgumentException e) {
            throw new ParsingException("Unknown BsnkType", e);
        }
    }
}
