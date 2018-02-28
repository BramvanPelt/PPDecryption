/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp.parser;

import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.BERTaggedObjectParser;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROctetStringParser;
import org.bouncycastle.asn1.DERSequenceParser;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemHeader;
import org.bouncycastle.util.io.pem.PemObject;

import nl.logius.resource.pp.crypto.BrainpoolP320r1;

public class DecryptKeyParser {
    public enum Type {
        IdentityDecryption("EI Decryption"),
        PseudonymDecryption("EP Decryption"),
        PseudonymClosing("EP Closing");

        public final String name;

        Type(String name) {
            this.name = name;
        }

        public static Type fromName(String name) {
            for (Type type : values()) {
                if (type.name.equals(name)) {
                    return type;
                }
            }
            throw new IllegalArgumentException(String.format("Unknown type %s", name));
        }
    }

    //private final static List<String> MANDATORY_HEADERS = ImmutableList.of(
    //    "SchemeVersion", "SchemeKeyVersion", "Type", "Recipient", "RecipientKeySetVersion");
    


    private final String contents;

    private int schemeVersion;
    private int schemeKeyVersion;
    private Type type;
    private String recipient;
    private int recipientKeySetVersion;
    private BigInteger privateKey;
    private ECPoint publicKey;

    public DecryptKeyParser(String contents) {
        this.contents = contents;
    }

    public void decode() {
        try (final PEMParser parser = new PEMParser(new StringReader(contents))){
            final PemObject pem = parser.readPemObject();
            if (!"EC PRIVATE KEY".equals(pem.getType())) {
                throw new ParsingException(String.format("Expected EC PRIVATE KEY, got %s", pem.getType()));
            }
            @SuppressWarnings("unchecked")
            final List<PemHeader> headers = pem.getHeaders();
            decodeHeaders(headers);
            decodeContent(pem.getContent());
        } catch (IOException e) {
            throw new ParsingException("Could not read PEM", e);
        }

    }

    public void decodeHeaders(List<PemHeader> headers) {
        final Set<String> mandatory = new LinkedHashSet<>();
        mandatory.add("SchemeVersion");
        mandatory.add("SchemeKeyVersion");
        mandatory.add("Type");
        mandatory.add("Recipient");
        mandatory.add("RecipientKeySetVersion");
        
        
        for (final PemHeader header: headers) {
            final String name = header.getName();
            final String value = header.getValue();

            mandatory.remove(name);
            switch (name) {
                case "SchemeVersion":
                    schemeVersion = parseVersion(name, value);
                    break;
                case "SchemeKeyVersion":
                    schemeKeyVersion = parseVersion(name, value);
                    break;
                case "Type":
                    type = parseType(value);
                    break;
                case "Recipient":
                    recipient = value;
                    break;
                case "RecipientKeySetVersion":
                    recipientKeySetVersion = parseVersion(name, value);
                    break;
            }
        }
        if (!mandatory.isEmpty()) {
            throw new ParsingException(String.format("Missing headers: %s", mandatory));
        }
    }

    private void decodeContent(byte[] encoded) throws IOException {
        final Asn1Parser parser = new Asn1Parser(encoded);

        parser.readObject(DERSequenceParser.class);
        final int version = parser.readObject(ASN1Integer.class).getValue().intValue();
        if (1 != version) {
            throw new ParsingException(String.format("Expected version 1, got %d", version));
        }
        final DEROctetString octetString =
            (DEROctetString) parser.readObject(DEROctetStringParser.class).getLoadedObject();
        privateKey = new BigInteger(1, octetString.getOctets());

        parser.readObject(BERTaggedObjectParser.class);
        final ASN1ObjectIdentifier oid = parser.readObject(ASN1ObjectIdentifier.class);
        if (!BrainpoolP320r1.OID.equals(oid)) {
            throw new ParsingException(String.format("Expected BrainpoolP320r1 (%s), got %s", BrainpoolP320r1.OID, oid));
        }

        final ASN1Encodable obj = parser.readObject();
        if (obj == null) {
            return;
        }
        Asn1Parser.checkObject(obj, BERTaggedObjectParser.class);
        try {
            publicKey = BrainpoolP320r1.CURVE.decodePoint(parser.readObject(DERBitString.class).getBytes()).normalize();
        } catch (IllegalArgumentException e) {
            throw new ParsingException("Could not decode point on curve", e);
        }

        BrainpoolP320r1.G.multiply(privateKey).normalize();
        if (!BrainpoolP320r1.G.multiply(privateKey).equals(publicKey)) {
            throw new ParsingException("Public key does not belong to private key");
        }
    }

    private static int parseVersion(String name, String value) {
        final int result;
        try {
            result = Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new ParsingException(String.format("Cannot parse %s [%s] as integer", value, name), e);
        }
        if (result <= 0) {
            throw new ParsingException(String.format("Expect %s [%d] to be positive", name, result));
        }
        return result;
    }

    private static Type parseType(String value) {
        try {
            return Type.fromName(value);
        } catch (IllegalArgumentException e) {
            throw new ParsingException(String.format("Unknown type %s", value), e);
        }
    }

    public int getSchemeVersion() {
        return schemeVersion;
    }

    public int getSchemeKeyVersion() {
        return schemeKeyVersion;
    }

    public Type getType() {
        return type;
    }

    public String getRecipient() {
        return recipient;
    }

    public int getRecipientKeySetVersion() {
        return recipientKeySetVersion;
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public ECPoint getPublicKey() {
        return publicKey;
    }

}
