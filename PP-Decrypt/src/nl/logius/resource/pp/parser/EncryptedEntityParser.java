/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp.parser;

import java.io.IOException;
import java.util.Arrays;

import org.bouncycastle.asn1.*;
import org.bouncycastle.math.ec.ECPoint;

import nl.logius.resource.pp.BsnkType;
import nl.logius.resource.pp.crypto.BrainpoolP320r1;
import nl.logius.resource.pp.crypto.Signature;
import nl.logius.resource.pp.key.EncryptedVerifier;
import nl.logius.resource.pp.key.EncryptedVerifiers;

public class EncryptedEntityParser {
    private static final String EC_SCHNORR_SHA384_OID = "0.4.0.127.0.7.1.1.4.3.3";
    private final Asn1Parser parser;
    private BsnkType bsnkType;

    private int schemeVersion;
    private int schemeKeyVersion;
    private String creator;
    private String recipient;
    private int recipientKeySetVersion;
    private String diversifier;
    private char type;
    private ECPoint[] points;

    public EncryptedEntityParser(byte[] encoded) {
        parser = new Asn1Parser(encoded);
    }

    public void decode(EncryptedVerifiers verifiers) {
        try {
            bsnkType = parser.checkHeader();
            switch (bsnkType) {
            case ENCRYPTED_IDENTITY:
                decodePayload(parser, false);
                return;
            case ENCRYPTED_PSEUDONYM:
                decodePayload(parser, true);
                return;
            case SIGNED_ENCRYPTED_IDENTITY:
                if (verifiers == null || verifiers.getIdentityVerifier() == null) {
                    throw new ParsingException("No verifier for identity found");
                }
                decodeSigned(false, verifiers.getIdentityVerifier());
                return;
            case SIGNED_ENCRYPTED_PSEUDONYM:
                if (verifiers == null || verifiers.getPseudonymVerifier() == null) {
                    throw new ParsingException("No verifier for pseudonym found");
                }
                decodeSigned(true, verifiers.getPseudonymVerifier());
                return;
            default:
                throw new ParsingException(String.format("Cannot handle type %s", bsnkType));
            }
        } catch (IOException e) {
            throw new ParsingException("Could not read ASN1", e);
        }
    }

    private void decodeSigned(boolean isPseudonym, EncryptedVerifier verifier) {
        try {
            final byte[] payload = parser.readObject(DERSequenceParser.class).getLoadedObject().getEncoded();
            final Asn1Parser payloadParser = new Asn1Parser(payload);
            payloadParser.readObject(DERSequenceParser.class);

            bsnkType = payloadParser.checkHeader();
            switch (bsnkType) {
            case ENCRYPTED_IDENTITY:
                if (isPseudonym) {
                    throw new ParsingException("Encrypted identity inside signed encrypted pseudonym");
                }
                decodePayload(payloadParser, false);
                break;
            case ENCRYPTED_PSEUDONYM:
                if (!isPseudonym) {
                    throw new ParsingException("Encrypted pseudonym inside signed encrypted identity");
                }
                decodePayload(payloadParser, true);
                break;
            default:
                throw new ParsingException(String.format("Cannot handle type %s", bsnkType));
            }

            final Signature signature = decodeSignature();
            verifier.verify(payload, signature);

        } catch (IOException e) {
            throw new ParsingException("ASN1 decode error", e);
        }
    }

    private void decodePayload(Asn1Parser payloadParser, boolean isPseudonym) throws IOException {
        schemeVersion = payloadParser.readObject(ASN1Integer.class).getValue().intValue();
        schemeKeyVersion = payloadParser.readObject(ASN1Integer.class).getValue().intValue();
        creator = payloadParser.readObject(DERIA5String.class).getString();
        recipient = payloadParser.readObject(DERIA5String.class).getString();
        recipientKeySetVersion = payloadParser.readObject(ASN1Integer.class).getValue().intValue();

        if (isPseudonym) {
            final ASN1Encodable obj = payloadParser.readObject();
            if (obj instanceof DERIA5String) {
                diversifier = ((DERIA5String) obj).getString();
                type = (char) payloadParser.readObject(ASN1Integer.class).getValue().byteValue();
            } else {
                type = (char) Asn1Parser.checkObject(obj, ASN1Integer.class).getValue().byteValue();
            }
        }
        payloadParser.readObject(DERSequenceParser.class);

        points = new ECPoint[3];
        for (int i = 0; i < points.length; i++) {
            final DEROctetString octet =
                (DEROctetString) payloadParser.readObject(DEROctetStringParser.class).getLoadedObject();
            try {
                points[i] = BrainpoolP320r1.CURVE.decodePoint(octet.getOctets());
            } catch (IllegalArgumentException e) {
                throw new ParsingException("Could not decode point on curve", e);
            }
        }
    }

    private Signature decodeSignature() throws IOException {
        parser.readObject(DERSequenceParser.class);
        final String oid = parser.readObject(ASN1ObjectIdentifier.class).getId();
        if (!EC_SCHNORR_SHA384_OID.equals(oid)) {
            throw new ParsingException(String.format("Expected EC Schnorr SHA-384 signature, got %s", oid));
        }
        parser.readObject(DERSequenceParser.class);
        return new Signature(
            parser.readObject(ASN1Integer.class).getPositiveValue(),
            parser.readObject(ASN1Integer.class).getPositiveValue()
        );
    }

    public BsnkType getBsnkType() {
        return bsnkType;
    }

    public int getSchemeVersion() {
        return schemeVersion;
    }

    public int getSchemeKeyVersion() {
        return schemeKeyVersion;
    }

    public String getCreator() {
        return creator;
    }

    public String getRecipient() {
        return recipient;
    }

    public int getRecipientKeySetVersion() {
        return recipientKeySetVersion;
    }

    public String getDiversifier() {
        return diversifier;
    }

    public char getType() {
        return type;
    }

    public ECPoint[] getPoints() {
        return Arrays.copyOf(points, points.length);
    }
}
