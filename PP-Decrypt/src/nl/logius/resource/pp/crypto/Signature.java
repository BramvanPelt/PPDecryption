/*
 *  This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" library.
 * SPDX-Licence-Identifier: EUPL-1.2
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */
package nl.logius.resource.pp.crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;

import org.bouncycastle.math.ec.ECPoint;

public class Signature {
    private final BigInteger r;
    private final BigInteger s;
    private static final String EC_SCHNORR_SHA384_OID = "0.4.0.127.0.7.1.1.4.3.3";
    private static final String EC_SDSA_SHA384_OID = "1.0.14888.3.0.11";

    public Signature(BigInteger r, BigInteger s) {
        this.r = r;
        this.s = s;
    }

    public void verify(ECPoint publicKey, ECPoint G, byte[] message, String SchnorrSignOid) 
    {
    	if(SchnorrSignOid.equals(EC_SCHNORR_SHA384_OID))
    	{
    		verifyEcSchnorr(publicKey, G, message);
    	}
    	else if (SchnorrSignOid.equals(EC_SDSA_SHA384_OID))
    	{
    		verifyEcSdsa(publicKey, G, message);
    	}
    	else
    	{
    		 throw new CryptoException("Invalid signature, signature algoritm not implemented");
    	}
    }
    
    private void verifyEcSchnorr(ECPoint publicKey, ECPoint G, byte[] message)
    {
    	//Step 1: check if r and s meet imput requirements
        if (r.bitCount() > 320 || r.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(BrainpoolP320r1.Q) >= 0) {
            throw new CryptoException("Invalid signature");
        }
             
        //Step 2 en 3: calculate points on curve
        final ECPoint q = G.multiply(s).add(publicKey.multiply(r)).normalize();
        if (q.isInfinity()) {
            throw new CryptoException("Invalid signature");
        }
        
        //Step 4: Generate message digest and and apply points on curve --- BSI 2012 verification:
        final MessageDigest md = SHA384.getInstance();
        md.update(message); 
        md.update(q.getAffineXCoord().getEncoded());
        
        final byte[] hash = Arrays.copyOfRange(md.digest(), 0, 40); // Use only 320 MSB
        final BigInteger v = new BigInteger(1, hash);
        
        //Step 5 Check if the signatures match
        if (!r.equals(v)) {
            throw new CryptoException("Invalid signature");
        }
    }
    
    private void verifyEcSdsa(ECPoint publicKey, ECPoint G, byte[] message)
    {
    	//Step 1: check if r and s meet imput requirements
        if (r.bitCount() > 320 || r.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(BrainpoolP320r1.Q) >= 0) {
            throw new CryptoException("Invalid signature");
        }
             
        //Step 2 en 3: calculate points on curve
        final ECPoint q = G.multiply(s).subtract(publicKey.multiply(r)).normalize();
        if (q.isInfinity()) {
            throw new CryptoException("Invalid signature");
        }

        //Step 4: Generate message digest and and apply points on curve --- ECSDSA  verification:
        final MessageDigest md = SHA384.getInstance();
        md.update(q.getAffineXCoord().getEncoded());
        md.update(q.getAffineYCoord().getEncoded());
        md.update(message);
        
        final byte[] hash = Arrays.copyOfRange(md.digest(), 0, 40); // Use only 320 MSB
        final BigInteger v = new BigInteger(1, hash);
        
        //Step 5 Check if the signatures match
        if (!r.equals(v)) {
            throw new CryptoException("Invalid signature");
        }
    }
    
}
