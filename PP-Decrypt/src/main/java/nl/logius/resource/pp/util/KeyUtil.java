/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" example package.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */

package nl.logius.resource.pp.util;


import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import nl.logius.resource.pp.crypto.CMS;
import nl.logius.resource.pp.key.DecryptKey;
import nl.logius.resource.pp.key.EncryptedVerifiers;
import nl.logius.resource.pp.key.IdentityDecryptKey;
import nl.logius.resource.pp.key.PseudonymClosingKey;
import nl.logius.resource.pp.key.PseudonymDecryptKey;

public class KeyUtil {
	
	private IdentityDecryptKey decryptKey;
	private EncryptedVerifiers verifiers;
	private EncryptedVerifiers pVerifiers;
	private PseudonymDecryptKey pDecryptKey;
	private PseudonymClosingKey pClosingKey;
	private String identityKeyLocation;
	private String pseudoKeyLocation;
	private String pseudoClosingKeyLocation;
	private String privatep8;
	
	private String identityPoint;
	private String pseudonymPoint;
	
	/**
	 * @return the identityPoint
	 */
	public String getIdentityPoint() {
		return identityPoint;
	}

	/**
	 * @param identityPoint the identityPoint to set
	 */
	public void setIdentityPoint(String identityPoint) {
		this.identityPoint = identityPoint;
	}

	/**
	 * @return the pseudonymPoint
	 */
	public String getPseudonymPoint() {
		return pseudonymPoint;
	}

	/**
	 * @param pseudonymPoint the pseudonymPoint to set
	 */
	public void setPseudonymPoint(String pseudonymPoint) {
		this.pseudonymPoint = pseudonymPoint;
	}

	/**
	 * @return the privatep8
	 */
	public String getPrivatep8() {
		return privatep8;
	}

	/**
	 * @param privatep8 the privatep8 to set
	 */
	public void setPrivatep8(String privatep8) {
		this.privatep8 = privatep8;
	}

	/**
	 * @return the identityKeyLocation
	 */
	public String getIdentityKeyLocation() {
		return identityKeyLocation;
	}

	/**
	 * @param identityKeyLocation the identityKeyLocation to set
	 */
	public void setIdentityKeyLocation(String identityKeyLocation) {
		this.identityKeyLocation = identityKeyLocation;
	}

	/**
	 * @return the pseudoKeyLocation
	 */
	public String getPseudoKeyLocation() {
		return pseudoKeyLocation;
	}

	/**
	 * @param pseudoKeyLocation the pseudoKeyLocation to set
	 */
	public void setPseudoKeyLocation(String pseudoKeyLocation) {
		this.pseudoKeyLocation = pseudoKeyLocation;
	}

	/**
	 * @return the pseudoClosingKeyLocation
	 */
	public String getPseudoClosingKeyLocation() {
		return pseudoClosingKeyLocation;
	}

	/**
	 * @param pseudoClosingKeyLocation the pseudoClosingKeyLocation to set
	 */
	public void setPseudoClosingKeyLocation(String pseudoClosingKeyLocation) {
		this.pseudoClosingKeyLocation = pseudoClosingKeyLocation;
	}

	public KeyUtil(String identityKeyLocation, String pseudoKeyLocation, String pseudoClosingKeyLocation) throws Exception {
		this.identityKeyLocation = identityKeyLocation;
		this.pseudoKeyLocation = pseudoKeyLocation;
		this.pseudoClosingKeyLocation = pseudoClosingKeyLocation;
		init();
	}
	public KeyUtil() {
        
	}
	public void init() throws Exception {
		 getIdentityKeys();
         getPseudoKeys();
	}
	private void getIdentityKeys() throws Exception
	{
        // Convert P7 key to PEM
        try (final InputStream is = new FileInputStream(identityKeyLocation)) {
            String identityKeyPem = CMS.read(getPrivateKey(), is);
            // Convert PEM to IdentityDecryptKey
            decryptKey = DecryptKey.fromPem(identityKeyPem, IdentityDecryptKey.class);
            // Derive verifier (for signature verifying) from key
            verifiers = decryptKey.toVerifiers(identityPoint);
        }        
        catch (Exception e) {
        	throw new Exception("Unable to read identity key", e);
		}
	}
	
	private void getPseudoKeys() throws Exception
	{   
        try (final InputStream is = new FileInputStream(pseudoKeyLocation)) {
        	String pseudoKeyPem = CMS.read(getPrivateKey(), is);
            // Convert PEM to IdentityDecryptKey
        	pDecryptKey = DecryptKey.fromPem(pseudoKeyPem, PseudonymDecryptKey.class);
            // Derive verifier (for signature verifying) from key
            pVerifiers = pDecryptKey.toVerifiers(pseudonymPoint);
        }        
        catch (Exception e) {
        	throw new Exception("Unable to read pseudo key", e);
		}
        
        try (final InputStream is = new FileInputStream(pseudoClosingKeyLocation)) {
        	String pseudoClosingKeyPem = CMS.read(getPrivateKey(), is);
            // Convert PEM to IdentityDecryptKey
        	pClosingKey = DecryptKey.fromPem(pseudoClosingKeyPem, PseudonymClosingKey.class);
        }        
        catch (Exception e) {
        	throw new Exception("Unable to read pseudo closing key", e);
		}
	}
	
	private PrivateKey getPrivateKey() throws Exception {
		File file = Paths.get(this.privatep8).toFile();
		byte[] fileBytes = null;
	    try
	    {
	        fileBytes = Files.readAllBytes(file.toPath());
	    }
	    catch (Exception ex) 
	    {
	        throw new Exception("Unable to read private key", ex);
	    }
		
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(fileBytes));
    }
		
	public IdentityDecryptKey getDecryptKey()
	{
		return decryptKey;
	}
	
	public EncryptedVerifiers getVerifiers()
	{
		return verifiers;
	}
	
	public EncryptedVerifiers getPVerifiers()
	{
		return pVerifiers;
	}
	
	public PseudonymDecryptKey getPDecryptKey()
	{
		return pDecryptKey;
	}
	
	public PseudonymClosingKey getPClosingKey()
	{
		return pClosingKey;
	}
}
