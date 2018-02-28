/*
 * This source code is protected by the EUPL version 1.2 and is part of the "PP Decrypt" example package.
 * 
 * Copyright: Logius (2018)
 * @author: Bram van Pelt 
 */

package nl.logius.resource.example;


import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import nl.logius.resource.pp.crypto.CMS;
import nl.logius.resource.pp.key.DecryptKey;
import nl.logius.resource.pp.key.EncryptedVerifiers;
import nl.logius.resource.pp.key.IdentityDecryptKey;
import nl.logius.resource.pp.key.PseudonymClosingKey;
import nl.logius.resource.pp.key.PseudonymDecryptKey;

public class keyUtil {
	
	private IdentityDecryptKey decryptKey;
	private EncryptedVerifiers verifiers;
	private EncryptedVerifiers pVerifiers;
	private PseudonymDecryptKey pDecryptKey;
	private PseudonymClosingKey pClosingKey;
	private String IDENTITY_POINT = "AmUppru04ghsI/FvbvV59eoX3lCUWlMAZKu1pPdlvixch5avV+aFwQg=";
	private String PSEUDONYM_POINT = "A9GtKDUn++nl2NWtN4F/2id1gmBhxn4I6Qr9BfeMN+fjNuXGvE79qHc=";
	
	public keyUtil()
	{
         getIdentityKeys();
         getPseudoKeys();
	}
	
	private void getIdentityKeys()
	{
        // Convert P7 key to PEM
        try (final InputStream is = new FileInputStream("F:\\workspace\\PP-Decrypt_ExamplePackage\\bin\\resources\\"+ "p7\\ID-4.p7")) {
            String identityKeyPem = CMS.read(getPrivateKey(), is);
            // Convert PEM to IdentityDecryptKey
            decryptKey = DecryptKey.fromPem(identityKeyPem, IdentityDecryptKey.class);
            // Derive verifier (for signature verifying) from key
            verifiers = decryptKey.toVerifiers(IDENTITY_POINT);
        }        
        catch (Exception e) {
			// TODO: handle exception
		}
	}
	
	private void getPseudoKeys()
	{   
        try (final InputStream is = new FileInputStream("F:\\workspace\\PP-Decrypt_ExamplePackage\\bin\\resources\\"+ "p7\\PD-4.p7")) {
        	String pseudoKeyPem = CMS.read(getPrivateKey(), is);
            // Convert PEM to IdentityDecryptKey
        	pDecryptKey = DecryptKey.fromPem(pseudoKeyPem, PseudonymDecryptKey.class);
            // Derive verifier (for signature verifying) from key
            pVerifiers = pDecryptKey.toVerifiers(PSEUDONYM_POINT);
        }        
        catch (Exception e) {
			// TODO: handle exception
		}
        
        try (final InputStream is = new FileInputStream("F:\\workspace\\PP-Decrypt_ExamplePackage\\bin\\resources\\"+ "p7\\PC-4.p7")) {
        	String pseudoClosingKeyPem = CMS.read(getPrivateKey(), is);
            // Convert PEM to IdentityDecryptKey
        	pClosingKey = DecryptKey.fromPem(pseudoClosingKeyPem, PseudonymClosingKey.class);
        }        
        catch (Exception e) {
			// TODO: handle exception
		}
	}
	
	private static PrivateKey getPrivateKey() throws Exception {
		
		File file = new File("F:\\workspace\\PP-Decrypt_ExamplePackage\\bin\\resources\\"+ "private.p8");
    	//init array with file length
    	byte[] bytesArray = new byte[(int) file.length()];

    	FileInputStream fis = new FileInputStream(file);
    	fis.read(bytesArray); //read file into bytes[]
    	fis.close();
		
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytesArray));
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
