import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ServerEncryption {
	
	private PrivateKey mpriv; //my private key
	private PublicKey mpub; //my public key, give to them
	private PublicKey tpub; //their public key
	private PublicKey ccpub; //their sign public key
	private String algorithm;
	private String blockseparator = "////";
	private SecretKey encryptsym;
	public SecretKey authsym;

	public ServerEncryption() {
	}
	
	public ServerEncryption(String alg) {
		this.algorithm = alg;
		generateKeys();
	}
	
	public void generateKeys() {
		try {
			if (!algIsSet()) {
				System.err.println("Could not generate keys as no algorithm was specified.");
	    		System.exit(1);
			}
			if (this.mpriv!=null && this.mpub!=null) {
				System.err.println("Keys have already been generated.");
				return;
			}
			
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");

			gen.initialize(1024);
			KeyPair pair = gen.generateKeyPair();
			this.mpriv = pair.getPrivate();
			this.mpub = pair.getPublic();
			
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error setting up encryption.\n"+e);
			System.exit(1);
		}
	}
	
	private int getBlockSize(String msg) {
		if (algorithm.equals("RSA")) return 117;
		else return msg.length();
	}
	
	public String getSessionKey() {
		return Base64.getEncoder().encodeToString(mpub.getEncoded()); //my public, to send to them
	}
	
	public String getSignatureKey() {
		return Base64.getEncoder().encodeToString(ccpub.getEncoded()); //client's ccpub
	}
	
	public String getCitizenCardAlg() {
		return this.ccpub.getAlgorithm();
	}
	
	public void setAlg(String alg) {
		this.algorithm = alg;
	}
	
	public void setEncryptionKey(String key) {
		try {
			byte[] b64 = Base64.getDecoder().decode(key);
			SecretKeySpec sks = new SecretKeySpec(b64, this.algorithm);
			this.encryptsym = sks;
			
		} catch (Exception e) {
			System.err.println("Error retrieving external public key.");
		}		
	}
	
	public void setAuthKey(String key) {
		try {
			byte[] b64 = Base64.getDecoder().decode(key);
			SecretKeySpec sks = new SecretKeySpec(b64, this.algorithm);
			this.authsym = sks;
			
		} catch (Exception e) {
			System.err.println("Error retrieving external public key.");
		}		
	}
	
	public void setExtPublicKey(String tpub) {
		try {
			byte[] b64 = Base64.getDecoder().decode(tpub);
			KeyFactory kf = KeyFactory.getInstance(algorithm);
			X509EncodedKeySpec ks = new X509EncodedKeySpec(b64);
			this.tpub = kf.generatePublic(ks);

		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			System.err.println("Error retrieving external public key.");
		}		
	}
	
	public void setSignatureKey(String ccpub) {
		try {
			byte[] b64 = Base64.getDecoder().decode(ccpub);
			KeyFactory kf = KeyFactory.getInstance(algorithm);
			X509EncodedKeySpec ks = new X509EncodedKeySpec(b64);
			this.ccpub = kf.generatePublic(ks);
			
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			System.err.println("Error retrieving signature public key.");
		}
	}
	
	public String getAlg() {
		return algorithm;
	}
	
	public String getBlockSeparator() {
		return blockseparator;
	}
	
	public boolean extPublicKeyIsSet() {
		if (this.tpub==null) return false;
		else return true;
	}
	
	public boolean algIsSet() {
		if (this.algorithm==null) return false;
		else return true;
	}

	public String authenticateMessage(String message) { //text string -> encrypted byte[] -> base64 string
	    try {
	    	if (!algIsSet()) {
	    		System.err.println("Could not encrypt as no encoding algorithm was specified.");
	    		System.exit(1);
	    	}
	    	
	    	String res = "";	   
	    	int pos = 0;
	    	int newpos = 0;
	    	Cipher cipher = Cipher.getInstance(algorithm);   
	    	if (this.algorithm.equals("RSA")) cipher.init(Cipher.ENCRYPT_MODE, mpriv);  
	    	else cipher.init(Cipher.ENCRYPT_MODE, authsym);
	    	Encoder e = Base64.getEncoder();
	    	
	    	while (pos<message.length()) {
	    		newpos = pos + getBlockSize(message);
	    		if (newpos>message.length()) newpos = message.length();
	    		byte[] b = cipher.doFinal(message.substring(pos, newpos).getBytes());
	    		res += e.encodeToString(b) + blockseparator;
	    		pos = newpos;
	    	}
	    	
	    	return res;
	    	
		} catch (Exception e) {
			System.err.println("Error authenticating message.");
			System.exit(1);
		}
	    return null;
	}
	
	public String validateMessage(String message) { //base64 string -> encrypted byte[] -> text string
	    try {
		    if (!algIsSet()) {
	    		System.err.println("Could not validate as no decoding algorithm was specified.");
	    		System.exit(1);
	    	}
	    
		    String[] blocks = message.split(blockseparator);
		    String res = "";
	    
	    	Cipher cipher = Cipher.getInstance(algorithm);   
	    	if (this.algorithm.equals("RSA")) cipher.init(Cipher.DECRYPT_MODE, tpub);  
	    	else cipher.init(Cipher.DECRYPT_MODE, authsym);
	    	Decoder d = Base64.getDecoder();
	    	for (String block: blocks) {
	    		byte[] b64 = d.decode(block);
	    		byte[] b = cipher.doFinal(b64);
	    		res += new String(b, StandardCharsets.ISO_8859_1);
	    	}
	    	
	    	return res;
	    	
		} catch (Exception e) {
			System.err.println("Error validating message.");
			e.printStackTrace();
			System.exit(1);
		}
	    return null;
	}
	
	public String encryptMessage(String message) { //text string -> encrypted byte[] -> base64 string
	    try {
	    	if (!extPublicKeyIsSet()) {
	    		System.err.println("Could not encrypt as there is no external public key.");
	    		System.exit(1);
	    	} else if (!algIsSet()) {
	    		System.err.println("Could not encrypt as no encoding algorithm was specified.");
	    		System.exit(1);
	    	}
	    	
	    	String res = "";	   
	    	int pos = 0;
	    	int newpos = 0;
	    	Cipher cipher = Cipher.getInstance(algorithm);   
	    	if (this.algorithm.equals("RSA")) cipher.init(Cipher.ENCRYPT_MODE, tpub);  
	    	else cipher.init(Cipher.ENCRYPT_MODE, encryptsym);
	    	Encoder e = Base64.getEncoder();
	    	
	    	while (pos<message.length()) {
	    		newpos = pos + getBlockSize(message);
	    		if (newpos>message.length()) newpos = message.length();
	    		byte[] b = cipher.doFinal(message.substring(pos, newpos).getBytes());
	    		res += e.encodeToString(b) + blockseparator;
	    		pos = newpos;
	    	}
	    	
	    	return res;
	    	
		} catch (Exception e) {
			System.err.println("Error encrypting message.");
			System.exit(1);
		}
	    return null;
	}
	
	public String decryptMessage(String message) { //base64 string -> encrypted byte[] -> text string
	    try {
		    if (!algIsSet()) {
	    		System.err.println("Could not decrypt as no decoding algorithm was specified.");
	    		System.exit(1);
	    	}
		    
		    String[] blocks = message.split(blockseparator);
		    String res = "";
	    
	    	Cipher cipher = Cipher.getInstance(algorithm);   
	    	if (this.algorithm.equals("RSA")) cipher.init(Cipher.DECRYPT_MODE, mpriv);  
	    	else cipher.init(Cipher.DECRYPT_MODE, encryptsym);
	    	Decoder d = Base64.getDecoder();
	    	for (String block: blocks) {
	    		byte[] b64 = d.decode(block);
	    		byte[] b = cipher.doFinal(b64);
	    		res += new String(b, StandardCharsets.ISO_8859_1);
	    	}
	    	
	    	return res;
	    	
		} catch (Exception e) {
			System.err.println("Error decrypting message.");
			System.exit(1);
		}
	    return null;
	}
	
}
