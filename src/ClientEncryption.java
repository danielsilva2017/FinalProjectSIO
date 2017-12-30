import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Calendar;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class ClientEncryption {
	
	private PrivateKey mpriv; //my private session key
	private PublicKey mpub; //my public session key, give to them
	private PublicKey tpub; //their public key
	private String algorithm;
	private SecretKey encryptsym;
	private SecretKey authsym;
	
	private PublicKey ccpub; //my cc sign public key
	private PrivateKey ccpriv; //my cc sign private key
	
	private PublicKey extrapub;
	private PrivateKey extrapriv;
	private String extraalgorithm;
	
	private String blockseparator = "////";	
	
	private String password;
	private SecretKey special;
	
	//citizen card is required for login
	
	//communication with the server (auth/encrypt) is dictated by 'algorithm'
	//everything else defaults to RSA
	
	public ClientEncryption(String alg) {
		this.algorithm = alg;
		generateKeys();
		readCitizenCard();
	}
	
	private void generateKeys() {
		try {
			if (!algIsSet()) {
				System.out.println("Could not generate keys as no algorithm was specified.");
	    		System.exit(1);
			}
			if (this.mpriv!=null && this.mpub!=null) {
				System.out.println("Keys have already been generated.");
				return;
			}
			
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");

			gen.initialize(getKeySize("RSA"));
			KeyPair pair = gen.generateKeyPair();
			this.mpriv = pair.getPrivate();
			this.mpub = pair.getPublic();
			
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error setting up encryption.\n"+e);
			System.exit(1);
		}
	}
	
	public void generateSymKeys(String alg) {
		try {
			if (!algIsSet()) {
				System.out.println("Could not generate keys as no algorithm was specified.");
	    		System.exit(1);
			}
			if (this.encryptsym!=null && this.authsym!=null) {
				System.out.println("Keys have already been generated.");
				return;
			}
			
			KeyGenerator gen = KeyGenerator.getInstance(alg);

			gen.init(getKeySize(alg));
			this.encryptsym = gen.generateKey();
			this.authsym = gen.generateKey();
			
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error setting up encryption.\n"+e);
			System.exit(1);
		}
	}
	
	public void generateExtraKeys() {
		try {
			if (!algIsSet()) {
				System.out.println("Could not generate a 2nd key pair as no algorithm was specified.");
	    		System.exit(1);
			}
			if (!extraAlgIsSet()) {
				this.extraalgorithm = "RSA";
			}
			if (extraKeysAreSet()) {
				System.out.println("Keys have already been generated.");
				return;
			}
			
			KeyPairGenerator gen = KeyPairGenerator.getInstance(this.extraalgorithm);

			gen.initialize(1024);
			KeyPair pair = gen.generateKeyPair();
			this.extrapriv = pair.getPrivate();
			this.extrapub = pair.getPublic();
			
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error setting up encryption.\n"+e);
			System.exit(1);
		}
	}
	
	public String getPasswordKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); //works with any size
		KeySpec ks = new PBEKeySpec(password.toCharArray(), password.getBytes(), 20, getKeySize("AES")); //we thought 20 iterations would suffice
		SecretKey tmp = factory.generateSecret(ks);
		this.special = new SecretKeySpec(tmp.getEncoded(), "AES");
		return Base64.getEncoder().encodeToString(this.special.getEncoded());
	}
	
	private int getBlockSize(String msg) {
		if (algorithm.equals("RSA")) return 117;
		else return msg.length();
	}
	
	private int getKeySize(String algorithm) {
		if (algorithm.equals("RSA")) return 1024;
		else if (algorithm.equals("AES")) return 128;
		else return 56;
	}
	
	public void setPassword(String p) throws NoSuchAlgorithmException, InvalidKeySpecException {
		password=p;
		getPasswordKey();
	}
	
	public void recoverExtraKeys(String alg, String pub, String priv) {
		try {
			this.extraalgorithm = alg;
			
			KeyFactory kf = KeyFactory.getInstance(alg);
			
			byte[] b64 = Base64.getDecoder().decode(pub);			
			X509EncodedKeySpec ks = new X509EncodedKeySpec(b64);
			this.extrapub = kf.generatePublic(ks);
			  	
	    	Cipher cipher = Cipher.getInstance("AES");   
	    	cipher.init(Cipher.DECRYPT_MODE, this.special); 
	    	byte[] b = cipher.doFinal(Base64.getDecoder().decode(priv));
	    	String realpriv = new String(b, StandardCharsets.ISO_8859_1);
			
	    	byte[] b64_2 = Base64.getDecoder().decode(realpriv);
			PKCS8EncodedKeySpec eks = new PKCS8EncodedKeySpec(b64_2);
			this.extrapriv = kf.generatePrivate(eks);
			
		} catch (Exception e) {
			System.out.println("Error retrieving 2nd key pair.");
		}	
	}
	
	public boolean testRecovery(String pword, String priv) {
		try {
			setPassword(pword);
			Cipher cipher = Cipher.getInstance("AES");   
			cipher.init(Cipher.DECRYPT_MODE, this.special); 
			cipher.doFinal(Base64.getDecoder().decode(priv));
			return true;
		} catch (Exception e) {
			return false;
		}	
	}
	
	public String recover2ndPrivateKey(String priv) {
		try {
			Cipher cipher = Cipher.getInstance("AES");   
	    	cipher.init(Cipher.DECRYPT_MODE, this.special); 
	    	byte[] b = cipher.doFinal(Base64.getDecoder().decode(priv));
	    	return new String(b, StandardCharsets.ISO_8859_1);
		} catch (Exception e) {
			System.out.println("Error retrieving 2nd private key.");
			e.printStackTrace();
			System.exit(1);
		}
		return null;
	}
	
	private void readCitizenCard() {
		try {
			Provider prov = Security.getProvider("SunPKCS11-CartaoCidadao");
			
			KeyStore ks = KeyStore.getInstance("PKCS11", prov);
		    ks.load(null,null);

		    X509Certificate cert = (X509Certificate) ks.getCertificate("CITIZEN AUTHENTICATION CERTIFICATE");
		    cert.checkValidity(Calendar.getInstance().getTime());
		    this.ccpub = cert.getPublicKey();
		    
		    PrivateKeyEntry pkEntry = (PrivateKeyEntry) ks.getEntry("CITIZEN AUTHENTICATION CERTIFICATE", null);
		    PrivateKey ccpriv = pkEntry.getPrivateKey();
		    this.ccpriv = ccpriv;
		    
		} catch (Exception e) {
			System.out.println("Error reading citizen card: "+e.toString());
			System.exit(1);
		}
	}
	
	public String getSessionKey() {
		return Base64.getEncoder().encodeToString(mpub.getEncoded()); //my public, to send to them
	}
	
	public String getEncryptSessionKey() {
		return Base64.getEncoder().encodeToString(encryptsym.getEncoded());
	}
	
	public String getAuthSessionKey() {
		return Base64.getEncoder().encodeToString(authsym.getEncoded());
	}
	
	public String getSignatureKey() {
		return Base64.getEncoder().encodeToString(ccpub.getEncoded()); //my ccpub, to send to them
	}
	
	public String get2ndPublicKey() {
		return Base64.getEncoder().encodeToString(extrapub.getEncoded());
	}
	
	private String get2ndPrivateKey() {
		return Base64.getEncoder().encodeToString(extrapriv.getEncoded());
	}
	
	public String getEncripted2ndPrivateKey() {
		return Base64.getEncoder().encodeToString(extrapriv.getEncoded());
	}
	
	public String getEncrypted2ndPrivateKey() { 
	    try {    	
	    	Cipher cipher = Cipher.getInstance("AES");   
	    	cipher.init(Cipher.ENCRYPT_MODE, this.special); 
	    	byte[] b = cipher.doFinal(get2ndPrivateKey().getBytes());
	    	return Base64.getEncoder().encodeToString(b);
	    	
		} catch (Exception e) {
			System.out.println("Error encrypting 2nd private key.");
			System.exit(1);
		}
	    return null;
	}
	
	public void setAlg(String alg) {
		this.algorithm = alg;
	}
	
	public void setExtPublicKey(String tpub) { //RSA only
		try {
			byte[] b64 = Base64.getDecoder().decode(tpub);
			KeyFactory kf = KeyFactory.getInstance(algorithm);
			X509EncodedKeySpec ks = new X509EncodedKeySpec(b64);
			this.tpub = kf.generatePublic(ks);
			
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			System.out.println("Error retrieving external public key.");
		}		
	}
	
	public String getAlg() {
		return algorithm;
	}
	
	public String getBlockSeparator() {
		return blockseparator;
	}
	
	public boolean extPublicKeyIsSet() {
		return this.tpub!=null;
	}
	
	public boolean algIsSet() {
		return this.algorithm!=null;
	}
	
	public boolean extraAlgIsSet() {
		return this.extraalgorithm!=null;
	}
	
	public boolean extraKeysAreSet() {
		return this.extrapriv!=null && this.extrapub!=null;
	}
	
	public String getCitizenCardAlg() {
		return this.ccpub.getAlgorithm();
	}
	
	public String generateDigest() throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA");
	    md.update(ccpub.getEncoded());
	    byte[] d = md.digest();
	    return Base64.getEncoder().encodeToString(d);
	}
	
	public String signMessage(String message) { //message string -> base64 signature
		try {
			Signature sobj = Signature.getInstance("SHA1withRSA");
			sobj.initSign(this.ccpriv);
			sobj.update(message.getBytes());
			byte[] sig = sobj.sign();
			return Base64.getEncoder().encodeToString(sig);
			
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		} 
		
		return null;
	}
	
	public boolean verifySign(String alg, String key, String message, String sign) { //message string, base64 sign -> boolean
		try {
			Decoder dec = Base64.getDecoder();
			byte[] b64sign = dec.decode(sign);			
			byte[] b64key = dec.decode(key);
			
			KeyFactory kf = KeyFactory.getInstance(alg);
			X509EncodedKeySpec ks = new X509EncodedKeySpec(b64key);
			PublicKey senderpub = kf.generatePublic(ks);
	    	
			Signature sobj = Signature.getInstance("SHA1withRSA");
			sobj.initVerify(senderpub);
			sobj.update(message.getBytes());
			return sobj.verify(b64sign);
					
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
		
		return false;
	}
	
	public String authenticateMessage(String message) { //text string -> encrypted byte[] -> base64 string
	    try {
	    	if (!algIsSet()) {
	    		System.out.println("Could not encrypt as no encoding algorithm was specified.");
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
			System.out.println("Error authenticating message.");
			e.printStackTrace();
			System.exit(1);
		}
	    return null;
	}
	
	public String validateMessage(String message) { //base64 string -> encrypted byte[] -> text string
	    try {
		    if (!algIsSet()) {
	    		System.out.println("Could not validate as no decoding algorithm was specified.");
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
			System.out.println("Error validating message.");
			e.printStackTrace();
			System.exit(1);
		}
	    return null;
	}
	
	public String encryptMessage(String message) { //text string -> encrypted byte[] -> base64 string
	    try {
	    	if (this.algorithm.equals("RSA") && !extPublicKeyIsSet()) {
	    		System.out.println("Could not encrypt as there is no external public key.");
	    		System.exit(1);
	    	} else if (!algIsSet()) {
	    		System.out.println("Could not encrypt as no encoding algorithm was specified.");
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
			System.out.println("Error encrypting message.");
			System.exit(1);
		}
	    return null;
	}
	
	public String encryptWith2ndPublic(String message) { //text string -> encrypted byte[] -> base64 string
	    try {
	    	if (!extraAlgIsSet()) {
	    		System.out.println("Could not encrypt as no encoding algorithm was specified.");
	    		System.exit(1);
	    	} else if (!extraKeysAreSet()) {
	    		System.out.println("Could not encrypt as the 2nd key pair was not set.");
	    		System.exit(1);
	    	}
	    	
	    	String res = "";	   
	    	int pos = 0;
	    	int newpos = 0;
	    	Cipher cipher = Cipher.getInstance("RSA");   
	    	cipher.init(Cipher.ENCRYPT_MODE, extrapub);  
	    	Encoder e = Base64.getEncoder();
	    	
	    	while (pos<message.length()) {
	    		newpos = pos + 117;
	    		if (newpos>message.length()) newpos = message.length();
	    		byte[] b = cipher.doFinal(message.substring(pos, newpos).getBytes());
	    		res += e.encodeToString(b) + blockseparator;
	    		pos = newpos;
	    	}
	    	
	    	return res;
	    	
		} catch (Exception e) {
			System.out.println("Error encrypting message.");
			System.exit(1);
		}
	    return null;
	}
	
	public String decryptMessage(String message) { //base64 string -> encrypted byte[] -> text string
	    try {
		    if (!algIsSet()) {
	    		System.out.println("Could not decrypt as no decoding algorithm was specified.");
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
			System.out.println("Error decrypting message.");
			System.exit(1);
		}
	    return null;
	}
	
	public String decryptWith2ndPrivate(String message) { //base64 string -> encrypted byte[] -> text string
	    try {
		    if (!extraAlgIsSet()) {
	    		System.out.println("Could not decrypt as no decoding algorithm was specified.");
	    		System.exit(1);
		    } else if (!extraKeysAreSet()) {
	    		System.out.println("Could not decrypt as the 2nd key pair was not set.");
	    		System.exit(1);
	    	}
		    
		    String[] blocks = message.split(blockseparator);
		    String res = "";
	    
	    	Cipher cipher = Cipher.getInstance(extraalgorithm);   
	    	cipher.init(Cipher.DECRYPT_MODE, extrapriv);  
	    	Decoder d = Base64.getDecoder();
	    	for (String block: blocks) {
	    		byte[] b64 = d.decode(block);
	    		byte[] b = cipher.doFinal(b64);
	    		res += new String(b, StandardCharsets.ISO_8859_1);
	    	}
	    	
	    	return res;
	    	
		} catch (Exception e) {
			System.out.println("Error decrypting message.");
			System.exit(1);
		}
	    return null;
	}
	
	public String encryptMessageCopy(String message) { //text string -> encrypted byte[] -> base64 string
	    try {
	    	
	    	String res = "";	   
	    	int pos = 0;
	    	int newpos = 0;
	    	Cipher cipher = Cipher.getInstance(extraalgorithm);   
	    	cipher.init(Cipher.ENCRYPT_MODE, extrapub);  
	    	Encoder e = Base64.getEncoder();
	    	
	    	while (pos<message.length()) {
	    		newpos = pos + 117;
	    		if (newpos>message.length()) newpos = message.length();
	    		byte[] b = cipher.doFinal(message.substring(pos, newpos).getBytes());
	    		res += e.encodeToString(b) + blockseparator;
	    		pos = newpos;
	    	}
	    	
	    	return res;
	    	
		} catch (Exception e) {
			System.out.println("Error encrypting message.");
			System.exit(1);
		}
	    return null;
	}
	
	public String encryptWithSpecificKey(String alg, String key, String message) { //text string -> encrypted byte[] -> base64 string
	    try {
	    	
	    	byte[] b64 = Base64.getDecoder().decode(key);
			KeyFactory kf = KeyFactory.getInstance(alg);
			X509EncodedKeySpec ks = new X509EncodedKeySpec(b64);
			PublicKey pub = kf.generatePublic(ks);
	    	
	    	String res = "";	   
	    	int pos = 0;
	    	int newpos = 0;
	    	Cipher cipher = Cipher.getInstance(alg);   
	    	cipher.init(Cipher.ENCRYPT_MODE, pub);  
	    	Encoder e = Base64.getEncoder();
	    	
	    	while (pos<message.length()) {
	    		newpos = pos + 117;
	    		if (newpos>message.length()) newpos = message.length();
	    		byte[] b = cipher.doFinal(message.substring(pos, newpos).getBytes());
	    		res += e.encodeToString(b) + blockseparator;
	    		pos = newpos;
	    	}
	    	
	    	return res;
	    	
		} catch (Exception e) {
			System.out.println("Error encrypting message.");
			System.exit(1);
		}
	    return null;
	}
	
	public String decryptMessageCopy(String message) { //base64 string -> encrypted byte[] -> text string
	    try {
		    
		    String[] blocks = message.split(blockseparator);
		    String res = "";
	    
	    	Cipher cipher = Cipher.getInstance(extraalgorithm);   
	    	cipher.init(Cipher.DECRYPT_MODE, extrapriv);  
	    	Decoder d = Base64.getDecoder();
	    	for (String block: blocks) {
	    		byte[] b64 = d.decode(block);
	    		byte[] b = cipher.doFinal(b64);
	    		res += new String(b, StandardCharsets.ISO_8859_1);
	    	}
	    	
	    	return res;
	    	
		} catch (Exception e) {
			System.out.println("Error decrypting message.");
			System.exit(1);
		}
	    return null;
	}
}
