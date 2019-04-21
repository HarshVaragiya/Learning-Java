package helloworld;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import java.util.Base64;
import javax.crypto.spec.PBEKeySpec;

/**
 * @author Harsh Varagiya
 * RSA Class for Public Key Cryptography.
 *   -> Generation of Random/Deterministic RSA Keys
 *   -> Encryption/Decryption using RSA Keys
 */

public class RSA{
	
	// Class Variables
	private KeyPairGenerator keyGen;
	private KeyPair pair;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private Cipher cipher;
	
	/*
	 * Class Functions 
	 */
	
	//Constructor
	public RSA() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		this.cipher = Cipher.getInstance("RSA");
	}

	public void createKeys(int keylength) throws NoSuchAlgorithmException {
		this.keyGen = KeyPairGenerator.getInstance("RSA");
		this.keyGen.initialize(keylength);
		this.pair = this.keyGen.generateKeyPair();
		this.privateKey = pair.getPrivate();
		this.publicKey = pair.getPublic();
	}
	
	public byte[] DBSGF(String Data,byte[] salt) throws Exception {
		// Data Based Seed Generation Function 
		byte[] ret = hashPassword(Data.toCharArray(),salt,50000,512);
		return ret;
	}
	
	public byte[] hashPassword(final char[] password, final byte[] salt, final int iterations, final int keyLength) throws Exception {
            SecretKeyFactory skf = SecretKeyFactory.getInstance( "PBKDF2WithHmacSHA512" );
            PBEKeySpec specs = new PBEKeySpec( password, salt, iterations, keyLength);
            SecretKey key = skf.generateSecret(specs);
            byte[] res = key.getEncoded();
            System.out.println("Seed Data : " + (Base64.getEncoder().encodeToString(res)));
            return res;
	}
	
	public void createDeterministicKeys(int keylength,String password,String salt) throws Exception{
		SecureRandom not_random=SecureRandom.getInstance("SHA1PRNG");
		not_random.setSeed(DBSGF(password,salt.getBytes()));
		this.keyGen=KeyPairGenerator.getInstance("RSA");
		this.keyGen.initialize(keylength, not_random);
		this.pair=keyGen.generateKeyPair();
		this.publicKey = this.pair.getPublic();
		this.privateKey = this.pair.getPrivate();
	}
	
	public String getPrivateKey() {
		return Base64.getEncoder().encodeToString((this.privateKey.getEncoded()));
	}
	public String getPublicKey() {
		return Base64.getEncoder().encodeToString((this.publicKey.getEncoded()));
	}
	
	public String DecryptText(String cipherText) throws Exception {
		cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
	    return new String(cipher.doFinal(Base64.getDecoder().decode(cipherText)),"UTF-8");
	}
	
	public String EncryptText(String plainText) throws Exception {
		cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
	    return Base64.getEncoder().encodeToString((cipher.doFinal(plainText.getBytes("UTF-8"))));
	}
	
	private void writeOnDisk(String path, byte[] key) throws IOException {
		File f = new File(path);
		f.getParentFile().mkdirs();
		FileOutputStream fos = new FileOutputStream(f);
		fos.write(key);
		fos.flush();
		fos.close();
	}
	
	public void SaveKeys(String private_path,String public_path) throws IOException{
		this.writeOnDisk(private_path, this.privateKey.getEncoded());
		this.writeOnDisk(public_path, this.publicKey.getEncoded());
	}
	
	public void importPrivateKey(String privateKeyFile) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(privateKeyFile).toPath());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		this.privateKey =  kf.generatePrivate(spec);
	}

	public void importPublicKey(String publicKeyFile) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(publicKeyFile).toPath());
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		this.publicKey =  kf.generatePublic(spec);	
	}
	
	public void importKeys(String publicPath,String privatePath)throws Exception {
		this.importPublicKey(publicPath);
		this.importPrivateKey(privatePath);
	}
	
	public boolean CanEncrypt() {
		if(this.publicKey != null)return true;
		else return false;
	}
	public boolean CanDecrypt() {
		if(this.privateKey != null)return true;
		else return false;
	}
	
	/*
	public boolean CanVerify() {
		if(this.publicKey != null)return true;
		else return false;
	}
	public boolean CanSign() {
		if(this.privateKey != null)return true;
		else return false;
	}
	*/
}
