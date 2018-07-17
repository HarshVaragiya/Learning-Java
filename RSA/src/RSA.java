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
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

/**
 * @author Harsh Varagiya
 * RSA Class for Asymmetric Key Cryptography
 * To implement RSA And to Encrypt Data,Decrypt Data, or Generate RSA Keys.
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
	public void showPrivateKey() {
		System.out.println(Base64.encodeBase64String(this.privateKey.getEncoded()));
	}
	public void showPublicKey() {
		System.out.println(Base64.encodeBase64String(this.publicKey.getEncoded()));
	}
	
	public String DecryptText(String cipherText) throws Exception {
		cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
	    return new String(cipher.doFinal(Base64.decodeBase64(cipherText)), "UTF-8");
	}
	
	public String EncryptText(String plainText) throws Exception {
		cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
	    byte[] cipherText = cipher.doFinal(plainText.getBytes());
	    return Base64.encodeBase64String(cipher.doFinal(plainText.getBytes("UTF-8")));
	}
	
	private void writeOnDisk(String path, byte[] key) throws IOException {
		File f = new File(path);
		f.getParentFile().mkdirs();
		FileOutputStream fos = new FileOutputStream(f);
		fos.write(key);
		fos.flush();
		fos.close();
	}
	
	public void SaveKeys(String path) throws IOException{
		String private_path = path + "/PrivateKey";
		String public_path  = path + "/PublicKey";
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
	
    // Main  
	
	public static void main(String[] args) throws Exception { //Too many Exceptions to Write ! LAZY AF
		
		RSA keyOne;
		keyOne = new RSA();
		
		keyOne.createKeys(1024);                 // 1024 Bits is Good Enough
		keyOne.SaveKeys("RSA");                  // Path = /RSA/Keys
		
		//keyOne.importKeys(new String("RSA/publickey"), new String("RSA/privatekey"));
		
		//keyOne.importPublicKey(new String("RSA/publickey"));
		System.out.print("Public Key  : ");keyOne.showPublicKey();
		//keyOne.importPrivateKey(new String("RSA/privatekey"));
		System.out.print("Private Key : ");keyOne.showPrivateKey();
		
		String str = "Test Something Out Here ! ";
		String enc = keyOne.EncryptText(str); 
		System.out.println("Cipher Text : " + enc);
		String ret = keyOne.DecryptText(enc);
		System.out.println("Plain Text  : " + ret);
	}

}
