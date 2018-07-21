import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class AES{
	
    private byte[] key;
    private SecretKeySpec secretKey;
    private Cipher cipher;
    
    public AES(byte[] key)throws Exception{
        this.key = key;
        this.secretKey = new SecretKeySpec(this.key,"AES");
        this.cipher = Cipher.getInstance("AES");
        }    
    
    public byte[] getkey() {
    	return this.key;
    }
    
    public String EncryptString(String plainText) throws Exception{
        this.cipher.init(Cipher.ENCRYPT_MODE, this.secretKey);
        byte[] inputBytes = plainText.getBytes();
        byte[] encrypted  = cipher.doFinal(inputBytes);
        return Base64.encodeBase64String(encrypted);
    }
    
    public String DecryptString(String cipherText) throws Exception{
        this.cipher.init(Cipher.DECRYPT_MODE, this.secretKey);
        byte[] inputBytes = Base64.decodeBase64(cipherText);
        byte[] decrypted  = cipher.doFinal(inputBytes);
        return new String(decrypted);
    }
    
    public static void main(String[] args) throws Exception {
    	System.out.print("Enter Key to be hashed : ");
    	Scanner cin = new Scanner(System.in);
    	String password = cin.nextLine();
    	Hashlib Hasher = new Hashlib();
    	AES aes = new AES(Hasher.sha256(password));
    	System.out.println(aes.getkey());
    	System.out.println("Enter to Encrypt : ");
    	String plainText = cin.nextLine();
    	String cipherText = aes.EncryptString(plainText);
    	System.out.println(cipherText);
    	System.out.println("Enter to Decrypt : ");
    	cipherText = cin.nextLine();
    	plainText = aes.DecryptString(cipherText);
    	System.out.println(plainText);    
    	cin.close();
    	}
}
