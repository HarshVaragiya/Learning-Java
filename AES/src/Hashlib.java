import org.apache.commons.codec.digest.DigestUtils;

public class Hashlib {
	
	public byte[] sha256(String Str) {              // SHA256 
    	return hexStringToByteArray(DigestUtils.sha256Hex(Str));
    }
	
    public byte[] sha512(String Str) {           // SHA512
    	return hexStringToByteArray(DigestUtils.sha512Hex(Str));
    }
    
    public static byte[] hexStringToByteArray(String s) {      // Hex String to Byte Array 
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    } 
    /*
    We cant just use HexString.getBytes(); Method to convert hex string to byte array as the .getBytes() will return 8bit value
    of each individual character;
    ex. 'A' in hex string should mean -> 10 Decimal Notation, but GetBytes returns 65 (ASCII Value);
    so , getBytes() will return 8bits for one character, what we want is 4 bits for 1 character.
    so, this method taken from stackoverflow helps to convert hexString to byte array!
    */
}
// # Addicted to python so HashLib
