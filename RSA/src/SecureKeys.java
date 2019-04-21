package helloworld;

public class SecureKeys {

	public static void main(String[] args) throws Exception{

		RSA keyOne;
		keyOne = new RSA();
		
		String password = new String("hEllo World!-");
		String salt = new String("NaCl");
		
		keyOne.createDeterministicKeys(4096,password,salt);
		
		keyOne.SaveKeys("C:/RSA/Private","C:/RSA/Public");                  
		
		System.out.println("Private RSA Key : " + keyOne.getPrivateKey());
		System.out.println("Public  RSA Key : " + keyOne.getPublicKey());

	}

}
