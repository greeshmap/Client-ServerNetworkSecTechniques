import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author Greeshma Reddy
 *
 */
public class KeyPairGeneration {
	
	String serverPublicKeyFile = "C:\\Users\\Greeshma Reddy\\Desktop\\Spring2017\\COMS559\\serverpublic.txt",
			serverPrivateKeyFile = "C:\\Users\\Greeshma Reddy\\Desktop\\Spring2017\\COMS559\\serverprivate.txt",
			clientPublicKeyFile = "C:\\Users\\Greeshma Reddy\\Desktop\\Spring2017\\COMS559\\clientpublic.txt",
			clientPrivateKeyFile = "C:\\Users\\Greeshma Reddy\\Desktop\\Spring2017\\COMS559\\clientprivate.txt";	

	public KeyFactory keyFactory1, keyFactory2;
	public PublicKey serverPublicKey, clientPublicKey;
	public PrivateKey serverPrivateKey, clientPrivateKey;
	public byte[] encodedClientPrivateKey, encodedServerPrivateKey;
	public byte[] encodedClientPublicKey, encodedServerPublicKey;

	
	public KeyPairGeneration() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		//initialize all variables that store keys
		
	    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	    keyGen.initialize(1024);
	    KeyPair keypair1 = keyGen.genKeyPair();
	    this.clientPrivateKey = keypair1.getPrivate();
	    this.clientPublicKey = keypair1.getPublic();
		this.keyFactory1 = KeyFactory.getInstance("RSA");		
		this.encodedClientPrivateKey = this.clientPrivateKey.getEncoded();
	    this.encodedClientPublicKey = this.clientPublicKey.getEncoded();
	    
	    
	    KeyPair keypair2 = keyGen.genKeyPair();
	    this.serverPrivateKey = keypair2.getPrivate();
	    this.serverPublicKey = keypair2.getPublic();
		this.keyFactory2 = KeyFactory.getInstance("RSA");		
		this.encodedServerPrivateKey = this.serverPrivateKey.getEncoded();
	    this.encodedServerPublicKey = this.serverPublicKey.getEncoded();
	}
	/*
	 * generates server' s key pair (RSA)
	 */
	
	private void generateKeyPairServer() throws InvalidKeySpecException, IOException {
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedServerPublicKey);
		serverPublicKey = keyFactory2.generatePublic(publicKeySpec);
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedServerPrivateKey);
		serverPrivateKey = keyFactory2.generatePrivate(privateKeySpec);
		
		
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(serverPublicKey.getEncoded());
		FileOutputStream fos = new FileOutputStream(serverPublicKeyFile);
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();
		
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(serverPrivateKey.getEncoded());
		FileOutputStream fos1 = new FileOutputStream(serverPrivateKeyFile);
		fos1.write(pkcs8EncodedKeySpec.getEncoded());
		fos1.close();
	}
	
	/**
	 * generate client's key pair (RSA)
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 */
	
	private  void generateKeyPairClient() throws InvalidKeySpecException, IOException {
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedClientPublicKey);
		clientPublicKey = keyFactory1.generatePublic(publicKeySpec);
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedClientPrivateKey);
		clientPrivateKey = keyFactory1.generatePrivate(privateKeySpec);
		
		
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(serverPublicKey.getEncoded());
		FileOutputStream fos = new FileOutputStream(clientPublicKeyFile);
		fos.write(x509EncodedKeySpec.getEncoded());
		fos.close();
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(serverPrivateKey.getEncoded());
		FileOutputStream fos1 = new FileOutputStream(clientPrivateKeyFile);
		fos1.write(pkcs8EncodedKeySpec.getEncoded());
		fos1.close();
	}
	
	public static void main(String[] args)
	{
		try {
			KeyPairGeneration keypairs= new KeyPairGeneration();
			keypairs.generateKeyPairClient();
			keypairs.generateKeyPairServer();
			
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException | IOException e) {
			System.out.println("Error while generating key pairs:");
			e.printStackTrace();
		}
		
	}

}
