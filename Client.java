import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;


/**
 * @author Greeshma Reddy
 *
 */
public class Client {
	
	Socket clientSocket = null;
	String clientIP, serverIP;
	int clientPort, serverPort;
	File clientPrivateKey, serverPublicKey, content;
	byte[] message1, message2;
	/**
	 * set all the parameters required to run client program
	 * @param clientIP
	 * @param clientPort
	 * @param serverIP
	 * @param serverPort
	 * @param clientPrivateKey
	 * @param serverPublicKey
	 * @param content
	 */
	public Client(String clientIP, int clientPort, String serverIP, int serverPort, File clientPrivateKey, File serverPublicKey, File content)
	{
		this.clientIP = clientIP;
		this.clientPort = clientPort;
		this.serverIP = serverIP;
		this.serverPort = serverPort;
		this.clientPrivateKey = clientPrivateKey;
		this.serverPublicKey = serverPublicKey;
		this.content = content;
	}
	
	/**
	 * Client method responsible for sharing keys and random numbers. Sends the file content to server
	 */
	void clientProcess()
	{		
	    try {
	    	InetAddress address = InetAddress.getByName(serverIP);
	    	clientSocket = new Socket(address.getHostAddress(), serverPort);
	    	System.out.println("client started on"+ clientSocket.getLocalPort());
//	    	generate a 128 bit random number
	    	BigInteger r_A = new BigInteger(128, new Random());	    	
	    	System.out.println("Sending from client side r_a: "+r_A);
	    	
//	    	encrypt r_A using server's public key
	    	byte[] cipherText = encryptRandomNumber(r_A, serverPublicKey);
	    	
//	    	include digital signature
	        Signature dsa = Signature.getInstance("MD5withRSA");
	        PrivateKey privatekey = loadPrivateKey(clientPrivateKey);
	        dsa.initSign(privatekey);
	        dsa.update(cipherText);
//	        write encrypted content as a byte array to socket
			DataOutputStream dataOutStream = new DataOutputStream(clientSocket.getOutputStream());
			dataOutStream.writeInt(cipherText.length);
			dataOutStream.write(cipherText);
//			receive r_B from the server
			DataInputStream dataInStream = new DataInputStream(clientSocket.getInputStream());
			int length = dataInStream.readInt(); 
			if(length>0) {
			    message1 = new byte[length];
			    dataInStream.readFully(message1, 0, length); 
			}
			else message1 = null;
			
			if(message1!=null)
			{
//				check the digital signature
				Signature digSig = Signature.getInstance("MD5withRSA");
		        PublicKey publickeyS = loadPublicKey(serverPublicKey);
		        digSig.initVerify(publickeyS);
		        digSig.update(message1);
		        
//		        decrypt the content
				Cipher cipherC = Cipher.getInstance("RSA");
		        PrivateKey key = loadPrivateKey(clientPrivateKey);
		        cipherC.init(Cipher.DECRYPT_MODE, key);
		        byte[] decryptedText = cipherC.doFinal(message1);
		        
		        BigInteger r_B = new BigInteger(decryptedText);
		        System.out.println("Receiving from client side r_B: "+r_B);      
		        
//		        get AES key
		        byte[] key_AES = getKey(r_A, r_B).getBytes("UTF-8");
		        key_AES = Arrays.copyOf(key_AES, 16);
		        
		        byte[] encryptedContent=encrypt(key_AES, content);		        
				byte[] HMAC = calculateMac(key_AES, encryptedContent);
				
//				put HMAC and encrypted file content in one byte array
				byte[] encryptedContent_HMAC= new byte[encryptedContent.length+HMAC.length];
				System.arraycopy(HMAC,0,encryptedContent_HMAC,0, HMAC.length);	
				System.arraycopy(encryptedContent, 0, encryptedContent_HMAC, HMAC.length, encryptedContent.length);
				
//				send  the HMAC+content over socket
				dataOutStream.writeInt(encryptedContent_HMAC.length);
				dataOutStream.write(encryptedContent_HMAC);
				
			}
			clientSocket.close();
			
		} catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException | SignatureException e) {
			System.out.println("Error occured"+ e.getMessage());
			e.printStackTrace();
		}

	}


	/**
	 * encrypts given andom number using given server's public key
	 * @param r_A
	 * @param serverPublicKey2
	 * @return encrypted random number
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws IOException 
	 * @throws InvalidKeySpecException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	private byte[] encryptRandomNumber(BigInteger r_A, File serverPublicKeyLocal) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
        PublicKey publickey = loadPublicKey(serverPublicKeyLocal);
        cipher.init(Cipher.ENCRYPT_MODE, publickey);
        return cipher.doFinal(r_A.toByteArray());
	}

	/**
	 * encrypts and adds digital signature to the file content using given key
	 * @param r_A
	 * @param r_B
	 * @return encrypted file content
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws IOException 
	 */
	private byte[] encrypt(byte[] key, File content) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
		
		SecretKeySpec key_AB = new SecretKeySpec(key, "AES");
		Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		aesCipher.init(Cipher.ENCRYPT_MODE, key_AB);
		String fileContent = new String(Files.readAllBytes(content.toPath()));				
		byte[] encryptedContent = aesCipher.doFinal(fileContent.getBytes());
		return encryptedContent;
	}


	/**
	 * performs XOR of r_A and r_B
	 * @param r_A
	 * @param r_B
	 * @return AES key
	 */
	private String getKey(BigInteger r_A, BigInteger r_B) {
		BigInteger key_AES_AB = r_A.xor(r_B);
		return key_AES_AB.toString();
	}


	/**
	 * calculates HMAC for given byte array
	 * @param aESKey
	 * @param content
	 * @return HMAC
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	private byte[] calculateMac(byte[] aESKey, byte[] content) throws NoSuchAlgorithmException, InvalidKeyException {
		Mac hMAC = Mac.getInstance("HmacSHA256");
		final SecretKeySpec key = new SecretKeySpec(aESKey, "HmacSHA256");
		hMAC.init(key);
		return hMAC.doFinal(content);
	}


	/**
	 * load's server's public key from the file
	 * @param sPublicKey
	 * @return server's public key
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 */
	private PublicKey loadPublicKey(File sPublicKey) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
		byte[] keyBytes = Files.readAllBytes(sPublicKey.toPath());
	    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePublic(spec);
	}
	
	/**
	 * loads private key from file
	 * @param cPrivateKey
	 * @return client's private key
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 */
	
	private PrivateKey loadPrivateKey(File cPrivateKey) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
		byte[] keyBytes = Files.readAllBytes(cPrivateKey.toPath());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePrivate(spec);
	}

}
