import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
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
import java.util.Scanner;

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
public class Server {
	
	ServerSocket serverSocket=null;
	String serverIP, clientIP;
	int serverPort, clientPort;
	File serverPrivateKey, clientPublicKey;
	/**
	 * All server details to be passed here
	 * @param serverIP
	 * @param serverPort
	 * @param clientIP
	 * @param clientPort
	 * @param serverPrivateKey
	 * @param clientPublicKey
	 */
	public Server(String serverIP, int serverPort, String clientIP, int clientPort, File serverPrivateKey, File clientPublicKey) 
	{
		this.serverIP = serverIP;
		this.serverPort = serverPort;
		this.clientIP = clientIP;
		this.clientPort = clientPort;
		this.serverPrivateKey = serverPrivateKey;
		this.clientPublicKey = clientPublicKey;
	}
	public static void main(String[] args)
	{
		Scanner s= new Scanner(System.in);
		System.out.println("enter server IP");
		String serverIP=s.next();
		System.out.println("Enter the port you want to use for server");
		int serverport=s.nextInt();
		System.out.println("Enter client IP");
		String clientIP=s.next();
		System.out.println("Enter the client port");
		int clientport=s.nextInt();
		System.out.println("Enter Server's private key file path");
		String sPrivateKey=s.next();
		System.out.println();
		System.out.println("Enter client's public key file path");
		String cPublicKey=s.next();
		Server server=new Server(serverIP, serverport, clientIP, clientport,new File(sPrivateKey), new File(cPublicKey));
		server.serverProcess();
	}

//	serverProcess() is responsible for socket creation and sharing random number, reciving actual file content
	
	public void serverProcess() //throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, NoSuchProviderException
	{
		byte[] message1, message2;
		try {
	        serverSocket = new ServerSocket();
	        serverSocket.bind(new InetSocketAddress(serverIP, serverPort));
	        System.out.println("Starting server on "+serverSocket.getLocalPort());
			while(true)
			{
				Socket clientSocket = serverSocket.accept();
				DataInputStream dataInStream = new DataInputStream(clientSocket.getInputStream());				
				int length = dataInStream.readInt(); 
				if(length>0) {
//					Received message over socket. message is random number r_A
				    message1 = new byte[length];
				    dataInStream.readFully(message1, 0, length); 
				}
				else message1 = null;
				if(message1!=null)
				{
					byte[] decryptedText=getDecryptedText(message1, clientPublicKey, serverPrivateKey);			        
			        BigInteger r_A = new BigInteger(decryptedText);
			        System.out.println("Receiving from server side r_A: "+r_A);			        
			        BigInteger r_B = new BigInteger(128, new Random());
			    	System.out.println("Sending from server side r_B: " +r_B);
			    	
//			    	encrypts random number r_A with client's public Key
			    	
			    	byte[] cipherText = encryptRandomNumber(r_B, clientPublicKey); 
			    	
//			    	include digital signature to the encrypted r_B
			        
			        Signature digSig = Signature.getInstance("MD5withRSA");
			        PrivateKey privatekeyS = loadPrivateKey(serverPrivateKey);
			        digSig.initSign(privatekeyS);
			        digSig.update(cipherText);
			        
//			        send length of the byte array and encrypted, digitally signed r_B over socket
			        
			        DataOutputStream dOS = new DataOutputStream(clientSocket.getOutputStream());
					dOS.writeInt(cipherText.length);
					dOS.write(cipherText);
					
//					DataInputStream dataInStream = new DataInputStream(clientSocket.getInputStream());
					
//					receive HMAC and encrypted file content in a single byte array
					
					int streamLength = dataInStream.readInt(); 
					if(streamLength>0) {
						message2 = new byte[streamLength];
						dataInStream.readFully(message2, 0, message2.length); 
					}
					else message2 = null;
					if(message2!=null)
					{
						byte[] HMAC = new byte[32];
						byte[] content = new byte[message2.length-32];
						
//						copy HMAC and encrypted content into two different arrays 
						System.arraycopy(message2,0,HMAC,0, 32);
						System.arraycopy(message2, 32, content, 0, content.length);		
//						get the secret key for AES
						byte[] key_AES = getKey(r_A, r_B).getBytes("UTF-8");
						key_AES = Arrays.copyOf(key_AES, 16);
//						if both HMAC are equal
						if(Arrays.equals(HMAC, calculateMac(key_AES, content)))
						{
//							decrypt the file content and display
							SecretKeySpec key_AB = new SecretKeySpec(key_AES, "AES");
							Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
							aesCipher.init(Cipher.DECRYPT_MODE, key_AB);
							byte[] decryptedContent = aesCipher.doFinal(content);
							System.out.println("Actual content decrypted:\n "+ new String(decryptedContent));
						}
					
					}
				}
			}
		} catch (IOException | InvalidKeyException | SignatureException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
			System.out.println("Error occured"+ e.getMessage());
			e.printStackTrace();
		}
	}
	
	/**
	 * @param r_B
	 * @param clientPublicKey2
	 * @return encrypted r_A
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws IOException 
	 * @throws InvalidKeySpecException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	private byte[] encryptRandomNumber(BigInteger r_B, File clientPublicKeyLocal) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipherB = Cipher.getInstance("RSA");
        PublicKey publickeyC = loadPublicKey(clientPublicKeyLocal);
        cipherB.init(Cipher.ENCRYPT_MODE, publickeyC);
        return cipherB.doFinal(r_B.toByteArray());
	}



	/**
	 * @param message, cPublicKey, sPrivateKey
	 * @return decrypted text
	 * @throws NoSuchAlgorithmException 
	 * @throws IOException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidKeyException 
	 * @throws SignatureException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 */
	private byte[] getDecryptedText(byte[] message, File cPublicKey, File sPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException, InvalidKeyException, SignatureException, IllegalBlockSizeException, BadPaddingException {
		Signature dsa = Signature.getInstance("MD5withRSA");
        PublicKey publickey = loadPublicKey(cPublicKey);
        dsa.initVerify(publickey);
        dsa.update(message);
        
		Cipher cipher = Cipher.getInstance("RSA");
        PrivateKey key = loadPrivateKey(sPrivateKey);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(message);
	}
	
	/**
	 * loads private key of server
	 * @param sPrivateKey
	 * @return server's private key
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 */
	public  PrivateKey loadPrivateKey(File sPrivateKey) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
		byte[] keyBytes = Files.readAllBytes(sPrivateKey.toPath());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePrivate(spec);
	}
	
	/**
	 * loads public key of client
	 * @param cPublicKey
	 * @return publickey
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 */
	
	public PublicKey loadPublicKey(File cPublicKey) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
		byte[] keyBytes = Files.readAllBytes(cPublicKey.toPath());
	    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePublic(spec);
	}
	
	/**
	 * calculated HMAC
	 * @param aESKey
	 * @param content
	 * @return hMac
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
	 * performs xor of r_A and r_B
	 * @param r_A
	 * @param r_B
	 * @return xor
	 */
	private String getKey(BigInteger r_A, BigInteger r_B) {
		BigInteger key_AES_AB = r_A.xor(r_B);
		return key_AES_AB.toString();
	}

}
