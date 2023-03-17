package pt.tecnico;

import java.net.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class SecureClient {

	private static final Charset UTF_8 = StandardCharsets.UTF_8;

	public static byte[] digest(byte[] input, String algorithm) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
        byte[] result = md.digest(input);
        return result;
    }

	public static boolean checkIntegrity(String hmac, JsonObject requestJson){
		//Verify integrity with hmac
		byte[] hmacToCheck = null;
		try{
			hmacToCheck = digest(requestJson.toString().getBytes(UTF_8), "SHA3-256");
		}catch (IllegalArgumentException e){
			System.out.println("Failed to hash value");
		}

		if(Base64.getEncoder().encodeToString(hmacToCheck).equals(hmac)){
			System.out.println("Integrity validated");
			return true;
		}
		return false;
	}

    public static String do_Encryption(String plainText, String path) throws Exception
    {
        // Load the secret key from the .key file
        byte[] secretKeyBytes = Files.readAllBytes(Paths.get(path));
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyBytes, "AES");

        // Convert the string to be encrypted to a byte array
        byte[] plaintextBytes = plainText.getBytes("UTF-8");

        // Create an instance of the Cipher class using the AES algorithm and initialize it with the secret key
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        // Use the Cipher object to encrypt the byte array
        byte[] ciphertextBytes = cipher.doFinal(plaintextBytes);

		// Encode the encrypted byte array to Base64 encoding
		String ciphertext = Base64.getEncoder().encodeToString(ciphertextBytes);

		return ciphertext;
    }

	/*Decryption function with secret key */
    public static String do_Decryption(String cipherText, String path, int lenght) throws Exception
    {
        // Load the secret key from the .key file
        byte[] secretKeyBytes = Files.readAllBytes(Paths.get(path));
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyBytes, "AES");

		byte[] ciphertextBytes = Base64.getDecoder().decode(cipherText);

		byte[] finalCipherText = new byte[lenght];
		System.arraycopy(ciphertextBytes, 0, finalCipherText, 0, lenght);

        // Create an instance of the Cipher class using the AES algorithm and initialize it with the secret key
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        // Use the Cipher object to decrypt the byte array
        byte[] plaintextBytes = cipher.doFinal(finalCipherText);

        // Convert the decrypted byte array to a string
        String plaintext = new String(plaintextBytes, "UTF-8");

		return plaintext;
    }

	/*Encryption function using RSA algorithm */
    public static String do_RSAEncryption(String plainText, String path) throws Exception
    {

		// Load the private key from the .key file
		byte[] privateKeyBytes = Files.readAllBytes(Paths.get(path));
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        // Convert the string to be encrypted into a byte array
        byte[] plaintextBytes = plainText.getBytes("UTF-8");

        // Create an instance of the Cipher class using the RSA algorithm and initialize it with the private key
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        // Use the Cipher object to encrypt the byte array
        byte[] ciphertextBytes = cipher.doFinal(plaintextBytes);

        // Encode the encrypted byte array into a string using Base64 encoding
        String ciphertext = Base64.getEncoder().encodeToString(ciphertextBytes);

		return ciphertext;
    }

    public static String do_RSADecryption(String cipherText, String path) throws Exception
    {
        // Load the public key from the .key file
        byte[] publicKeyBytes = Files.readAllBytes(Paths.get(path));
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        // Decode the encrypted string from Base64 encoding to a byte array
    	byte[] ciphertextBytes = Base64.getDecoder().decode(cipherText);

        // Create an instance of the Cipher class using the RSA algorithm and initialize it with the public key
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        // Use the Cipher object to decrypt the byte array
        byte[] plaintextBytes = cipher.doFinal(ciphertextBytes);

        // Convert the decrypted byte array to a string
        String plaintext = new String(plaintextBytes, "UTF-8");

		return plaintext;
    }

	/** Buffer size for receiving a UDP packet. */
	private static final int BUFFER_SIZE = 65_507;

	public static void main(String[] args) throws IOException {
		// Check arguments
		if (args.length < 3) {
			System.err.println("Argument(s) missing!");
			System.err.printf("Usage: java %s host port%n", SecureClient.class.getName());
			System.exit(1);
		}

        final String keyPathPublic = "keys/serverPub.der";
		final String keyPathPriv = "keys/userPriv.der";
		final String keyPathSecret = "keys/secret.key";

		String tokenToString = null;

		final String serverHost = args[0];
		final InetAddress serverAddress = InetAddress.getByName(serverHost);
		final int serverPort = Integer.parseInt(args[1]);
		final String sentence = args[2];

        Integer token = 0;
		
		try{
			tokenToString = do_RSAEncryption(token.toString(), keyPathPriv);
		}
		catch (Exception e){
			System.out.printf("RSA encryption failed\n");
			System.out.println(e.getMessage());
		}

		/*
		Scanner sc = new Scanner(System.in);
		String sentence = sc.nextLine();
		sc.close();
		*/

		
		// Create socket
		DatagramSocket socket = new DatagramSocket(10000);

        // Create request message
		JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
		{
			JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
			requestJson.add("info", infoJson);
            infoJson.addProperty("token", tokenToString);
			String bodyText = sentence;
			requestJson.addProperty("body", bodyText);
		}

		//Create hmac to assure integrity
		byte[] hmac = null;
		try{
			hmac = digest(requestJson.toString().getBytes(UTF_8), "SHA3-256");
		}catch (IllegalArgumentException e){
			System.out.println("Failed to hash value");
		}

		//ENVIAR HMAC EM BASE 64
		JsonObject messageWithHMAC = JsonParser.parseString("{}").getAsJsonObject();
		{
			messageWithHMAC.addProperty("payload", requestJson.toString());
			messageWithHMAC.addProperty("hmac", Base64.getEncoder().encodeToString(hmac));
		}

		String clientData = null;
		//Encrypt datagram with AES and simetric key
		try{
			clientData = do_Encryption(messageWithHMAC.toString(), keyPathSecret);
		}
		catch (Exception e){
			System.out.printf("Encryption with AES failed\n");
		}

		DatagramPacket clientPacket = new DatagramPacket(Base64.getDecoder().decode(clientData), Base64.getDecoder().decode(clientData).length, serverAddress, serverPort);
		socket.send(clientPacket);
		System.out.printf("Request packet sent\n");

		// Receive response
		byte[] serverData = new byte[BUFFER_SIZE];
		DatagramPacket serverPacket = new DatagramPacket(serverData, serverData.length);
		socket.receive(serverPacket);

		System.out.println("Received response");

		String serverText = null;
		try{
			serverText = do_Decryption(Base64.getEncoder().encodeToString(serverPacket.getData()), keyPathSecret, clientPacket.getLength());
		}
		catch(Exception e){
			System.out.println("Decryption with AES failed");
		}

		//Parse Json with payload and hmac
		JsonObject received = JsonParser.parseString(serverText).getAsJsonObject();
		String hmacRcvd = null, receivedFromJson = null;
		{
			hmacRcvd = received.get("hmac").getAsString();
			receivedFromJson = received.get("payload").getAsString();
		}

		// Parse JSON and extract arguments
		JsonObject responseJson = null;
		try{
			responseJson = JsonParser.parseString(receivedFromJson).getAsJsonObject();
		} catch (Exception e){
			System.out.println("Failed to parse Json received");
		}

		boolean integrityCheck = checkIntegrity(hmacRcvd, responseJson);

		if(!integrityCheck){
			System.out.println("Integrity violated");
		}

		// Parse JSON and extract arguments
		String body = null, tokenRcvd = null;
		{
			JsonObject infoJson = responseJson.getAsJsonObject("info");
            tokenRcvd = infoJson.get("token").getAsString();
			body = responseJson.get("body").getAsString();
		}

		try{
			tokenRcvd = do_RSADecryption(tokenRcvd, keyPathPublic);
		}
		catch (Exception e){
			System.out.printf("Identity invalid");
		}

		System.out.printf("Identity validated\n");

		// Close socket
		socket.close();

		System.out.printf(body);

		String finalValue = body.substring(0, body.length() - 1);

		if(!sentence.equals(finalValue)){
			System.out.println("Vou sair com 1");
			System.exit(1);
		}
		else{
			System.out.println("Vou sair com 0");
			System.exit(0);
		}
	}
}