package pt.tecnico;

import java.io.*;
import java.net.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import com.google.gson.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class SecureClient {

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

        System.out.println("Decrypted string: " + plaintext);

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
        System.out.println("Encrypted string: " + ciphertext);

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

        System.out.println("Decrypted string: " + plaintext);

		return plaintext;
    }

	/** Buffer size for receiving a UDP packet. */
	private static final int BUFFER_SIZE = 65_507;

	public static void main(String[] args) throws IOException {
		// Check arguments
		if (args.length < 2) {
			System.err.println("Argument(s) missing!");
			System.err.printf("Usage: java %s host port%n", SecureClient.class.getName());
			return;
		}

        final String keyPathPublic = "keys/serverPub.key";
		final String keyPathPriv = "keys/userPriv.key";
		final String keyPathSecret = "keys/secret.key";

		String tokenToString = null;
		String clientData = null;
		String serverText = null;

		final String serverHost = args[0];
		final InetAddress serverAddress = InetAddress.getByName(serverHost);
		final int serverPort = Integer.parseInt(args[1]);

        Integer token = 0;
		
		try{
			tokenToString = do_RSAEncryption(token.toString(), keyPathPriv);
		}
		catch (Exception e){
			System.out.printf("RSA encryption failed\n");
			System.out.println(e.getMessage());
		}
		
		// Create socket
		DatagramSocket socket = new DatagramSocket();

        // Create request message
		JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
		{
			JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
			infoJson.addProperty("from", "Alice");
			requestJson.add("info", infoJson);
            infoJson.addProperty("token", tokenToString);
			String bodyText = "Hello." + System.lineSeparator() + "Do you want to meet tomorrow?";
			requestJson.addProperty("body", bodyText);
		}
		System.out.println("Request message: " + requestJson);

		// Send request
		try{
			clientData = do_Encryption(requestJson.toString(), keyPathSecret);
		}
		catch (Exception e){
			System.out.printf("Encryption failed\n");
		}

		System.out.printf("%d bytes %n", Base64.getDecoder().decode(clientData).length);
		DatagramPacket clientPacket = new DatagramPacket(Base64.getDecoder().decode(clientData), Base64.getDecoder().decode(clientData).length, serverAddress, serverPort);
		socket.send(clientPacket);
		System.out.printf("Request packet sent to %s:%d!%n", serverAddress, serverPort);

		// Receive response
		byte[] serverData = new byte[BUFFER_SIZE];
		DatagramPacket serverPacket = new DatagramPacket(serverData, serverData.length);
		System.out.println("Wait for response packet...");
		socket.receive(serverPacket);
		System.out.printf("Received packet from %s:%d!%n", serverPacket.getAddress(), serverPacket.getPort());
		System.out.printf("%d bytes %n", serverPacket.getLength());

		// Convert response to string
		try{
			serverText = do_Decryption(Base64.getEncoder().encodeToString(serverPacket.getData()), keyPathSecret, serverPacket.getLength());
		}
		catch(Exception e){
			System.out.printf("Decryption failed\n");
		}
		System.out.println("Received response: " + serverText);

		// Parse JSON and extract arguments
		JsonObject responseJson = JsonParser.parseString(serverText).getAsJsonObject();
		String from = null, body = null, tokenRcvd = null;
		{
			JsonObject infoJson = responseJson.getAsJsonObject("info");
			from = infoJson.get("from").getAsString();
            tokenRcvd = infoJson.get("token").getAsString();
			body = responseJson.get("body").getAsString();
		}
		System.out.printf("Message from '%s':%n%s%n", from, body);

		try{
			tokenRcvd = do_RSADecryption(tokenRcvd, keyPathPublic);
		}
		catch (Exception e){
			System.out.printf("Identity invalid");
		}

		System.out.printf("Identity validated");

		// Close socket
		socket.close();
		System.out.println("Socket closed");
	}

}