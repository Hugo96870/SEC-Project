package pt.tecnico;

import java.net.*;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.security.PublicKey;
import java.security.spec.*;
import java.nio.file.Files;
import java.util.Base64;
import java.nio.file.Paths;


public class SecureServer {

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

		System.out.println("Encryptei com AES");

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

		System.out.println("Desencriptei com AES");

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

		System.out.println("Encriptei com RSA");

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

		System.out.println("Desencriptei com RSA");

		return plaintext;
    }

	/**
	 * Maximum size for a UDP packet. The field size sets a theoretical limit of
	 * 65,535 bytes (8 byte header + 65,527 bytes of data) for a UDP datagram.
	 * However the actual limit for the data length, which is imposed by the IPv4
	 * protocol, is 65,507 bytes (65,535 − 8 byte UDP header − 20 byte IP header.
	 */
	private static final int MAX_UDP_DATA_SIZE = (64 * 1024 - 1) - 8 - 20;

	/** Buffer size for receiving a UDP packet. */
	private static final int BUFFER_SIZE = MAX_UDP_DATA_SIZE;

	public static void main(String[] args) throws IOException {
		// Check arguments
		if (args.length < 1) {
			System.err.println("Argument(s) missing!");
			System.err.printf("Usage: java %s port%n", SecureServer.class.getName());
			return;
		}

		final String keyPathClientPublic = "keys/userPub.der";
		final String keyPathPriv = "keys/serverPriv.der";
		final String keyPathSecret = "keys/secret.key";

		String tokenToByte = null;

		final int port = Integer.parseInt(args[0]);

		// Create server socket
		DatagramSocket socket = new DatagramSocket(port);
		System.out.printf("Server will receive packets on port %d %n", port);

		// Wait for client packets 
		byte[] buf = new byte[BUFFER_SIZE];
		while (true) {
			// Receive packet
			DatagramPacket clientPacket = new DatagramPacket(buf, buf.length);
			socket.receive(clientPacket);
			InetAddress clientAddress = clientPacket.getAddress();
			int clientPort = clientPacket.getPort();
			int clientLength = clientPacket.getLength();
            String token = null;
			String serverData = null;
			byte[] clientData = clientPacket.getData();
			String clientText = null;
			System.out.printf("Received request packet from %s:%d!%n", clientAddress, clientPort);
			System.out.printf("%d bytes %n", clientLength);
			String tokenRcvd = null;

			// Convert request to string
			try{
				clientText = do_Decryption(Base64.getEncoder().encodeToString(clientData), keyPathSecret, clientLength);
			}
			catch(Exception e){
				System.out.println(e);
			}

			// Parse JSON and extract arguments
			JsonObject requestJson = JsonParser.parseString(clientText).getAsJsonObject();
			String from = null, body = null;
			{
				JsonObject infoJson = requestJson.getAsJsonObject("info");
				body = requestJson.get("body").getAsString();
                token = infoJson.get("token").getAsString();
			}

			System.out.printf("Recebi esta mensagem: %s\n", body);

			try{
				tokenRcvd = do_RSADecryption(token, keyPathClientPublic);
			}
			catch (Exception e){
				System.out.printf("Identity invalid");
			}

			try{
				tokenToByte = do_RSAEncryption(tokenRcvd, keyPathPriv);
			}
			catch (Exception e){
				System.out.printf("RSA encryption failed\n");
			}

			// Create response message
			JsonObject responseJson = JsonParser.parseString("{}").getAsJsonObject();
			{
				JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
				responseJson.add("info", infoJson);
                infoJson.addProperty("token", tokenToByte);
				String bodyText = "String added";
				responseJson.addProperty("body", bodyText);
			}

            // Send response
			try{
				serverData = do_Encryption(responseJson.toString(), keyPathSecret);
			}
			catch (Exception e){
				System.out.printf("Encryption failed\n");
			}
			
			DatagramPacket serverPacket = new DatagramPacket( Base64.getDecoder().decode(serverData), Base64.getDecoder().decode(serverData).length, clientPacket.getAddress(), clientPacket.getPort());
			socket.send(serverPacket);
			System.out.printf("Response packet sent to %s:%d!%n", clientPacket.getAddress(), clientPacket.getPort());
		}
	}
}