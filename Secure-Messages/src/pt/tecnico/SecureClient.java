package pt.tecnico;

import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Arrays.*;
import java.lang.Math;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.xml.bind
    .DatatypeConverter;
import javax.crypto.spec.SecretKeySpec;
import com.google.gson.*;



public class SecureClient {

    public static byte[] do_Encryption(String plainText, SecretKey key) throws Exception
    {
		Cipher cipher = Cipher.getInstance(key.getAlgorithm());

		cipher.init(Cipher.ENCRYPT_MODE, key);

		return cipher.doFinal(plainText.getBytes());
    }

	/*Decryption function with secret key */
    public static String do_Decryption(byte[] cipherText, SecretKey key) throws Exception
    {
		Cipher cipher = Cipher.getInstance(key.getAlgorithm());

		cipher.init(Cipher.DECRYPT_MODE, key);

		byte[] result = cipher.doFinal(cipherText);
		
		return new String(result);
    }

	/*Encryption function using RSA algorithm */
    public static byte[] do_RSAEncryption(String plainText,Key key) throws Exception
    {
        Cipher cipher = Cipher.getInstance("RSA");
 
        cipher.init(Cipher.ENCRYPT_MODE, key);
 
        return cipher.doFinal(plainText.getBytes());
    }

    public static String do_RSADecryption(byte[] cipherText, Key key) throws Exception
    {
        Cipher cipher = Cipher.getInstance("RSA");
 
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] result = cipher.doFinal(cipherText);
 
        return new String(result);
    }

    private static byte[] readFile(String path) throws FileNotFoundException, IOException {
        FileInputStream fis = new FileInputStream(path);
        byte[] content = new byte[fis.available()];
        fis.read(content);
        fis.close();
        return content;
    }

    public static PublicKey readPublicKey(String publicKeyPath) throws Exception {
        System.out.println("Reading public key from file " + publicKeyPath + " ...");
        byte[] pubEncoded = readFile(publicKeyPath);
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubEncoded);
        KeyFactory keyFacPub = KeyFactory.getInstance("RSA");
        PublicKey pub = keyFacPub.generatePublic(pubSpec);
        return pub;
    }

    public static PrivateKey readPrivateKey(String privateKeyPath) throws Exception {
        byte[] privEncoded = readFile(privateKeyPath);
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privEncoded);
        KeyFactory keyFacPriv = KeyFactory.getInstance("RSA");
        PrivateKey priv = keyFacPriv.generatePrivate(privSpec);
        return priv;
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

        final String keyPathPublic = "../Keys/userPub.key";
		final String keyPathServerPublic = "../Keys/serverPub.key";
		final String keyPathPriv = "../Keys/userPriv.key";
		//final String keyPathSecret = "../Keys/";

		final String serverHost = args[0];
		final InetAddress serverAddress = InetAddress.getByName(serverHost);
		final int serverPort = Integer.parseInt(args[1]);

        Integer token = 0;

        byte[] tokenToByte = do_RSAEncryption(token.toString(), readPrivateKey(keyPathPriv));

		// Create socket
		DatagramSocket socket = new DatagramSocket();

        // Create request message
		JsonObject requestJson = JsonParser.parseString​("{}").getAsJsonObject();
		{
			JsonObject infoJson = JsonParser.parseString​("{}").getAsJsonObject();
			infoJson.addProperty("from", "Alice");
			requestJson.add("info", infoJson);
            infoJson.addProperty("token", tokenToByte.toString());
			String bodyText = "Hello." + System.lineSeparator() + "Do you want to meet tomorrow?";
			requestJson.addProperty("body", bodyText);
		}
		System.out.println("Request message: " + requestJson);

		// Send request
		byte[] clientData = do_Encryption(requestJson.toString(), "READ SECRET KEY");
		System.out.printf("%d bytes %n", clientData.length);
		DatagramPacket clientPacket = new DatagramPacket(clientData, clientData.length, serverAddress, serverPort);
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
		String serverText = do_Decryption(serverPacket.getData(), "READ SECRET KEY");
		System.out.println("Received response: " + serverText);

		// Parse JSON and extract arguments
		JsonObject responseJson = JsonParser.parseString​(serverText).getAsJsonObject();
		String from = null, body = null, tokenRcvd = null;
		{
			JsonObject infoJson = responseJson.getAsJsonObject("info");
			from = infoJson.get("from").getAsString();
            tokenRcvd = infoJson.get("token").getAsString();
			body = responseJson.get("body").getAsString();
		}
		System.out.printf("Message from '%s':%n%s%n", from, body);

        //DECRYPT TOKEN WITH RSA key

		// Close socket
		socket.close();
		System.out.println("Socket closed");
	}

}