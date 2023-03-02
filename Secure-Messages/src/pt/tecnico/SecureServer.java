package pt.tecnico;

import java.io.*;
import java.net.*;
import com.google.gson.*;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Scanner;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Arrays.*;
import java.lang.Math;
import javax.xml.bind.DatatypeConverter;
import com.google.gson.*;


public class SecureServer {

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

        final String keyPathPublic = "../Keys/serverPub.key";
		final String keyPathClientPublic = "../Keys/userPub.key";
		final String keyPathPriv = "../Keys/serverPriv.key";
		//final String keyPathSecret = "../Keys/";

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
            byte[] token = null;
			byte[] clientData = clientPacket.getData();
			System.out.printf("Received request packet from %s:%d!%n", clientAddress, clientPort);
			System.out.printf("%d bytes %n", clientLength);

			// Convert request to string
			String clientText = do_Decryption(clientData, "READ SECRET KEY");
			System.out.println("Received request: " + clientText);

			// Parse JSON and extract arguments
			JsonObject requestJson = JsonParser.parseString​(clientText).getAsJsonObject();
			String from = null, body = null;
			{
				JsonObject infoJson = requestJson.getAsJsonObject("info");
				from = infoJson.get("from").getAsString();;
				body = requestJson.get("body").getAsString();
                token = infoJson.get("token").getAsString().getBytes();
			}
			System.out.printf("Message from '%s':%n%s%n", from, body);

			// Create response message
			JsonObject responseJson = JsonParser.parseString​("{}").getAsJsonObject();
			{
				JsonObject infoJson = JsonParser.parseString​("{}").getAsJsonObject();
				infoJson.addProperty("from", "Bob");
				responseJson.add("info", infoJson);
                infoJson.addProperty("token", token.toString());
				String bodyText = "Yes. See you tomorrow!";
				responseJson.addProperty("body", bodyText);
			}
			System.out.println("Response message: " + responseJson);

            // Send response
            byte[] serverData = do_Encryption(responseJson.toString(), "READ SECRET KEY");
			System.out.printf("%d bytes %n", serverData.length);
			DatagramPacket serverPacket = new DatagramPacket(serverData, serverData.length, clientPacket.getAddress(), clientPacket.getPort());
			socket.send(serverPacket);
			System.out.printf("Response packet sent to %s:%d!%n", clientPacket.getAddress(), clientPacket.getPort());
		}
	}
}