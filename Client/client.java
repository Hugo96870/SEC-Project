package pt.tecnico;

import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
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

	/** Buffer size for receiving a UDP packet. */
	private static final int BUFFER_SIZE = 65_507;
	private static final Charset UTF_8 = StandardCharsets.UTF_8;

    public static byte[] do_Encryption(String plainText,SecretKey key) throws Exception
    {
		Cipher cipher = Cipher.getInstance(key.getAlgorithm());

		cipher.init(Cipher.ENCRYPT_MODE, key);

		return cipher.doFinal(plainText.getBytes());
    }

    public static String do_Decryption(byte[] cipherText,SecretKey key) throws Exception
    {
		Cipher cipher = Cipher.getInstance(key.getAlgorithm());

		cipher.init(Cipher.DECRYPT_MODE, key);

		byte[] result = cipher.doFinal(cipherText);
		
		return new String(result);
    }

    public static byte[] do_RSAEncryption(String plainText,Key key) throws Exception
    {
        Cipher cipher = Cipher.getInstance("RSA");
 
        cipher.init(Cipher.ENCRYPT_MODE, key);
 
        return cipher.doFinal(plainText.getBytes());
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
	public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
	public static void main(String[] args) throws IOException {
		// Check arguments
		if (args.length < 2) {
			System.err.println("Argument(s) missing!");
			return;
		}
		final String serverHost = args[0];
		final InetAddress serverAddress = InetAddress.getByName(serverHost);
		final int serverPort = Integer.parseInt(args[1]);
		final String keyPathPublic = "../Keys/userPub.key";
		final String keyPathServerPublic = "../Keys/serverPub.key";
		final String keyPathPriv = "../Keys/userPriv.key";
		//final String keyPathSecret = "../Keys/";

		double tokenDouble = Math.round(Math.abs(Math.random()) * 1000000);
		Integer token = (int)tokenDouble;
		String decryptedText = null;

		Key publicKey = null;
		Key privateKey = null;
		Key secretKey = null;

		byte[] cipherText = null, secretKeyinByte = null, serverData = null;

		// Create socket
		DatagramSocket socket = new DatagramSocket();

        // Create request message
		JsonObject requestJson = JsonParser.parseString​("{}").getAsJsonObject();
		{
			requestJson.addProperty("from", "Client");
			String bodyText = "Establish connection";
			requestJson.addProperty("info", bodyText);
			requestJson.addProperty("token", token);
		}

		String plainText = requestJson.toString();

		try{
			publicKey = readPublicKey(keyPathPublic);
			privateKey = readPrivateKey(keyPathPriv);
			//secretKey =
		}catch(Exception e){
			System.out.println("Errooooooooooooooooooouuuuuuuuuuuuuuu");
		}

		try{
			cipherText = do_Encryption(plainText, secretKey);
		} catch(Exception e){
			System.out.println("Errou");
		}

		// Send request
		DatagramPacket clientPacket = new DatagramPacket(cipherText, cipherText.length, serverAddress, serverPort);
		socket.send(clientPacket);
		System.out.printf("Request packet sent to %s:%d!%n", serverAddress, serverPort);

		// Receive response
		serverData = new byte[BUFFER_SIZE];
		DatagramPacket serverPacket = new DatagramPacket(serverData, serverData.length);
		System.out.println("Wait for response packet...");
		socket.receive(serverPacket);

		byte[] rcvdMsg = new byte[serverPacket.getLength()];
		System.arraycopy(serverPacket.getData(), 0, rcvdMsg, 0, serverPacket.getLength());

		try{
			decryptedText = do_Decryption(rcvdMsg, secretKey);
		} catch(Exception e){
			System.out.println("Errou1");
		}

		System.out.printf("Recebi %s", decryptedText);
		// Parse JSON and extract arguments

		JsonObject responseJson = JsonParser.parseString​(decryptedText).getAsJsonObject();
		String body = null, tokenRcvd = null;
		{
			JsonObject infoJson = responseJson.getAsJsonObject("info");
			tokenRcvd = infoJson.get("token").getAsString();
			body = responseJson.get("body").getAsString();
		}
		token = Integer.parseInt(tokenRcvd);
		token++;

		//------------------------------- CICLO WHILE A RECEBER RESPOSTA SERVER E RECEBER PEDIDO TERMINAL--------------------------------------

		while(true){

			// Esperar por clique e proceder

			JsonObject requestJsonWhile = JsonParser.parseString​("{}").getAsJsonObject();
			{
				JsonObject infoJson = JsonParser.parseString​("{}").getAsJsonObject();
				infoJson.addProperty("token", token.toString());
				requestJsonWhile.add("info", infoJson);
				String restaurant = "...";
				requestJsonWhile.addProperty("restaurant", restaurant);
				String numberPeople = "...";
				requestJsonWhile.addProperty("numberPeople", numberPeople);
				String date = "...";
				requestJsonWhile.addProperty("date", date);
				String time = "...";
				requestJsonWhile.addProperty("time", time);
			}

			String plainTextWhile = requestJsonWhile.toString();

			System.out.printf("Enviei %s", plainTextWhile);

			try{
				cipherText = do_Encryption(plainTextWhile, secretKey);
			} catch(Exception e){
				System.out.println("Errou");
			}

			// Send request
			DatagramPacket clientPacketWhile = new DatagramPacket(cipherText, cipherText.length, serverAddress, serverPort);
			socket.send(clientPacketWhile);

// -------------------------------------------------------- RECEBER Resposta ----------------------------------------------------------
			while(true){
				// Receive response
				byte[] serverDataWhile = new byte[BUFFER_SIZE];
				DatagramPacket serverPacketWhile = new DatagramPacket(serverDataWhile, serverDataWhile.length);
				System.out.println("Wait for response packet...");
				socket.receive(serverPacketWhile);

				byte[] rcvdMsgWhile = new byte[serverPacketWhile.getLength()];
				System.arraycopy(serverPacketWhile.getData(), 0, rcvdMsgWhile, 0, serverPacketWhile.getLength());

				try{
					decryptedText = do_Decryption(rcvdMsgWhile, secretKey);
				} catch(Exception e){
					System.out.println("Errou");
				}

				responseJson = JsonParser.parseString​(decryptedText).getAsJsonObject();
				{
					JsonObject infoJson = responseJson.getAsJsonObject("info");
					tokenRcvd = infoJson.get("token").getAsString();
					body = responseJson.get("body").getAsString();
				}

				System.out.printf("Recebi %s", decryptedText);
				
				//if we received response from server send msg
				if((token + 1) == Integer.parseInt(tokenRcvd)){
					token = Integer.parseInt(tokenRcvd) + 1;
					break;
				}
				//else ignore response
			}
		}
	}
}