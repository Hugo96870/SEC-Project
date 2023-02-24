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
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.xml.bind
    .DatatypeConverter;
import javax.crypto.spec.SecretKeySpec;
import com.google.gson.*;
import java.sql.*;

public class SecureServer {

	/**
	 * Maximum size for a UDP packet. The field size sets a theoretical limit of
	 * 65,535 bytes (8 byte header + 65,527 bytes of data) for a UDP datagram.
	 * However the actual limit for the data length, which is imposed by the IPv4
	 * protocol, is 65,507 bytes (65,535 − 8 byte UDP header − 20 byte IP header.
	 */
	private static final int MAX_UDP_DATA_SIZE = (64 * 1024 - 1) - 8 - 20;

	/** Buffer size for receiving a UDP packet. */
	private static final int BUFFER_SIZE = MAX_UDP_DATA_SIZE;
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
		if (args.length < 1) {
			System.err.println("Argument(s) missing!");
			return;
		}

		final int port = Integer.parseInt(args[0]);

		final String keyPathPublic = "../Keys/serverPub.key";
		final String keyPathClientPublic = "../Keys/userPub.key";
		final String keyPathPriv = "../Keys/serverPriv.key";
		//final String keyPathSecret = "../Keys/";

		byte[] bufRSA = new byte[BUFFER_SIZE];
		byte[] bufAES = new byte[BUFFER_SIZE];
		DatagramSocket socket = new DatagramSocket(port);		

		DatagramPacket clientPacketAES = new DatagramPacket(bufAES, bufAES.length);
		DatagramPacket clientPacketRSA = new DatagramPacket(bufRSA, bufRSA.length);
		socket.receive(clientPacketRSA);


		Key publicKey = null;
		Key privateKey = null;
		Key secretKey = null;

		String decryptedText = null;

		// Create server socket
		InetAddress clientAddress = clientPacketRSA.getAddress();
		byte[] clientData = clientPacketRSA.getData(), clientDataWhile = null, responseBt = null, serverData = null;

		Integer token;
		int clientPort = clientPacketRSA.getPort(), clientLength = clientPacketRSA.getLength();

		System.out.printf("Received request packet from %s:%d!%n", clientAddress, clientPort);

		byte[] finalCipherText = new byte[clientPacketRSA.getLength()];
		System.arraycopy(clientData, 0, finalCipherText, 0, clientPacketRSA.getLength());

		try{
			publicKey = readPublicKey(keyPathPublic);
			privateKey = readPrivateKey(keyPathPriv);
			//secretKey =
		} catch(Exception e){
			System.out.println("Errouuuuuuuuuuuuuuu");
		}		

		try{
			decryptedText = do_Decryption(finalCipherText, secretKey);
		} catch(Exception e){
			System.out.println("Errou");
		}

		// Parse JSON and extract arguments
		JsonObject requestJson = JsonParser.parseString​(decryptedText).getAsJsonObject();
		String from = null, body = null;
		{
			body = requestJson.get("info").getAsString();
			from = requestJson.get("from").getAsString();
			token = requestJson.get("token").getAsString();
		}

		token++;

		// Create response message

		JsonObject responseJson = JsonParser.parseString​("{}").getAsJsonObject();
		{
				JsonObject infoJson = JsonParser.parseString​("{}").getAsJsonObject();
				infoJson.addProperty("token", token.toString());
				responseJson.add("info", infoJson);
				String bodyText = "Connection established";
				responseJson.addProperty("body", bodyText);
		}

		try{
			serverData = do_Encryption(responseJson.toString(), secretKey);
		} catch(Exception e){
			System.out.println("Errou1");
		}

		System.out.printf("Enviei %s", responseJson.toString());

		// Send response
		DatagramPacket serverPacket = new DatagramPacket(serverData, serverData.length, clientPacketRSA.getAddress(), clientPacketRSA.getPort());
		socket.send(serverPacket);

		while (true) {
			//-------------------------------------------- RECEBER PEDIDOS E DESENCRIPTAR COM CHAVE SECRETA

			socket.receive(clientPacketAES);
			clientAddress = clientPacketAES.getAddress();
			clientPort = clientPacketAES.getPort();

			byte[] finalCipherTextWhile = new byte[clientPacketAES.getLength()];
			System.arraycopy(clientPacketAES.getData(), 0, finalCipherTextWhile, 0, clientPacketAES.getLength());

			try{
				decryptedText = do_Decryption(finalCipherTextWhile, secretKey);
			} catch(Exception e){
				System.out.println("Errou");
			}

			System.out.printf("Recebi %s", decryptedText);

			// Parse JSON and extract arguments
			String restaurant = null, date = null, time = null, tokenRcvd = null, numberPeople = null;
			requestJson = JsonParser.parseString​(decryptedText).getAsJsonObject();
			{
				JsonObject infoJsonWhile = requestJson.getAsJsonObject("info");
				tokenRcvd = infoJsonWhile.get("token").getAsString();
				restaurant = requestJson.get("restaurant").getAsString();
				numberPeople = requestJson.get("numberPeople").getAsString();
				date = requestJson.get("date").getAsString();
				time = requestJson.get("time").getAsString();
			}

			if((token + 1) == Integer.parseInt(tokenRcvd)){
				token = Integer.parseInt(tokenRcvd);

				//Sendo query de acordo com pedido recebido
				//SendQuery();

				token++;

				// Create response message
				JsonObject responseJsonWhile = JsonParser.parseString​("{}").getAsJsonObject();
				{
					JsonObject infoJson = JsonParser.parseString​("{}").getAsJsonObject();
					infoJson.addProperty("token", token.toString());
					responseJsonWhile.add("info", infoJson);
					String bodyText = "Table reservation succeded";
					responseJsonWhile.addProperty("body", bodyText);
				}

				try{
					serverData = do_Encryption(responseJsonWhile.toString(), secretKey);
				} catch(Exception e){
					System.out.println("Errou");
				}

				System.out.printf("Enviei %s", responseJsonWhile.toString());

				// Send response
				DatagramPacket serverPacketWhile = new DatagramPacket(serverData, serverData.length, clientPacketAES.getAddress(), clientPacketAES.getPort());
				socket.send(serverPacketWhile);
			}
			else{
				System.out.println("Erro");
				break;
			}
		}
	}
}