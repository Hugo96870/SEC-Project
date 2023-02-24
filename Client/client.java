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

	/** Buffer size for receiving a UDP packet. */
	private static final int BUFFER_SIZE = 65_507;
	private static final Charset UTF_8 = StandardCharsets.UTF_8;

	/*Encryption function with secret key */
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

	/*Digest function to use in pre master secret */
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
		final String keyPath = args[2];
		
		/*Create the token that will be responsible for freshness */
		Integer token = 0;

		/*Generate pre master secret */
		Long preMasterSecret = Math.round(Math.abs(Math.random()) * 1000000);

		String decryptedText = null, decryptedHmac = null, toSend = "accept";

		Key key = null;
		byte[] cipherText = null, secretKeyinByte = null, serverData = null, hmacToCheck = null;

		// Create socket
		DatagramSocket socket = new DatagramSocket();

        // Create request message
		JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
		{
			requestJson.addProperty("preMasterSecret", preMasterSecret);
			requestJson.addProperty("from", "Client");
			String bodyText = "Establish connection";
			requestJson.addProperty("info", bodyText);
		}
		try{
			secretKeyinByte = digest(preMasterSecret.toString().getBytes(UTF_8), "SHA3-256");
		} catch(Exception e){
			System.out.println("Error in SHA3");
		}
		System.out.println(String.format("PREMASTERSECRET: %s",bytesToHex(secretKeyinByte)));

		String plainText = requestJson.toString();

		/*Read server's public key */
		try{
			key = readPublicKey(keyPath);
		}catch(Exception e){
			System.out.println("Error reading server's public key");
		}

		//Encrypt with server's public key
		try{
			cipherText = do_RSAEncryption(plainText, key);
		} catch(Exception e){
			System.out.println("Error encrypting with server's public key");
		}

		// Send connection request
		DatagramPacket clientPacket = new DatagramPacket(cipherText, cipherText.length, serverAddress, serverPort);
		socket.send(clientPacket);
		System.out.printf("Request packet sent to %s:%d!%n\n", serverAddress, serverPort);

		/*Create secret key with AES algorithm */
		SecretKey secretKey = new SecretKeySpec(secretKeyinByte, 0, secretKeyinByte.length, "AES");

		// Receive response
		serverData = new byte[BUFFER_SIZE];
		DatagramPacket serverPacket = new DatagramPacket(serverData, serverData.length);

		socket.receive(serverPacket);

		byte[] rcvdMsg = new byte[serverPacket.getLength()];

		System.arraycopy(serverPacket.getData(), 0, rcvdMsg, 0, serverPacket.getLength());

		JsonObject received = JsonParser.parseString(new String(rcvdMsg)).getAsJsonObject();
		String hmac = null, receivedFromJson = null;
		{
			hmac = received.get("hmac").getAsString();
			receivedFromJson = received.get("payload").getAsString();
		}

		byte[] receivedFromJsonBytes = Base64.getDecoder().decode(receivedFromJson);

		//Decrypt with secret key
		try{
			decryptedText = do_Decryption(receivedFromJsonBytes, secretKey);
		} catch(Exception e){
			System.out.println(e);
		}

		// Parse JSON and extract arguments
		JsonObject responseJson = JsonParser.parseString(decryptedText).getAsJsonObject();
		String body = null, tokenRcvd = null;
		{
			JsonObject infoJson = responseJson.getAsJsonObject("info");
			tokenRcvd = infoJson.get("token").getAsString();
			body = responseJson.get("body").getAsString();
		}

		//Verificação do hmac de modo a verificar integridade

		byte[] hmacBytes = Base64.getDecoder().decode(hmac);

		try{
			decryptedHmac = do_Decryption(hmacBytes, secretKey);
		} catch(Exception e){
			System.out.println(e);
		}

		try{
			hmacToCheck = digest(decryptedText.getBytes(UTF_8), "SHA3-256");
		} catch (Exception e){
			System.out.println(e);
		}
		if(decryptedHmac.getBytes() == hmacToCheck){
			System.out.println("Compromised message");
		}

		System.out.printf("Recebi %s\n", decryptedText);

		token = Integer.parseInt(tokenRcvd);

		//------------------------------- CICLO WHILE A RECEBER Pedido WEBSERVER E Enviar resposta--------------------------------------

		while(true){

			// -------------------------------------------------------- Receive Responses ----------------------------------------------------------
			while(true){
				// Receive response from webserver
				byte[] serverDataWhile = new byte[BUFFER_SIZE];
				DatagramPacket serverPacketWhile = new DatagramPacket(serverDataWhile, serverDataWhile.length);
				System.out.println("Wait for response packet...");
				socket.receive(serverPacketWhile);

				byte[] rcvdMsgWhile = new byte[serverPacketWhile.getLength()];

				System.arraycopy(serverPacketWhile.getData(), 0, rcvdMsgWhile, 0, serverPacketWhile.getLength());

				JsonObject receivedWhile = JsonParser.parseString(new String(rcvdMsgWhile)).getAsJsonObject();
				hmac = null;
				receivedFromJson = null;
				{
					hmac = receivedWhile.get("hmac").getAsString();
					receivedFromJson = receivedWhile.get("payload").getAsString();
				}

				receivedFromJsonBytes = Base64.getDecoder().decode(receivedFromJson);

				//Decrypt with secret key
				try{
					decryptedText = do_Decryption(receivedFromJsonBytes, secretKey);
				} catch(Exception e){
					System.out.println(e);
				}

				//Parse info to Json
				responseJson = JsonParser.parseString(decryptedText).getAsJsonObject();
				String cardNumber = null, threeDigits = null, validityDate = null, name = null;
				{
					JsonObject infoJson = responseJson.getAsJsonObject("info");
					tokenRcvd = infoJson.get("token").getAsString();
					cardNumber = responseJson.get("cardNumber").getAsString();
					threeDigits = responseJson.get("threeDigits").getAsString();
					validityDate = responseJson.get("validityDate").getAsString();
					name = responseJson.get("name").getAsString();
				}
				System.out.printf("Recebi %s\n", decryptedText);

				System.out.printf("Meu token %d\n", token);

				//Verificação do hmac de modo a verificar integridade
				hmacBytes = Base64.getDecoder().decode(hmac);

				try{
					decryptedHmac = do_Decryption(hmacBytes, secretKey);
				} catch(Exception e){
					System.out.println(e);
				}
				System.out.printf("Hmac %s\n", Base64.getEncoder().encodeToString(hmacBytes));

				try{
					hmacToCheck = digest(responseJson.toString().getBytes(UTF_8), "SHA3-256");
				} catch (Exception e){
					System.out.println(e);
				}

				if(decryptedHmac.getBytes() == hmacToCheck){
					toSend = "false";
					System.out.println("Compromised message");
				}

				receivedFromJsonBytes = Base64.getDecoder().decode(receivedFromJson);
				try{
					threeDigits = do_Decryption( Base64.getDecoder().decode(threeDigits), secretKey);
					cardNumber = do_Decryption( Base64.getDecoder().decode(cardNumber), secretKey);
					validityDate = do_Decryption( Base64.getDecoder().decode(validityDate), secretKey);
				} catch (Exception e){
					System.out.println("Erro a decifrar");
				}
				
				//Check message freshness
				if((token + 1) == Integer.parseInt(tokenRcvd)){
					token = Integer.parseInt(tokenRcvd) + 1;
					break;
				}
				//else ignore response
			}

// -------------------------------------------------------- Send Requests ----------------------------------------------------------
			//Wait for frontend click and store that information

			/* Simular algum tipo de verificação por parte do banco dos dados da conta */

			//Store info in Json format
			JsonObject requestJsonWhile = JsonParser.parseString("{}").getAsJsonObject();
			{
				JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
				infoJson.addProperty("token", token.toString());
				requestJsonWhile.add("info", infoJson);
				requestJsonWhile.addProperty("response", toSend);
			}

			String plainTextWhile = requestJsonWhile.toString();

			System.out.printf("Enviei %s\n", plainTextWhile);

			//Encrypt information with secret key
			try{
				cipherText = do_Encryption(plainTextWhile, secretKey);
			} catch(Exception e){
				System.out.println("Error encrypting with secret key");
			}

			byte[] hmacWhile = null;

			//Criar Hmac da mensagem que nos irá garantir integridade
			try{
				hmacWhile = do_Encryption(digest(requestJsonWhile.toString().getBytes(UTF_8), "SHA3-256").toString(), secretKey);
			} catch (Exception e){
				System.out.println(e);
			}

			//Criar mensagem para enviar ao servidor
			JsonObject toSendResponse = JsonParser.parseString("{}").getAsJsonObject();
			{
				toSendResponse.addProperty("payload", Base64.getEncoder().encodeToString(cipherText));
				toSendResponse.addProperty("hmac", Base64.getEncoder().encodeToString(hmacWhile));
			}

			// Send request
			DatagramPacket clientPacketWhile = new DatagramPacket(toSendResponse.toString().getBytes(),
					toSendResponse.toString().getBytes().length, serverAddress, serverPort);
			socket.send(clientPacketWhile);
		}
	}
}