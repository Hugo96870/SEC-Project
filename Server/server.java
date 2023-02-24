package pt.tecnico;

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

	/* Database stuff */
	static Connection conn = null;
	static PreparedStatement p = null;
	static ResultSet rs = null;
	//Create server socket
	static DatagramSocket socket;		

	static byte[] bufRSA = new byte[BUFFER_SIZE];

	static SecretKey secretKey;

	static DatagramPacket clientPacketAES = new DatagramPacket(bufRSA, bufRSA.length);
	static DatagramPacket clientPacketRSA = new DatagramPacket(bufRSA, bufRSA.length);

	/*Create the token that will be responsible for freshness and initialize it */
	static double tokenDouble = Math.round(Math.abs(Math.random()) * 1000000);
	static Integer token = (int)tokenDouble;


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

	/*Decryption function using RSA algorithm */
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

	/*Read private key sent by client */
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

	/*Database initialization */
	public void InitializeDB(){

		try{
			Class.forName("org.postgresql.Driver");
		}catch (Exception e){
			System.out.println("Error in creating database");
		}

		int port = 5432;
		String database = "thecork";
		String username = "t48";
		String password = "1234";

		String url = "jdbc:postgresql://192.168.2.4" + ":" + port + "/" + database;

		//192.168.2.4

		try{
			conn = DriverManager.getConnection(url, username, password);
			System.out.println("Connected to the PostgreSQL server successfully., ");
		} catch (Exception e) {
			System.out.println(e);
		}
	}

	public void updateQueryCard(String name, String cardNumber, String validityDate, String threedigits){

		byte[] threeDigitsByte = null, cardNumberByte = null, validityDateByte = null;

		try{
			cardNumberByte = do_Encryption(cardNumber, secretKey);
			validityDateByte = do_Encryption(validityDate, secretKey);
			threeDigitsByte = do_Encryption(threedigits, secretKey);
		}catch(Exception e){
			System.out.println(e);
		}
		String threeDigits64 = Base64.getEncoder().encodeToString(threeDigitsByte);
		String cardNumber64 = Base64.getEncoder().encodeToString(cardNumberByte);
		String validityDate64 = Base64.getEncoder().encodeToString(validityDateByte);


		try{
			p = conn.prepareStatement("INSERT INTO user_profile values ('" + name + "','" + cardNumber64 + "','" + threeDigits64 + "','" + validityDate64 + "')");
			rs = p.executeQuery();
		} catch (Exception e){
			System.out.println("Error sending query to the database");
		}
	}

	public boolean sendQueryCard(String name){

		try{
			String query = "SELECT * FROM user_profile";
			p = conn.prepareStatement(query);
			rs = p.executeQuery();
			while (rs.next())
			{
				String user = rs.getString("nome");
				if(user.equals(name)){
					return true;
				}
			}
		} catch (Exception e){
			System.out.println("Error sending query to the database");
		}
		return false;
	}

	/*Send querys to the database */
	public boolean sendQueryLogin(String user, String pass){

		String password = null;
		String name = null;

		try{
			String query = "SELECT * FROM users_login";
			p = conn.prepareStatement(query);
			rs = p.executeQuery();
			while (rs.next())
			{
				name = rs.getString("nome");		
				password = rs.getString("password");
				if(pass.equals(password) && user.equals(name)){
					return true;
				}
			}
		} catch (Exception e){
			System.out.println("Erro na query login");
		}
		return false;
	}

	public boolean RcvSendMsg(String name, String cardNumber, String validityDate, String threedigits){

		byte[] hmacToCheck = null, serverData = null, hmac = null;
		String decryptedText = null, decryptedHmac = null;
		Boolean returnValue = null;
		byte[] threeDigitsByte = null, cardNumberByte = null, validityDateByte = null;

		try{
			cardNumberByte = do_Encryption(cardNumber.toString(), secretKey);
			validityDateByte = do_Encryption(validityDate, secretKey);
			threeDigitsByte = do_Encryption(threedigits.toString(), secretKey);
		}catch(Exception e){
			System.out.println(e);
		}
		String threeDigits64 = Base64.getEncoder().encodeToString(threeDigitsByte);
		String cardNumber64 = Base64.getEncoder().encodeToString(cardNumberByte);
		String validityDate64 = Base64.getEncoder().encodeToString(validityDateByte);

		token++;

		// Create response message
		JsonObject responseJsonWhile = JsonParser.parseString("{}").getAsJsonObject();
		{
			JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
			infoJson.addProperty("token", token.toString());
			responseJsonWhile.add("info", infoJson);
			responseJsonWhile.addProperty("name", name);
			responseJsonWhile.addProperty("cardNumber", cardNumber64);
			responseJsonWhile.addProperty("threeDigits", threeDigits64);
			responseJsonWhile.addProperty("validityDate", validityDate64);
		}

		//Encrypt response message with secret key
		try{
			serverData = do_Encryption(responseJsonWhile.toString(), secretKey);
		} catch(Exception e){
			System.out.println("Error encrypting with secret key");
		}

		//Criar Hmac da mensagem que nos irá garantir integridade
		try{
			hmac = do_Encryption(digest(responseJsonWhile.toString().getBytes(UTF_8), "SHA3-256").toString(), secretKey);
		} catch (Exception e){
			System.out.println(e);
		}

		//Criar mensagem para enviar ao cliente
		JsonObject toSendResponse = JsonParser.parseString("{}").getAsJsonObject();
		{
			toSendResponse.addProperty("payload", Base64.getEncoder().encodeToString(serverData));
			toSendResponse.addProperty("hmac", Base64.getEncoder().encodeToString(hmac));
		}

		System.out.printf("Hmac %s\n", Base64.getEncoder().encodeToString(hmac));

		System.out.printf("Enviei %s\n", responseJsonWhile.toString());

		// Send response
		DatagramPacket serverPacketWhile = new DatagramPacket(toSendResponse.toString().getBytes(),
			toSendResponse.toString().getBytes().length, clientPacketRSA.getAddress(), clientPacketRSA.getPort());
		try{
			socket.send(serverPacketWhile);
		}catch (Exception e){
			System.out.println(e);
		}

		// -------------------------------------------------- Receive requests ------------------------------------------
		// Receive requests from client
		while(true){

			try{
				socket.receive(clientPacketAES);
			}catch (Exception e){
				System.out.println(e);
			}

			byte[] rcvdMsgWhile = new byte[clientPacketAES.getLength()];

			System.arraycopy(clientPacketAES.getData(), 0, rcvdMsgWhile, 0, clientPacketAES.getLength());

			JsonObject receivedWhile = JsonParser.parseString(new String(rcvdMsgWhile)).getAsJsonObject();
			String hmacWhile = null, receivedFromJsonWhile = null;
			{
				hmacWhile = receivedWhile.get("hmac").getAsString();
				receivedFromJsonWhile = receivedWhile.get("payload").getAsString();
			}

			byte[] receivedFromJsonBytes = Base64.getDecoder().decode(receivedFromJsonWhile);

			//Decrypt with secret key
			try{
				decryptedText = do_Decryption(receivedFromJsonBytes, secretKey);
			} catch(Exception e){
				System.out.println(e);
			}

			// Parse JSON and extract arguments
			String tokenRcvd = null, received = null;
			JsonObject requestJson = JsonParser.parseString(decryptedText).getAsJsonObject();
			{
				JsonObject infoJsonWhile = requestJson.getAsJsonObject("info");
				tokenRcvd = infoJsonWhile.get("token").getAsString();
				received = requestJson.get("response").getAsString();
			}

			//Verificação do hmac de modo a verificar integridade

			byte[] hmacBytes = Base64.getDecoder().decode(hmacWhile);

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

			if(received == "accept"){
				returnValue = true;
			}
			else{
				returnValue = false;
			}

			System.out.printf("Recebi %s\n", decryptedText);

			//Check fressness of the message
			if((token + 1) == Integer.parseInt(tokenRcvd)){
				token = Integer.parseInt(tokenRcvd);
				break;
			}
			else{
				returnValue = false;
				System.out.println("Not fresh request");
			}
		}

		return returnValue;
	}

	public void InitializeConnection(){
		//Parse arguments and initialize variables

		final String keyPath = "src/main/java/pt/tecnico/keys/webServerPriv.der";

		//Estabelecer ligacao com server
		try{
			socket = new DatagramSocket(8000);
			//receive first connection request
			socket.receive(clientPacketRSA);
		} catch(Exception e){
			System.out.println(e);
		}

		Key key = null;
		String decryptedText = null, preMasterSecret = null;
		Integer preSecretMaster = 0;
		byte[] clientData = clientPacketRSA.getData(), serverData = null;
		byte[] secretKeyinByte = null;

		byte[] finalCipherText = new byte[clientPacketRSA.getLength()], hmac = null;
		System.arraycopy(clientData, 0, finalCipherText, 0, clientPacketRSA.getLength());

		try{
			key = readPrivateKey(keyPath);
		} catch(Exception e){
			System.out.println("Error reading the server's private key");
		}		

		//Decrypt information with server's private key
		try{
			decryptedText = do_RSADecryption(finalCipherText, key);
		} catch(Exception e){
			System.out.println("Error decrypting with server's private key");
		}

		// Parse JSON and extract arguments
		JsonObject requestJson = JsonParser.parseString(decryptedText).getAsJsonObject();
		{
			preSecretMaster = Integer.parseInt(requestJson.get("preMasterSecret").getAsString());
		}

		preMasterSecret = preSecretMaster.toString();

		//Create secret key with preMasterSecret
		try{
			secretKeyinByte = digest(preMasterSecret.getBytes(UTF_8), "SHA3-256");
		} catch(Exception e){
			System.out.println("Error in SHA3");
		}
		secretKey = new SecretKeySpec(secretKeyinByte, 0, secretKeyinByte.length, "AES");

		// Create response message with connection established and send new token to check freshness of future messages
		JsonObject responseJson = JsonParser.parseString("{}").getAsJsonObject();
		{
				JsonObject infoJson = JsonParser.parseString("{}").getAsJsonObject();
				infoJson.addProperty("token", token.toString());
				responseJson.add("info", infoJson);
				String bodyText = "Connection established";
				responseJson.addProperty("body", bodyText);
		}

		//Encrypt data with secret key
		try{
			serverData = do_Encryption(responseJson.toString(), secretKey);
		} catch(Exception e){
			System.out.println("Error encrypting with secret key");
		}

		//Criar Hmac da mensagem que nos irá garantir integridade
		try{
			hmac = do_Encryption(digest(responseJson.toString().getBytes(UTF_8), "SHA3-256").toString(), secretKey);
		} catch (Exception e){
			System.out.println(e);
		}

		//Criar mensagem para enviar ao cliente
		JsonObject toSendResponse = JsonParser.parseString("{}").getAsJsonObject();
		{
			toSendResponse.addProperty("payload", Base64.getEncoder().encodeToString(serverData));
			toSendResponse.addProperty("hmac", Base64.getEncoder().encodeToString(hmac));
		}

		// Send response
		DatagramPacket serverPacket = new DatagramPacket(toSendResponse.toString().getBytes(), toSendResponse.toString().getBytes().length,
			clientPacketRSA.getAddress(), clientPacketRSA.getPort());
		try{
			socket.send(serverPacket);
		} catch(Exception e){
			System.out.println(e);
		}

		System.out.printf("Enviei %s\n", toSendResponse.toString());
	}
}