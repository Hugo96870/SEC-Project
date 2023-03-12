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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;


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

	private static byte[] buf = new byte[BUFFER_SIZE];

	private static Integer consensusCounter = 0;

	enum message_type{
		PREPREPARE,
		PREPARE,
		COMMIT;
	}

	//Key paths
	private static final String keyPathClientPublic = "keys/userPub.der";
	private static final String keyPathPriv = "keys/serverPriv.der";
	private static final String keyPathSecret = "keys/secret.key";

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

	public static void sendMessageToAll(message_type type, String valueToSend, List<Integer> serverPorts,
						Integer port, DatagramSocket socket){

		InetAddress serverToSend = null;

		System.out.printf("Vou enviar este tipo" + type + "\n");

		// Create request message
		JsonObject message = JsonParser.parseString("{}").getAsJsonObject();
		{
			message.addProperty("messageType", type.name());
			message.addProperty("instance", consensusCounter.toString());
			message.addProperty("value", valueToSend);
		}

		String clientData = null;

		try{
			clientData = do_Encryption(message.toString(), keyPathSecret);
		}
		catch (Exception e){
			System.out.printf("Encryption failed\n");
		}

		try{
			serverToSend = InetAddress.getByName("localhost");
		}catch (Exception e){
			System.out.printf("Cant resolve host\n");
		}

		for(int i = 0; i < serverPorts.size(); i++){
			if(!port.equals(serverPorts.get(i))){
				Integer portToSend = serverPorts.get(i);
				DatagramPacket prePreparePacket = new DatagramPacket(Base64.getDecoder().decode(clientData),
				Base64.getDecoder().decode(clientData).length, serverToSend, portToSend);
				try{
					socket.send(prePreparePacket);
					System.out.printf("Enviei este tipo" + type + " para" + serverPorts.get(i) + "\n");
				}catch (Exception e){
					System.out.printf("Cant send PrePrepare message\n");
				}
			}
		}
	}

	public static void broadcast(String text, Integer port, List<Integer> serverPorts, DatagramSocket socket){
		consensusCounter++;

		sendMessageToAll(message_type.PREPREPARE, text, serverPorts, port, socket);
	}

	public static String waitForQuorum(Map<String, List<Integer>> values, Integer consensusNumber,
							message_type type, DatagramSocket socket){
		
		//Cycle waitin for quorum
		while(true){
			DatagramPacket messageFromServer = new DatagramPacket(buf, buf.length);
			System.out.printf("Tou à espera deste pedido" + type + "\n");
			try{
				socket.receive(messageFromServer);
			}catch(Exception e){
				System.out.println("Failed to receive message");
			}
			String clientText = null;
			byte[] clientData = messageFromServer.getData();

			try{
				clientText = do_Decryption(Base64.getEncoder().encodeToString(clientData), keyPathSecret, messageFromServer.getLength());
			}
			catch(Exception e){
				System.out.println(e);
			}

			// Parse JSON and extract arguments
			JsonObject requestJson = JsonParser.parseString(clientText).getAsJsonObject();
			String messageType = null, instance = null, value = null;
			{
				messageType = requestJson.get("messageType").getAsString();
				instance = requestJson.get("instance").getAsString();
				value = requestJson.get("value").getAsString();
			}

			// If consensus instance is expected
			if(Integer.parseInt(instance) == consensusCounter){
				// If we receive message type expected
				if (messageType.equals(type.toString())){
					// Add to list of received
					if (values.get(value) != null){
						values.get(value).add(messageFromServer.getPort());
					}
					else{
						values.put(value, new ArrayList<Integer>());
						values.get(value).add(messageFromServer.getPort());
					}
					// If we reached consensus
					if(values.get(value).size() >= consensusNumber){
						System.out.printf("Acordamos este valor " + value + " para " + type + "\n");
						return value;
					}
				}
			}
		}
	}

	public static String leaderConsensus(DatagramSocket socket, Integer consensusNumber, String input,
								List<Integer> serverports, Integer port){

		Map<String, List<Integer>> prepareValues = new HashMap<String, List<Integer>>();
		Map<String, List<Integer>> commitValues = new HashMap<String, List<Integer>>();

		sendMessageToAll(message_type.PREPARE, input, serverports, port, socket);

		prepareValues.put(input, new ArrayList<Integer>());
		prepareValues.get(input).add(port);

		String valueAgreed = waitForQuorum(prepareValues, consensusNumber, message_type.PREPARE, socket);

		sendMessageToAll(message_type.COMMIT, valueAgreed, serverports, port, socket);

		commitValues.put(input, new ArrayList<Integer>());
		commitValues.get(input).add(port);

		String valueDecided = waitForQuorum(commitValues, consensusNumber, message_type.COMMIT, socket);

		if(!valueAgreed.equals(valueDecided)){
			return "No Decision";
		}

		return valueDecided;
	}

	public static String receivePrePrepare(DatagramSocket socket, Integer leaderPort){

		System.out.println("vou esperar por preprepare");

		while(true){
			DatagramPacket messageFromServer = new DatagramPacket(buf, buf.length);
			try{
				System.out.println("Estou à espera");
				socket.receive(messageFromServer);
				consensusCounter++;
				System.out.println("Recebi");
			}catch(Exception e){
				System.out.println("Failed to receive message");
			}
			String clientText = null;
			byte[] clientData = messageFromServer.getData();

			try{
				clientText = do_Decryption(Base64.getEncoder().encodeToString(clientData), keyPathSecret, messageFromServer.getLength());
			}
			catch(Exception e){
				System.out.println(e);
			}

			// Parse JSON and extract arguments
			JsonObject requestJson = JsonParser.parseString(clientText).getAsJsonObject();
			String messageType = null, instance = null, value = null;
			{
				messageType = requestJson.get("messageType").getAsString();
				instance = requestJson.get("instance").getAsString();
				value = requestJson.get("value").getAsString();
			}

			// If we receive message type expected
			System.out.printf("Tipo de mansagem %s %s\n", message_type.PREPREPARE.toString(), messageType);
			System.out.printf("Instancia %s %s\n", consensusCounter, instance);
			System.out.printf("leader %s %s\n", leaderPort, messageFromServer.getPort());
			if (messageType.equals(message_type.PREPREPARE.toString()) && Integer.parseInt(instance) == consensusCounter
													&& leaderPort == messageFromServer.getPort()){
				return value;
			}
		}

	}

	public static String normalConsensus(DatagramSocket socket, Integer consensusNumber, Integer leaderPort,
								List<Integer> serverports, Integer port){

		Map<String, List<Integer>> prepareValues = new HashMap<String, List<Integer>>();
		Map<String, List<Integer>> commitValues = new HashMap<String, List<Integer>>();

		String valueReceived = receivePrePrepare(socket, leaderPort);

		sendMessageToAll(message_type.PREPARE, valueReceived, serverports, port, socket);

		prepareValues.put(valueReceived, new ArrayList<Integer>());
		prepareValues.get(valueReceived).add(port);

		String valueAgreed = waitForQuorum(prepareValues, consensusNumber, message_type.PREPARE, socket);

		sendMessageToAll(message_type.COMMIT, valueAgreed, serverports, port, socket);

		commitValues.put(valueAgreed, new ArrayList<Integer>());
		commitValues.get(valueAgreed).add(port);

		String valueDecided = waitForQuorum(commitValues, consensusNumber, message_type.COMMIT, socket);

		if(valueAgreed != valueDecided){
			return "No Decision";
		}

		return valueDecided;
	}

	public static void respondToClient(String tokenRcvd, String keyPathPriv, String keyPathSecret, DatagramSocket socket,
										DatagramPacket clientPacket, String valueToSend){
			/* ------------------------------------- Consenso atingido, Enviar mensagem ao cliente ------------------------------ */
		String tokenToByte = null;

		System.out.println("Vou encriptar token");

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
			responseJson.addProperty("body", valueToSend);
		}

		System.out.println("Vou encriptar pedido");

		// Send response
		String serverData = null;
		try{
			serverData = do_Encryption(responseJson.toString(), keyPathSecret);
		}
		catch (Exception e){
			System.out.printf("Encryption failed\n");
		}
		
		DatagramPacket serverPacket = new DatagramPacket( Base64.getDecoder().decode(serverData), Base64.getDecoder().decode(serverData).length, clientPacket.getAddress(), clientPacket.getPort());
		
		try{
			socket.send(serverPacket);
		}catch(Exception e){
			System.out.println("Error when responding to client");
		}

		System.out.printf("Response packet sent to %s:%d!%n", clientPacket.getAddress(), clientPacket.getPort());

/* --------------------------------------------------------------------------------------------------------------------------- */
	}

	public static void main(String[] args) throws IOException {
		// Check arguments
		if (args.length < 3) {
			System.err.println("Argument(s) missing! You only provided " + args.length);
			System.err.printf("Usage: java %s port%n", SecureServer.class.getName());
			return;
		}

		//Parse Arguments
		Integer nrPorts = Integer.parseInt(args[0]);

		final Integer port = Integer.parseInt(args[1]);

		final int leaderPort = Integer.parseInt(args[2]);

		List<Integer> serverPorts = new ArrayList<Integer>(nrPorts);

		//Initialization algorithm variables
		String inputValue;
		String valueDecided;

		for(int i = 0; i < nrPorts; i++){
			serverPorts.add(8000 + i);
		}

		// Create server socket
		DatagramSocket socket = new DatagramSocket(port);
		System.out.printf("Server will receive packets on port %d %n", port);

		Integer consensusNumber = (nrPorts + (nrPorts-1)/3)/2 + 1;

		// Wait for client packets 
		byte[] buf = new byte[BUFFER_SIZE];
		while (true) {

			//Algoritmo 1
			if(port == leaderPort){
				System.out.println("Sou lider");

	/* ---------------------------------------Recebi mensagem do cliente e desencriptei------------------------------ */
				// Receive packet
				DatagramPacket clientPacket = new DatagramPacket(buf, buf.length);
				socket.receive(clientPacket);

				InetAddress clientAddress = clientPacket.getAddress();
				int clientPort = clientPacket.getPort();
				int clientLength = clientPacket.getLength();
				byte[] clientData = clientPacket.getData();

				String token = null;
				String tokenRcvd = null;
				String clientText = null;

				System.out.printf("Received request packet from %s:%d!%n", clientAddress, clientPort);

				System.out.println("Vou desencriptar pedido");

				// Convert request to string
				try{
					clientText = do_Decryption(Base64.getEncoder().encodeToString(clientData), keyPathSecret, clientLength);
				}
				catch(Exception e){
					System.out.println(e);
				}

				// Parse JSON and extract arguments
				JsonObject requestJson = JsonParser.parseString(clientText).getAsJsonObject();
				String body = null;
				{
					JsonObject infoJson = requestJson.getAsJsonObject("info");
					body = requestJson.get("body").getAsString();
					token = infoJson.get("token").getAsString();
				}

				inputValue = body;
				System.out.printf("Recebi esta mensagem: %s\n", body);

				System.out.println("Vou desencriptar token");

				try{
					tokenRcvd = do_RSADecryption(token, keyPathClientPublic);
				}
				catch (Exception e){
					System.out.printf("Identity invalid");
				}
/* --------------------------------------------------------------------------------------------------------------------------- */
	/* ------------------------------------- Broadcast da primeira mensagem ------------------------------ */

				broadcast(inputValue, port, serverPorts, socket);

/* --------------------------------------------------------------------------------------------------------------------------- */
			
			/* ------------------------------------- Algoritmo de consenso  ------------------------------ */

				valueDecided = leaderConsensus(socket, consensusNumber, inputValue, serverPorts, port);

/* --------------------------------------------------------------------------------------------------------------------------- */

				String response = "Adicionámos este valor à blockchain: " + valueDecided;

				respondToClient(tokenRcvd, keyPathPriv, keyPathSecret, socket, clientPacket, response);

			}
			else{
			/* ------------------------------------- Algoritmo de consenso  ------------------------------ */
				System.out.println("Sou normal");
				valueDecided = normalConsensus(socket, consensusNumber, leaderPort, serverPorts, port);

	/* --------------------------------------------------------------------------------------------------------------------------- */
			}
		}
	}
}