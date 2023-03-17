package pt.tecnico;

import java.net.*;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.Data;

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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Callable;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

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

	private static final Charset UTF_8 = StandardCharsets.UTF_8;

	private static Integer consensusCounter = 0;

	enum message_type{
		PREPREPARE,
		PREPARE,
		COMMIT;
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

	public static boolean checkIntegrity(String hmac, JsonObject requestJson){
		//Verify integrity with hmac
		byte[] hmacToCheck = null;
		try{
			hmacToCheck = digest(requestJson.toString().getBytes(UTF_8), "SHA3-256");
		}catch (IllegalArgumentException e){
			System.out.println("Failed to hash value");
		}

		if(Base64.getEncoder().encodeToString(hmacToCheck).equals(hmac)){
			return true;
		}
		return false;
	}

	public static void sendMessageToAll(message_type type, String valueToSend, List<Integer> serverPorts,
						Integer port, DatagramSocket socket, Integer consensusNumber){

		InetAddress serverToSend = null;

		try{
			serverToSend = InetAddress.getByName("localhost");
		}catch (Exception e){
			System.out.printf("Cant resolve host\n");
		}

		//Send message to servers
		System.out.println("Vou enviar pedidos do tipo: " + type);

		ExecutorService executorService = Executors.newFixedThreadPool(serverPorts.size());
		List<sendAndReceiveAck> myThreads = new ArrayList<>();

		Integer basePort = 8000;

		for(int i = 0; i < serverPorts.size(); i++){
			//We dont send message to ourselves, only assume we sent and received it
			if(!port.equals(serverPorts.get(i))){
				Integer portToSend = serverPorts.get(i);

				// Create request message
				JsonObject message = null;
				try{
					message = JsonParser.parseString("{}").getAsJsonObject();
					{
						message.addProperty("messageType", type.name());
						message.addProperty("instance", consensusCounter.toString());
						message.addProperty("value", valueToSend);
						message.addProperty("idMainProcess", ((Integer)(port % basePort)).toString());
					}
				} catch (Exception e){
					System.out.println("Failed to parse Json and arguments");
				}
			

				//Create hmac to assure integrity
				byte[] hmac = null;
				try{
					hmac = digest(message.toString().getBytes(UTF_8), "SHA3-256");
				}catch (IllegalArgumentException e){
					System.out.println("Failed to hash value");
				}

				//ENVIAR HMAC EM BASE 64
				JsonObject messageWithHMAC = JsonParser.parseString("{}").getAsJsonObject();
				{
					messageWithHMAC.addProperty("payload", message.toString());
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

				//Create datagram
				DatagramPacket packet = null;
				try{
					packet = new DatagramPacket(Base64.getDecoder().decode(clientData),
					Base64.getDecoder().decode(clientData).length, serverToSend, portToSend);
				} catch (Exception e){
					System.out.println("Failed to create Datagram");
				}

				myThreads.add(new sendAndReceiveAck(packet, serverPorts.get(i)));

			}
		}

		try{
			for(int i = 0; i < serverPorts.size() - 1; i++){
				executorService.submit(myThreads.get(i));
			}
		}catch(Exception e){
			System.out.println("Error launching threads");
		}
	}

	public static void broadcast(String text, Integer port, List<Integer> serverPorts, DatagramSocket socket, Integer consensusNumber){
		consensusCounter++;

		sendMessageToAll(message_type.PREPREPARE, text, serverPorts, port, socket, consensusNumber);
	}

	public static String waitForQuorum(Map<String, List<Integer>> values, Integer consensusNumber,
							message_type type, DatagramSocket socket){

		//Cycle waitin for quorum
		String messageType = null, instance = null, value = null, idMainProcess = null;
		while(true){
			DatagramPacket messageFromServer = new DatagramPacket(buf, buf.length);
			System.out.printf("Tou à espera deste pedido " + type + "\n");
			try{

				socket.receive(messageFromServer);

				String clientText = null;
				byte[] clientData = messageFromServer.getData();
	
				try{
					clientText = do_Decryption(Base64.getEncoder().encodeToString(clientData), keyPathSecret, messageFromServer.getLength());
				}
				catch(Exception e){
					System.out.println("Decryption with AES failed");
				}

				//Parse Json with payload and hmac
				JsonObject received = JsonParser.parseString(clientText).getAsJsonObject();
				String hmac = null, receivedFromJson = null;
				{
					hmac = received.get("hmac").getAsString();
					receivedFromJson = received.get("payload").getAsString();
				}

				// Parse JSON and extract arguments
				JsonObject requestJson = null;
				try{
					requestJson = JsonParser.parseString(receivedFromJson).getAsJsonObject();
				} catch (Exception e){
					System.out.println("Failed to parse Json received");
				}

				boolean integrityCheck = checkIntegrity(hmac, requestJson);

				if(!integrityCheck){
					System.out.println("Integrity violated");
				}
				else{
					try{
						{
							messageType = requestJson.get("messageType").getAsString();
							instance = requestJson.get("instance").getAsString();
							value = requestJson.get("value").getAsString();
							idMainProcess = requestJson.get("idMainProcess").getAsString();
						}
					} catch (Exception e){
						System.out.println("Failed to extract arguments from Json payload");
					}

	
					// Create request message
					JsonObject message = JsonParser.parseString("{}").getAsJsonObject();
					{
						message.addProperty("value", "ack");
					}

					String clientDataToSend = null;
					try{
						clientDataToSend = do_Encryption(message.toString(), keyPathSecret);
					}catch(Exception e){
						System.out.println("Failed to encrypt data with AES");
					}
	
					DatagramPacket ackPacket = new DatagramPacket(Base64.getDecoder().decode(clientDataToSend),
					Base64.getDecoder().decode(clientDataToSend).length,  messageFromServer.getAddress(), messageFromServer.getPort());
	
					//send ack datagram
					socket.send(ackPacket);

					// If consensus instance is expected
					if(Integer.parseInt(instance) == consensusCounter){
						// If we receive message type expected
						if (messageType.equals(type.toString())){
							// Add to list of received
							if (values.get(value) != null){
								if(!values.get(value).contains(8000 + Integer.parseInt(idMainProcess))){
									values.get(value).add(8000 + Integer.parseInt(idMainProcess));
								}
							}
							else{
								values.put(value, new ArrayList<Integer>());
								values.get(value).add(8000 + Integer.parseInt(idMainProcess));
							}
							// If we reached consensus
							if(values.get(value).size() >= consensusNumber){
								System.out.printf("Acordamos este valor " + value + " para " + type + "\n");
								return value;
							}
						}
					}
				}

			}catch(Exception e){
				System.out.println("Failed to receive or send message");
			}
		}
	}

	public static String leaderConsensus(DatagramSocket socket, Integer consensusNumber, String input,
								List<Integer> serverports, Integer port){

		//Create prepare and commit messages maps
		Map<String, List<Integer>> prepareValues = new HashMap<String, List<Integer>>();
		Map<String, List<Integer>> commitValues = new HashMap<String, List<Integer>>();

		//Send Prepare to all, we assume we received preprepare from ourselves
		sendMessageToAll(message_type.PREPARE, input, serverports, port, socket, consensusNumber);

		//add value to prepare map
		prepareValues.put(input, new ArrayList<Integer>());
		prepareValues.get(input).add(port);

		//wait for prepare quorum
		String valueAgreed = waitForQuorum(prepareValues, consensusNumber, message_type.PREPARE, socket);

		//Once the quorum is reached, send commit to all
		sendMessageToAll(message_type.COMMIT, valueAgreed, serverports, port, socket, consensusNumber);

		//add value to commit map
		commitValues.put(input, new ArrayList<Integer>());
		commitValues.get(input).add(port);

		//wait for commit quorum
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
				//Receive Preprepare
				socket.receive(messageFromServer);

				// Create request message
				JsonObject message = JsonParser.parseString("{}").getAsJsonObject();
				{
					message.addProperty("value", "ack");
				}

				String clientData = do_Encryption(message.toString(), keyPathSecret);

				DatagramPacket ackPacket = new DatagramPacket(Base64.getDecoder().decode(clientData),
				Base64.getDecoder().decode(clientData).length,  messageFromServer.getAddress(), messageFromServer.getPort());

				String clientText = null;
				byte[] clientDataReceived = messageFromServer.getData();
	
				//Decrypt message received with aes and simetric key
				try{
					clientText = do_Decryption(Base64.getEncoder().encodeToString(clientDataReceived), keyPathSecret, messageFromServer.getLength());
				}
				catch(Exception e){
					System.out.println(e);
				}

				//Parse json with payload and Hmac
				JsonObject received = JsonParser.parseString(clientText).getAsJsonObject();
				String hmac = null, receivedFromJson = null;
				{
					hmac = received.get("hmac").getAsString();
					receivedFromJson = received.get("payload").getAsString();
				}

				// Parse JSON and extract arguments
				JsonObject requestJson = JsonParser.parseString(receivedFromJson).getAsJsonObject();

				boolean integrityCheck = checkIntegrity(hmac, requestJson);

				if(!integrityCheck){
					System.out.println("Integrity violated");
				}
				else{
					System.out.println("Integrity checked");
					String messageType = null, instance = null, value = null, idMainProcess = null;
					{
						messageType = requestJson.get("messageType").getAsString();
						instance = requestJson.get("instance").getAsString();
						value = requestJson.get("value").getAsString();
						idMainProcess = requestJson.get("idMainProcess").getAsString();
					}
	
					//send ack datagram
					if(leaderPort == 8000 + Integer.parseInt(idMainProcess)){
						socket.send(ackPacket);
						System.out.println("Recebi preprepare do lider");
					}
	
					// If we receive message type expected
					if (messageType.equals(message_type.PREPREPARE.toString()) && Integer.parseInt(instance) == consensusCounter + 1
						&& leaderPort == 8000 + Integer.parseInt(idMainProcess)){
						consensusCounter++;
						return value;
					}
				}

			}catch(Exception e){
				System.out.println("Failed to receive message");
			}
		}
	}

	public static String normalConsensus(DatagramSocket socket, Integer consensusNumber, Integer leaderPort,
								List<Integer> serverports, Integer port){

		//Create commit and prepare maps
		Map<String, List<Integer>> prepareValues = new HashMap<String, List<Integer>>();
		Map<String, List<Integer>> commitValues = new HashMap<String, List<Integer>>();

		//Wait for preprepare message
		String valueReceived = receivePrePrepare(socket, leaderPort);

		//send prepare message to all
		sendMessageToAll(message_type.PREPARE, valueReceived, serverports, port, socket, consensusNumber);

		//add value of preprepare to map
		prepareValues.put(valueReceived, new ArrayList<Integer>());
		prepareValues.get(valueReceived).add(port);

		//wait for prepare quorum
		String valueAgreed = waitForQuorum(prepareValues, consensusNumber, message_type.PREPARE, socket);

		//send commit message to all
		sendMessageToAll(message_type.COMMIT, valueAgreed, serverports, port, socket, consensusNumber);

		//add value sent in commits to commit map
		commitValues.put(valueAgreed, new ArrayList<Integer>());
		commitValues.get(valueAgreed).add(port);

		//wait for commit quorum
		String valueDecided = waitForQuorum(commitValues, consensusNumber, message_type.COMMIT, socket);

		if(!valueAgreed.equals(valueDecided)){
			return "No Decision";
		}

		return valueDecided;
	}

	//Byzantine process doesnt respect Prepare and Commit values
	public static String byzantineProcessPC(DatagramSocket socket, Integer consensusNumber, Integer leaderPort,
		List<Integer> serverports, Integer port){

			Map<String, List<Integer>> prepareValues = new HashMap<String, List<Integer>>();
			Map<String, List<Integer>> commitValues = new HashMap<String, List<Integer>>();

			receivePrePrepare(socket, leaderPort);

			sendMessageToAll(message_type.PREPARE, "Vou trollar", serverports, port, socket, consensusNumber);

			prepareValues.put("Vou trollar", new ArrayList<Integer>());
			prepareValues.get("Vou trollar").add(port);

			waitForQuorum(prepareValues, consensusNumber, message_type.PREPARE, socket);

			sendMessageToAll(message_type.COMMIT, "Vou trollar no commit", serverports, port, socket, consensusNumber);

			commitValues.put("Vou trollar no commit", new ArrayList<Integer>());
			commitValues.get("Vou trollar no commit").add(port);

			String valueDecided = waitForQuorum(commitValues, consensusNumber, message_type.COMMIT, socket);

			if("Vou trollar no commit" != valueDecided){
				return "No Decision";
			}

		return valueDecided;
	}

	//Byzantine process tries to send PrePrepare even though he is not the leader and doesnt respect Prepare and Commit messages
	public static String byzantineProcessPP(DatagramSocket socket, Integer consensusNumber, Integer leaderPort,
	List<Integer> serverports, Integer port){

		Map<String, List<Integer>> prepareValues = new HashMap<String, List<Integer>>();
		Map<String, List<Integer>> commitValues = new HashMap<String, List<Integer>>();

		broadcast("Vou trollar no prePrepare", port, serverports, socket, consensusNumber);

		sendMessageToAll(message_type.PREPARE, "Vou trollar", serverports, port, socket, consensusNumber);

		prepareValues.put("Vou trollar", new ArrayList<Integer>());
		prepareValues.get("Vou trollar").add(port);

		waitForQuorum(prepareValues, consensusNumber, message_type.PREPARE, socket);

		sendMessageToAll(message_type.COMMIT, "Vou trollar no commit", serverports, port, socket, consensusNumber);

		commitValues.put("Vou trollar no commit", new ArrayList<Integer>());
		commitValues.get("Vou trollar no commit").add(port);

		String valueDecided = waitForQuorum(commitValues, consensusNumber, message_type.COMMIT, socket);

		if("Vou trollar no commit" != valueDecided){
			return "No Decision";
		}

		return valueDecided;
	}

	//Byzantine process sends several COMMITs and PREPAREs to other servers not respecting the algorithm
	public static String byzantineProcessPCT(DatagramSocket socket, Integer consensusNumber, Integer leaderPort,
	List<Integer> serverports, Integer port){

		Map<String, List<Integer>> prepareValues = new HashMap<String, List<Integer>>();
		Map<String, List<Integer>> commitValues = new HashMap<String, List<Integer>>();

		receivePrePrepare(socket, leaderPort);

		sendMessageToAll(message_type.PREPARE, "Vou trollar", serverports, port, socket, consensusNumber);
		sendMessageToAll(message_type.PREPARE, "Vou trollar", serverports, port, socket, consensusNumber);
		sendMessageToAll(message_type.PREPARE, "Vou trollar", serverports, port, socket, consensusNumber);

		prepareValues.put("Vou trollar", new ArrayList<Integer>());
		prepareValues.get("Vou trollar").add(port);

		waitForQuorum(prepareValues, consensusNumber, message_type.PREPARE, socket);

		sendMessageToAll(message_type.COMMIT, "Vou trollar no commit", serverports, port, socket, consensusNumber);
		sendMessageToAll(message_type.COMMIT, "Vou trollar no commit", serverports, port, socket, consensusNumber);
		sendMessageToAll(message_type.COMMIT, "Vou trollar no commit", serverports, port, socket, consensusNumber);

		commitValues.put("Vou trollar no commit", new ArrayList<Integer>());
		commitValues.get("Vou trollar no commit").add(port);

		String valueDecided = waitForQuorum(commitValues, consensusNumber, message_type.COMMIT, socket);

		if("Vou trollar no commit" != valueDecided){
			return "No Decision";
		}

		return valueDecided;
	}

	//Sends encrypted message to client confirming the string appended
	public static void respondToClient(String tokenRcvd, String keyPathPriv, String keyPathSecret, DatagramSocket socket,
										DatagramPacket clientPacket, String valueToSend){
			/* ------------------------------------- Consenso atingido, Enviar mensagem ao cliente ------------------------------ */
		String tokenToByte = null;

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

		//Create hmac to assure integrity
		byte[] hmac = null;
		try{
			hmac = digest(responseJson.toString().getBytes(UTF_8), "SHA3-256");
		}catch (IllegalArgumentException e){
			System.out.println("Failed to hash value");
		}

		//ENVIAR HMAC EM BASE 64
		JsonObject messageWithHMAC = JsonParser.parseString("{}").getAsJsonObject();
		{
			messageWithHMAC.addProperty("payload", responseJson.toString());
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
		
		DatagramPacket serverPacket = new DatagramPacket( Base64.getDecoder().decode(clientData), Base64.getDecoder().decode(clientData).length, clientPacket.getAddress(), clientPacket.getPort());
		
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

		final String serverType = args[3];

		//Initialization algorithm variables
		String inputValue;
		String valueDecided;

		List<Integer> serverPorts = new ArrayList<Integer>(nrPorts);

		for(int i = 0; i < nrPorts; i++){
			serverPorts.add(8000 + i);
		}

		// Create server socket
		DatagramSocket socket = new DatagramSocket(port);
		System.out.printf("Server will receive packets on port %d %n", port);

		Integer consensusNumber = (nrPorts + (nrPorts-1)/3)/2 + 1;

		Map<Integer, String> consensusRounds = new HashMap<Integer,String>();

		List<DatagramPacket> requests = new ArrayList<>();

		BlockingQueue<DatagramPacket> queue = new LinkedBlockingQueue<>();

		Callable<Void> callable = new receiveString(requests, 9999, queue);

		ExecutorService executor = Executors.newSingleThreadExecutor();

		executor.submit(callable);

		// Wait for client packets 
		while (true) {

			//Algoritmo 1
			if(port == leaderPort){
				System.out.println("Sou lider");
	/* ---------------------------------------Recebi mensagem do cliente e desencriptei------------------------------ */

				DatagramPacket clientPacket = null;
				Integer flag = 0;
				try{
					while(flag.equals(0)){
						clientPacket = queue.take();
						flag = 1;
					}
				} catch (Exception e){
					System.out.println("Queue error");
				}

				byte[] clientData = clientPacket.getData();

				String clientText = null;

				try{
					clientText = do_Decryption(Base64.getEncoder().encodeToString(clientData), keyPathSecret, clientPacket.getLength());
				}
				catch(Exception e){
					System.out.println("Decryption with AES failed");
				}

				//Parse Json with payload and hmac
				JsonObject received = JsonParser.parseString(clientText).getAsJsonObject();
				String hmac = null, receivedFromJson = null;
				{
					hmac = received.get("hmac").getAsString();
					receivedFromJson = received.get("payload").getAsString();
				}

				// Parse JSON and extract arguments
				JsonObject requestJson = null;
				try{
					requestJson = JsonParser.parseString(receivedFromJson).getAsJsonObject();
				} catch (Exception e){
					System.out.println("Failed to parse Json received");
				}

				boolean integrityCheck = checkIntegrity(hmac, requestJson);

				if(!integrityCheck){
					System.out.println("Integrity violated");
				}

				// Parse JSON and extract arguments
				requestJson = JsonParser.parseString(receivedFromJson).getAsJsonObject();
				String token = null;
				String tokenRcvd = null;
				String body = null;
				{
					JsonObject infoJson = requestJson.getAsJsonObject("info");
					body = requestJson.get("body").getAsString();
					token = infoJson.get("token").getAsString();
				}

				inputValue = body;
				
				//Decrypt autentication token
				try{
					tokenRcvd = do_RSADecryption(token, keyPathClientPublic);
				}
				catch (Exception e){
					System.out.printf("Identity invalid");
				}
/* --------------------------------------------------------------------------------------------------------------------------- */
	/* ------------------------------------- Broadcast PREPREPARE message ------------------------------ */

				broadcast(inputValue, port, serverPorts, socket, consensusNumber);

/* --------------------------------------------------------------------------------------------------------------------------- */
			
			/* ------------------------------------- Algoritmo de consenso  ------------------------------ */

				valueDecided = leaderConsensus(socket, consensusNumber, inputValue, serverPorts, port);

/* --------------------------------------------------------------------------------------------------------------------------- */

				String response = valueDecided + "\n";

				respondToClient(tokenRcvd, keyPathPriv, keyPathSecret, socket, clientPacket, response);

				consensusRounds.put(consensusCounter,valueDecided);

			}
			else if (serverType.equals("N")){
			/* ------------------------------------- Algoritmo de consenso  ------------------------------ */
				System.out.println("Sou normal");
				valueDecided = normalConsensus(socket, consensusNumber, leaderPort, serverPorts, port);

				System.out.printf("Sou normal e concordamos com isto: " + valueDecided + "\n");

				consensusRounds.put(consensusCounter, valueDecided);

	/* --------------------------------------------------------------------------------------------------------------------------- */
			}

			// Caso o processo seja bizantino e não respeite o valor as mensagens COMMIT e PREPARE
			else if (serverType.equals("B-PC")){
				valueDecided = byzantineProcessPC(socket, consensusNumber, leaderPort, serverPorts, port);

				System.out.printf("Sou bizantino e tentei trollar mas não deu e eles concordaram nisto " + valueDecided);
			}
			// Caso o processo seja bizantino e não respeite as mensagens PREPREPARE e o valor dos COMMITs e PREPAREs
			else if (serverType.equals("B-PP")){
				valueDecided = byzantineProcessPP(socket, consensusNumber, leaderPort, serverPorts, port);

				System.out.printf("Sou bizantino e tentei trollar mas não deu e eles concordaram nisto " + valueDecided);
			}
			// Caso o processo seja bizantino e envie várias vezes PREPARE E COMMIT fora de ordem
			else if (serverType.equals("B-PC-T")){
				valueDecided = byzantineProcessPCT(socket, consensusNumber, leaderPort, serverPorts, port);

				System.out.printf("Sou bizantino e tentei trollar mas não deu e eles concordaram nisto " + valueDecided);
			}
		}
	}
}