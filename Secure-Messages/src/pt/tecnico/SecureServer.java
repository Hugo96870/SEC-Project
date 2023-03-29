package pt.tecnico;

import java.net.*;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import pt.tecnico.IBFT_Functions.message_type;
import pt.tecnico.blockChain.server_type;
import java.util.Base64;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Callable;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.*;

public class SecureServer {

	private static auxFunctions auxF = new auxFunctions();
	private static IBFT_Functions ibft_f = new IBFT_Functions();
	//private static byzantineBehaviours byzB = new byzantineBehaviours(ibft_f);

	//Key paths
	private final static String keyPathPubAlice = "keys/userPub.der";
	private final static String keyPathPubBob = "keys/userBobPub.der";
	private final static String keyPathPubCharlie = "keys/userCharliePub.der";
	private static final String keyPathPriv = "keys/serverPriv.der";
	private static final String keyPathPriv1 = "keys/serverPriv1.der";
	private static final String keyPathPriv2 = "keys/serverPriv2.der";
	private static final String keyPathPriv3 = "keys/serverPriv3.der";
	final static String keyPathSecret = "keys/secret.key";

	private static SecretKey key;
	private static String pMS;

	public static operation parseInput(DatagramPacket clientPacket, String pathToKey){
	
		String clientText = null;
		try{
			clientText = auxF.ConvertReceived(Base64.getEncoder().encodeToString(clientPacket.getData()), clientPacket.getLength());
		}catch (Exception e){
			System.err.println("Error parsing arguments");
			System.err.println(e.getMessage());
		}

		//Parse Json with payload and hmac
		JsonObject received = JsonParser.parseString(clientText).getAsJsonObject();
		String receivedFromJson = null, preMS = null;
		{
			receivedFromJson = received.get("payload").getAsString();
			preMS = received.get("PMS").getAsString();
		}

		String pMSDecrypted = null;
		try{
			pMSDecrypted = auxF.do_RSADecryption(preMS, pathToKey);
		}catch (Exception e){
			System.err.println("Error in assymetric decryption");
			System.err.println(e.getMessage());
		}

		pMS = pMSDecrypted;

		byte[] secretKeyinByte = auxF.digest(pMSDecrypted.getBytes(auxF.UTF_8), "SHA3-256");
		key = new SecretKeySpec(secretKeyinByte, 0, secretKeyinByte.length, "AES");

		try{
			receivedFromJson = auxF.do_Decryption(receivedFromJson, key, Base64.getDecoder().decode(receivedFromJson).length);
		}catch (Exception e){
			System.err.println("Error in symetric decryption");
			System.err.println(e.getMessage());
		}

		// Parse JSON and extract arguments
		JsonObject requestJson = null;
		try{
			requestJson = JsonParser.parseString(receivedFromJson).getAsJsonObject();
		} catch (Exception e){
			System.err.println("Failed to parse Json received");
			System.err.println(e.getMessage());
		}

		// Parse JSON and extract arguments
		requestJson = JsonParser.parseString(receivedFromJson).getAsJsonObject();
		String type = null;
		{
			type = requestJson.get("type").getAsString();
		}
		operation op = null;
		PublicKey keySrc = null, keyDest = null;
		byte[] keySource = null, keyDestination = null;
		switch(type){
			case("CREATE"):
				String pubKey = null;
				{
					pubKey = requestJson.get("pubKey").getAsString();
				}

				try{
					keySource = pubKey.getBytes("UTF-8");
				} catch(Exception e){
					System.err.println("Error converting key");
					System.err.println(e.getMessage());
				}

				keySrc = auxF.convertByteIntoPK(keySource);
				
				op = new operation("CREATE", keySrc);
				break;
			case("TRANSFER"):
				String source = null, dest = null, amount = null;
				{
					source = requestJson.get("source").getAsString();
					dest = requestJson.get("dest").getAsString();
					amount = requestJson.get("amount").getAsString();
				}

				try{
					keyDestination = dest.getBytes("UTF-8");
					keySource = source.getBytes("UTF-8");
				} catch(Exception e){
					System.err.println("Error converting key");
					System.err.println(e.getMessage());
				}

				keyDest = auxF.convertByteIntoPK(keyDestination);
				keySrc = auxF.convertByteIntoPK(keySource);

				op = new operation("TRANSFER", keySrc, keyDest, Integer.parseInt(amount));
				break;
			default:
				break;
		}

		return op;
	}


	public static String receivePrePrepare(DatagramSocket socket, Integer leaderPort, Integer instanceNumber){

		System.out.println("I will wait for PREPREPARE");

		while(true){
			DatagramPacket messageFromServer = new DatagramPacket(ibft_f.buf, ibft_f.buf.length);
			try{
				//Receive Preprepare
				socket.receive(messageFromServer);

				// Create request message
				JsonObject message = JsonParser.parseString("{}").getAsJsonObject();
				{
					message.addProperty("value", "ack");
				}

				String clientData = auxF.ConvertToSend(message.toString());

				DatagramPacket ackPacket = new DatagramPacket(Base64.getDecoder().decode(clientData),
				Base64.getDecoder().decode(clientData).length,  messageFromServer.getAddress(), messageFromServer.getPort());

				String clientText = auxF.ConvertReceived(Base64.getEncoder().encodeToString(messageFromServer.getData()), messageFromServer.getLength());

				//Parse json with payload and Hmac
				JsonObject received = JsonParser.parseString(clientText).getAsJsonObject();
				String hmac = null, receivedFromJson = null;
				{
					hmac = received.get("hmac").getAsString();
					receivedFromJson = received.get("payload").getAsString();
				}

				// Parse JSON and extract arguments
				JsonObject requestJson = JsonParser.parseString(receivedFromJson).getAsJsonObject();

				boolean integrityCheck = auxF.checkIntegrity(hmac, requestJson);

				if(!integrityCheck){
					System.err.println("Integrity violated");
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
					}
	
					// If we receive message type expected
					if (messageType.equals(message_type.PREPREPARE.toString()) && Integer.parseInt(instance) == instanceNumber + 1
						&& leaderPort == 8000 + Integer.parseInt(idMainProcess)){
						return value;
					}
				}

			}catch(Exception e){
				System.err.println("Failed to receive message");
			}
		}
	}

	public static String leaderConsensus(DatagramSocket socket, Integer consensusNumber, String input,
								List<Integer> serverports, Integer port, blockChain bC){

		//Create prepare and commit messages maps
		Map<String, List<Integer>> prepareValues = new HashMap<String, List<Integer>>();
		Map<String, List<Integer>> commitValues = new HashMap<String, List<Integer>>();

		//Send Prepare to all, we assume we received preprepare from ourselves
		ibft_f.sendMessageToAll(message_type.PREPARE, input, serverports, port, socket, consensusNumber, bC.getInstance());

		//add value to prepare map
		prepareValues.put(input, new ArrayList<Integer>());
		prepareValues.get(input).add(port);

		//wait for prepare quorum
		String valueAgreed = ibft_f.waitForQuorum(prepareValues, consensusNumber, message_type.PREPARE, socket, bC.getInstance());

		//Once the quorum is reached, send commit to all
		ibft_f.sendMessageToAll(message_type.COMMIT, valueAgreed, serverports, port, socket, consensusNumber, bC.getInstance());

		//add value to commit map
		commitValues.put(input, new ArrayList<Integer>());
		commitValues.get(input).add(port);

		//wait for commit quorum
		String valueDecided = ibft_f.waitForQuorum(commitValues, consensusNumber, message_type.COMMIT, socket, bC.getInstance());

		if(!valueAgreed.equals(valueDecided)){
			return "No Decision";
		}

		return valueDecided;
	}

	public static String normalConsensus(DatagramSocket socket, Integer consensusNumber, Integer leaderPort,
								List<Integer> serverports, Integer port, blockChain bC){

		//Create commit and prepare maps
		Map<String, List<Integer>> prepareValues = new HashMap<String, List<Integer>>();
		Map<String, List<Integer>> commitValues = new HashMap<String, List<Integer>>();

		//Wait for preprepare message
		String valueReceived = receivePrePrepare(socket, leaderPort, bC.getInstance());
		bC.increaseInstance();

		//send prepare message to all
		ibft_f.sendMessageToAll(message_type.PREPARE, valueReceived, serverports, port, socket, consensusNumber, bC.getInstance());

		//add value of preprepare to map
		prepareValues.put(valueReceived, new ArrayList<Integer>());
		prepareValues.get(valueReceived).add(port);

		//wait for prepare quorum
		String valueAgreed = ibft_f.waitForQuorum(prepareValues, consensusNumber, message_type.PREPARE, socket, bC.getInstance());

		//send commit message to all
		ibft_f.sendMessageToAll(message_type.COMMIT, valueAgreed, serverports, port, socket, consensusNumber, bC.getInstance());

		//add value sent in commits to commit map
		commitValues.put(valueAgreed, new ArrayList<Integer>());
		commitValues.get(valueAgreed).add(port);

		//wait for commit quorum
		String valueDecided = ibft_f.waitForQuorum(commitValues, consensusNumber, message_type.COMMIT, socket, bC.getInstance());

		if(!valueAgreed.equals(valueDecided)){
			return "No Decision";
		}

		return valueDecided;
	}

	//Sends encrypted message to client confirming the string appended
	public static void respondToClient(String keyPathPriv,
									DatagramSocket socket, String valueToSend, Integer port, SecretKey key, String pms, int clientPort){
		/* ------------------------------------- Consenso atingido, Enviar mensagem ao cliente ------------------------------ */

		// Create response message
		JsonObject responseJson = JsonParser.parseString("{}").getAsJsonObject();
		{
			responseJson.addProperty("body", valueToSend);
		}

		String clientData = null;
		try{
			clientData = auxF.do_Encryption(responseJson.toString(), key);
		}
		catch (Exception e){
			System.err.printf("AES encryption failed\n");
			System.err.println(e.getMessage());
		}

		String pMSEncrypted = null;
		try{
			pMSEncrypted = auxF.do_RSAEncryption(pms, keyPathPriv);
		}
		catch (Exception e){
			System.err.printf("RSA encryption failed\n");
			System.err.println(e.getMessage());
		}

		JsonObject message = JsonParser.parseString("{}").getAsJsonObject();
		{
			message.addProperty("payload", clientData);
			message.addProperty("PMS", pMSEncrypted);
		}

		String dataToSend = null;
		try{
			dataToSend = auxF.ConvertToSend(message.toString());
		}
		catch (Exception e){
			System.err.printf("Error parsing\n");
			System.err.println(e.getMessage());
		}

		// Create Datagram Packet
		InetAddress hostToSend = null;
		try{
			hostToSend = InetAddress.getByName("localhost");
		}catch (Exception e){
			System.err.printf("Cant resolve host\n");
			System.err.println(e.getMessage());
		}

		DatagramPacket serverPacket = new DatagramPacket( Base64.getDecoder().decode(dataToSend),
						Base64.getDecoder().decode(dataToSend).length, hostToSend, clientPort);
		
		Callable<Integer> callable = new sendAndReceiveAck(serverPacket, clientPort, port + 4000);

		ExecutorService executor = Executors.newSingleThreadExecutor();

		Future<Integer> future = executor.submit(callable);

		try{
			future.get();
		} catch (Exception e){
			System.err.println("Failed to wait for thread");
			System.err.println(e.getMessage());
		}
		System.out.printf("Response packet sent to %s:%d! and received ack \n", hostToSend, clientPort);

	}

	//Byzantine process doesnt respect Prepare and Commit values
	public static String byzantineProcessPC(DatagramSocket socket, Integer consensusNumber, Integer leaderPort,
							List<Integer> serverports, Integer port, blockChain bC){

		Map<String, List<Integer>> prepareValues = new HashMap<String, List<Integer>>();
		Map<String, List<Integer>> commitValues = new HashMap<String, List<Integer>>();

		receivePrePrepare(socket, leaderPort, bC.getInstance());

		ibft_f.sendMessageToAll(message_type.PREPARE, "Vou trollar", serverports, port, socket, consensusNumber, bC.getInstance());

		prepareValues.put("Vou trollar", new ArrayList<Integer>());
		prepareValues.get("Vou trollar").add(port);

		ibft_f.waitForQuorum(prepareValues, consensusNumber, message_type.PREPARE, socket, bC.getInstance());

		ibft_f.sendMessageToAll(message_type.COMMIT, "Vou trollar no commit", serverports, port, socket, consensusNumber, bC.getInstance());

		commitValues.put("Vou trollar no commit", new ArrayList<Integer>());
		commitValues.get("Vou trollar no commit").add(port);

		String valueDecided = ibft_f.waitForQuorum(commitValues, consensusNumber, message_type.COMMIT, socket, bC.getInstance());

		if("Vou trollar no commit" != valueDecided){
			return "No Decision";
		}

		return valueDecided;
	}

	//Byzantine process tries to send PrePrepare even though he is not the leader and doesnt respect Prepare and Commit messages
	public static String byzantineProcessPP(DatagramSocket socket, Integer consensusNumber, Integer leaderPort,
						List<Integer> serverports, Integer port, blockChain bC){

		Map<String, List<Integer>> prepareValues = new HashMap<String, List<Integer>>();
		Map<String, List<Integer>> commitValues = new HashMap<String, List<Integer>>();

		bC.increaseInstance();
		ibft_f.sendMessageToAll(message_type.PREPREPARE, "Vou trollar", bC.getPorts(), port,
								socket,  bC.getConsensusMajority(), bC.getInstance());

		ibft_f.sendMessageToAll(message_type.PREPARE, "Vou trollar", serverports,
								port, socket, consensusNumber, bC.getInstance());

		prepareValues.put("Vou trollar", new ArrayList<Integer>());
		prepareValues.get("Vou trollar").add(port);

		ibft_f.waitForQuorum(prepareValues, consensusNumber, message_type.PREPARE, socket, bC.getInstance());

		ibft_f.sendMessageToAll(message_type.COMMIT, "Vou trollar no commit",
									serverports, port, socket, consensusNumber, bC.getInstance());

		commitValues.put("Vou trollar no commit", new ArrayList<Integer>());
		commitValues.get("Vou trollar no commit").add(port);

		String valueDecided = ibft_f.waitForQuorum(commitValues, consensusNumber, message_type.COMMIT, socket, bC.getInstance());

		if("Vou trollar no commit" != valueDecided){
			return "No Decision";
		}

		return valueDecided;
	}

	//Byzantine process sends several COMMITs and PREPAREs to other servers not respecting the algorithm
	public static String byzantineProcessPCT(DatagramSocket socket, Integer consensusNumber, Integer leaderPort,
					List<Integer> serverports, Integer port, blockChain bC){

		Map<String, List<Integer>> prepareValues = new HashMap<String, List<Integer>>();
		Map<String, List<Integer>> commitValues = new HashMap<String, List<Integer>>();

		receivePrePrepare(socket, leaderPort, bC.getInstance());

		ibft_f.sendMessageToAll(message_type.PREPARE, "Vou trollar", serverports, port, socket,
									consensusNumber, bC.getInstance());
		ibft_f.sendMessageToAll(message_type.PREPARE, "Vou trollar", serverports, port, socket,
									consensusNumber, bC.getInstance());
		ibft_f.sendMessageToAll(message_type.PREPARE, "Vou trollar", serverports, port, socket,
									consensusNumber, bC.getInstance());

		prepareValues.put("Vou trollar", new ArrayList<Integer>());
		prepareValues.get("Vou trollar").add(port);

		ibft_f.waitForQuorum(prepareValues, consensusNumber, message_type.PREPARE, socket, bC.getInstance());

		ibft_f.sendMessageToAll(message_type.COMMIT, "Vou trollar no commit", serverports, port,
									socket, consensusNumber, bC.getInstance());
		ibft_f.sendMessageToAll(message_type.COMMIT, "Vou trollar no commit", serverports, port, socket,
									consensusNumber, bC.getInstance());
		ibft_f.sendMessageToAll(message_type.COMMIT, "Vou trollar no commit", serverports, port, socket,
									consensusNumber, bC.getInstance());

		commitValues.put("Vou trollar no commit", new ArrayList<Integer>());
		commitValues.get("Vou trollar no commit").add(port);

		String valueDecided = ibft_f.waitForQuorum(commitValues, consensusNumber, message_type.COMMIT, socket, bC.getInstance());

		if("Vou trollar no commit" != valueDecided){
			return "No Decision";
		}

		return valueDecided;
	}

	public static void main(String[] args) throws IOException {
		// Check arguments
		if (args.length < 2) {
			System.err.println("Argument(s) missing! You only provided " + args.length);
			return;
		}

		//Parse arguments
		final Integer port = Integer.parseInt(args[0]);
		final String serverType = args[1];

		//Create blockChain State
		blockChain bC = new blockChain();
		List<operation> block = new ArrayList<operation>();

		//Initialization algorithm variables
		String inputValue;
		String valueDecided;

		// Create server socket
		DatagramSocket socket = new DatagramSocket(port);
		System.out.printf("Server will receive packets on port %d %n", port);

		List<DatagramPacket> requests = new ArrayList<>();
		//Value to be sent to client
		String response;

		//Thread that receives inputs
		BlockingQueue<DatagramPacket> queue = new LinkedBlockingQueue<>();
		Callable<Void> callable = new receiveString(requests, port + 3000, queue);
		ExecutorService executor = Executors.newSingleThreadExecutor();
		executor.submit(callable);

		DatagramPacket clientPacket = null;

		List<operation> operations;

		// Wait for client packets 
		while (true) {
			if(((Integer)block.size()).equals(bC.getBlockSize())){
				operations = bC.executeBlock(block);
				for (operation op: operations){
					System.out.println(op.toString());
				}
				block.clear();
			}

			/* ---------------------------------------Recebi mensagem do cliente e desencriptei------------------------------ */
			Integer flag = 0;
			try{
				while(flag.equals(0)){
					clientPacket = queue.take();
					System.out.println("Received message from client");
					flag = 1;
				}
			} catch (Exception e){
				System.err.println("Queue error");
				System.err.println(e.getMessage());
			}

			String keyToDecrypt = null;
			switch(((Integer)clientPacket.getPort()).toString()){
				case "10003":
					keyToDecrypt = keyPathPubAlice;
					break;
				case "10004":
					keyToDecrypt = keyPathPubBob;
					break;
				case "10005":
					keyToDecrypt = keyPathPubCharlie;
					break;
			}

			operation op = parseInput(clientPacket, keyToDecrypt);

			inputValue = bC.getInstance().toString();

			//Algoritmo
			if(bC.isLeader(port)){
				System.out.println("Im the leader");
	/* ------------------------------------- Broadcast PREPREPARE message ------------------------------ */

				bC.increaseInstance();
				ibft_f.sendMessageToAll(message_type.PREPREPARE, inputValue, bC.getPorts(), port,
										socket,  bC.getConsensusMajority(), bC.getInstance());


/* --------------------------------------------------------------------------------------------------------------------------- */
			
			/* ------------------------------------- Algoritmo de consenso  ------------------------------ */

				valueDecided = leaderConsensus(socket, bC.getConsensusMajority(), inputValue, bC.getPorts(), port, bC);

/* --------------------------------------------------------------------------------------------------------------------------- */
				if(valueDecided.equals(inputValue)){
					System.out.println("All good");
					response = "OK";
				}
				else{
					response = "No Decision";
				}

				System.out.println("Going to respond to client");

				respondToClient(keyPathPriv, socket, response, port, key, pMS, clientPacket.getPort() - 3);

				block.add(op);
			}
			else if (serverType.equals(server_type.NORMAL.toString())){
			/* ------------------------------------- Algoritmo de consenso  ------------------------------ */
				System.out.println("Im a normal server");

				valueDecided = normalConsensus(socket, bC.getConsensusMajority(), bC.getLeaderPort(), bC.getPorts(), port, bC);

				if(valueDecided.equals(inputValue)){
					response = "OK";
				}
				else{
					response = "No Decision";
				}

				String path = null;
				switch(port.toString()){
					case "8001":
						path = keyPathPriv1;
						break;
					case "8002":
						path = keyPathPriv2;
						break;
				}

				respondToClient(path, socket, response, port, key, pMS, clientPacket.getPort() - 3);

				System.out.printf("Im a normal server and this was the value agreed: " + valueDecided + "\n");

				block.add(op);
	/* --------------------------------------------------------------------------------------------------------------------------- */
			}

			// Caso o processo seja bizantino e não respeite o valor as mensagens COMMIT e PREPARE
			else if (serverType.equals(server_type.B_PC.toString())){
				valueDecided = byzantineProcessPC(socket, bC.getConsensusMajority(), bC.getLeaderPort(), bC.getPorts(), port, bC);

				if(valueDecided.equals(inputValue)){
					response = "OK";
				}
				else{
					response = "No Decision";
				}

				respondToClient(keyPathPriv3, socket, response, port, key, pMS, clientPacket.getPort() - 3);

				block.add(op);

				System.out.printf("Im byzantine and i got this value " + valueDecided);
			}
			// Caso o processo seja bizantino e não respeite as mensagens PREPREPARE e o valor dos COMMITs e PREPAREs
			else if (serverType.equals(server_type.B_PP.toString())){
				valueDecided = byzantineProcessPP(socket, bC.getConsensusMajority(), bC.getLeaderPort(), bC.getPorts(), port, bC);

				if(valueDecided.equals(inputValue)){
					response = "OK";
				}
				else{
					response = "No Decision";
				}

				respondToClient(keyPathPriv3, socket, response, port, key, pMS, clientPacket.getPort() - 3);

				block.add(op);

				System.out.printf("Im byzantine and i got this value " + valueDecided);
			}
			// Caso o processo seja bizantino e envie várias vezes PREPARE E COMMIT fora de ordem
			else if (serverType.equals(server_type.B_PC_T.toString())){
				valueDecided = byzantineProcessPCT(socket, bC.getConsensusMajority(), bC.getLeaderPort(), bC.getPorts(), port, bC);

				if(valueDecided.equals(inputValue)){
					response = "OK";
				}
				else{
					response = "No Decision";
				}

				respondToClient(keyPathPriv3, socket, response, port, key, pMS, clientPacket.getPort() - 3);

				block.add(op);

				System.out.printf("Im byzantine and i got this value " + valueDecided);
			}
		}
	}
}