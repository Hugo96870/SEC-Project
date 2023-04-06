package pt.tecnico;

import java.net.*;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.PublicKey;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import pt.tecnico.IBFT_Functions.message_type;
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

public class SecureServer {

	private static auxFunctions auxF = new auxFunctions();
	private static IBFT_Functions ibft_f = new IBFT_Functions();

	private static final Integer snapshotPeriod = 2;

	//Key paths
	private final static String keyPathPubAlice = "keys/userPub.der";
	private final static String keyPathPubBob = "keys/userBobPub.der";
	private final static String keyPathPubCharlie = "keys/userCharliePub.der";
	private static final String keyPathPriv = "keys/serverPriv.der";
	private static final String keyPathPriv1 = "keys/serverPriv1.der";
	private static final String keyPathPriv2 = "keys/serverPriv2.der";
	private static final String keyPathPriv3 = "keys/serverPriv3.der";

	private static void respondToPendingProcesses(List<operation> block, List<operation> valueDecided, blockChain bC, String path,
														DatagramSocket socket, Integer port, List<DatagramPacket> signatures){

		String response;

		if(ibft_f.compareLists(block, valueDecided)){
			response = "OK";
		}
		else{
			response = "No Decision";
		}

		if(response.equals("OK")){
			bC.executeBlock(block, signatures);
			response = "OK";
		}
		else{
			response = "No Decision";
		}

		System.out.println("Going to respond to client with " + response);

		for(operation opera: block){
			sendMessageToClient(path, socket, response, port, opera.getPort());
		}
	}

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
		String receivedFromJson = null, signatureEncrypted = null;
		{
			receivedFromJson = received.get("payload").getAsString();
			signatureEncrypted = received.get("signature").getAsString();
		}

		try{
			auxF.verifySignature(signatureEncrypted, pathToKey, receivedFromJson);
		}catch (Exception e){
			System.err.println("Error in Signature, signature wrong");
			System.err.println(e.getMessage());
			System.exit(1);
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
		String type = null, port = null;
		{
			type = requestJson.get("type").getAsString();
			port = requestJson.get("port").getAsString();
		}
		operation op = null;
		PublicKey keySource = null, keyDestination = null;

		switch(type){
			case("CREATE"):
				String pubKey = null;
				{
					pubKey = requestJson.get("pubKey").getAsString();
				}

				try{
					keySource = auxF.convertStrToPK(pubKey);
				} catch(Exception e){
					System.err.println("Error converting key");
					System.err.println(e.getMessage());
				}

				op = new operation("CREATE", keySource, Integer.parseInt(port));
				break;
			case("TRANSFER"):
				String source = null, dest = null, amount = null;
				{
					source = requestJson.get("source").getAsString();
					dest = requestJson.get("dest").getAsString();
					amount = requestJson.get("amount").getAsString();
				}

				try{
					keyDestination = auxF.convertStrToPK(dest);
					keySource = auxF.convertStrToPK(source);
				} catch(Exception e){
					System.err.println("Error converting key");
					System.err.println(e.getMessage());
				}

				op = new operation("TRANSFER", keySource, keyDestination, Integer.parseInt(amount), Integer.parseInt(port));
				break;
			case("BALANCE"):
				String key = null, mode = null;
				{
					key = requestJson.get("pubKey").getAsString();
					mode = requestJson.get("mode").getAsString();
				}

				try{
					keySource = auxF.convertStrToPK(key);
				} catch(Exception e){
					System.err.println("Error converting key");
					System.err.println(e.getMessage());
				}

				op = new operation("BALANCE", keySource, Integer.parseInt(port), mode);
				break;
			default:
				break;
		}

		return op;
	}


	public static List<operation> receivePrePrepare(DatagramSocket socket, Integer leaderPort, Integer instanceNumber, blockChain bC){

		System.out.println("I will wait for PREPREPARE");

		while(true){
			DatagramPacket messageFromServer = new DatagramPacket(IBFT_Functions.buf, IBFT_Functions.buf.length);
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
					System.exit(1);
				}
				else{
					String messageType = null, instance = null, idMainProcess = null;
					List<JsonObject> ops = new ArrayList<JsonObject>(bC.getBlockSize());
					{
						messageType = requestJson.get("messageType").getAsString();
						instance = requestJson.get("instance").getAsString();
						idMainProcess = requestJson.get("idMainProcess").getAsString();
					}

					for(int j = 0; j < bC.getBlockSize(); j++){
						ops.add(requestJson.getAsJsonObject("op" + j));
					}

					List<operation> value = ibft_f.convertJsonToOp(ops);

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

	public static List<operation> leaderConsensus(DatagramSocket socket, Integer consensusNumber, List<operation> input,
								List<Integer> serverports, Integer port, blockChain bC, String path){

		//Create prepare and commit messages maps
		Map<List<operation>, List<Integer>> prepareValues = new HashMap<List<operation>, List<Integer>>();
		Map<List<operation>, List<Integer>> commitValues = new HashMap<List<operation>, List<Integer>>();

		//Send Prepare to all, we assume we received preprepare from ourselves
		ibft_f.sendMessageToAll(message_type.PREPARE, input, serverports, port, socket, consensusNumber, bC.getInstance(), path);

		//add value to prepare map
		prepareValues.put(input, new ArrayList<Integer>());
		prepareValues.get(input).add(port);

		//wait for prepare quorum
		List<operation> valueAgreed = ibft_f.waitForQuorum(prepareValues, consensusNumber, message_type.PREPARE, socket, bC.getInstance(), bC);

		//Once the quorum is reached, send commit to all
		ibft_f.sendMessageToAll(message_type.COMMIT, valueAgreed, serverports, port, socket, consensusNumber, bC.getInstance(), path);

		//add value to commit map
		commitValues.put(input, new ArrayList<Integer>());
		commitValues.get(input).add(port);

		//wait for commit quorum
		List<operation> valueDecided = ibft_f.waitForQuorum(commitValues, consensusNumber, message_type.COMMIT, socket, bC.getInstance(), bC);

		if(!ibft_f.compareLists(valueAgreed, valueDecided)){
			System.out.println("Values prepare and commit not equal");
			return null;
		}

		return valueDecided;
	}

	public static List<operation> normalConsensus(DatagramSocket socket, Integer consensusNumber, Integer leaderPort,
								List<Integer> serverports, Integer port, blockChain bC, String path){

		//Create commit and prepare maps
		Map<List<operation>, List<Integer>> prepareValues = new HashMap<List<operation>, List<Integer>>();
		Map<List<operation>, List<Integer>> commitValues = new HashMap<List<operation>, List<Integer>>();

		//Wait for preprepare message
		List<operation> valueReceived = receivePrePrepare(socket, leaderPort, bC.getInstance(), bC);
		bC.increaseInstance();

		//send prepare message to all
		ibft_f.sendMessageToAll(message_type.PREPARE, valueReceived, serverports, port, socket, consensusNumber, bC.getInstance(), path);

		//add value of prepare to map
		prepareValues.put(valueReceived, new ArrayList<Integer>());
		prepareValues.get(valueReceived).add(port);

		//wait for prepare quorum
		List<operation> valueAgreed = ibft_f.waitForQuorum(prepareValues, consensusNumber, message_type.PREPARE, socket, bC.getInstance(), bC);

		//send commit message to all
		ibft_f.sendMessageToAll(message_type.COMMIT, valueAgreed, serverports, port, socket, consensusNumber, bC.getInstance(), path);

		//add value sent in commits to commit map
		commitValues.put(valueAgreed, new ArrayList<Integer>());
		commitValues.get(valueAgreed).add(port);

		//wait for commit quorum
		List<operation> valueDecided = ibft_f.waitForQuorum(commitValues, consensusNumber, message_type.COMMIT, socket, bC.getInstance(), bC);

		if(!ibft_f.compareLists(valueAgreed, valueDecided)){
			System.out.println("Values prepare and commit not equal");
			return null;
		}

		return valueDecided;
	}

	//Sends encrypted message to client with the result
	public static void sendMessageToClient(String keyPathPriv,
									DatagramSocket socket, String valueToSend, Integer port, int clientPort){
		// Create response message
		JsonObject responseJson = JsonParser.parseString("{}").getAsJsonObject();
		{
			responseJson.addProperty("body", valueToSend);
		}

		String signatureEncrypted = null;
		try{
			signatureEncrypted = auxF.do_RSAEncryption(auxF.digest(responseJson.toString().getBytes(auxF.UTF_8),
									"SHA3-256").toString(), keyPathPriv);
		}
		catch (Exception e){
			System.err.printf("RSA encryption failed\n");
			System.err.println(e.getMessage());
		}

		JsonObject message = JsonParser.parseString("{}").getAsJsonObject();
		{
			message.addProperty("payload", responseJson.toString());
			message.addProperty("signature", signatureEncrypted);
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

		System.out.println("Going to send response to " + clientPort);
		
		Callable<Integer> callable = new sendAndReceiveAck(serverPacket, clientPort, 0);

		ExecutorService executor = Executors.newSingleThreadExecutor();

		executor.submit(callable);
	}

	//Sends snapshot to client with all the signatures in the snapshot quorum
	public static void sendSnapshotToClient(String keyPathPriv, DatagramSocket socket,
								JsonObject toSend, Integer port, int clientPort, List<String> signatures){

		String concatenatedSignature = "";

		for(String signature: signatures){
			concatenatedSignature += signature;
			concatenatedSignature += " ";
		}

		// Create response message
		JsonObject responseJson = JsonParser.parseString("{}").getAsJsonObject();
		{
			responseJson.addProperty("signatures", concatenatedSignature);
			responseJson.add("state", toSend);
		}

		String signatureEncrypted = null;
		try{
			signatureEncrypted = auxF.do_RSAEncryption(auxF.digest(responseJson.toString().getBytes(auxF.UTF_8),
									"SHA3-256").toString(), keyPathPriv);
		}
		catch (Exception e){
			System.err.printf("RSA encryption failed\n");
			System.err.println(e.getMessage());
		}

		JsonObject message = JsonParser.parseString("{}").getAsJsonObject();
		{
			message.addProperty("payload", responseJson.toString());
			message.addProperty("signature", signatureEncrypted);
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

		System.out.println("Going to send response to " + clientPort);
		
		Callable<Integer> callable = new sendAndReceiveAck(serverPacket, clientPort, port + 4000);

		ExecutorService executor = Executors.newSingleThreadExecutor();

		executor.submit(callable);
	}

	//Byzantine process doesnt respect Prepare and Commit values
	public static List<operation> byzantineProcessPC(DatagramSocket socket, Integer consensusNumber, Integer leaderPort,
							List<Integer> serverports, Integer port, blockChain bC, String path){

		Map<List<operation>, List<Integer>> prepareValues = new HashMap<List<operation>, List<Integer>>();
		Map<List<operation>, List<Integer>> commitValues = new HashMap<List<operation>, List<Integer>>();

		receivePrePrepare(socket, leaderPort, bC.getInstance(), bC);
		bC.increaseInstance();

		List<operation> op = new ArrayList<operation>();

		ibft_f.sendMessageToAll(message_type.PREPARE, op, serverports, port, socket, consensusNumber, bC.getInstance(), path);

		prepareValues.put(op, new ArrayList<Integer>());
		prepareValues.get(op).add(port);

		List<operation> valueDecidedPREPARE = ibft_f.waitForQuorum(prepareValues, consensusNumber, message_type.PREPARE,
					socket, bC.getInstance(), bC);

		ibft_f.sendMessageToAll(message_type.COMMIT, op, serverports, port, socket, consensusNumber, bC.getInstance(), path);

		commitValues.put(op, new ArrayList<Integer>());
		commitValues.get(op).add(port);

		List<operation> valueDecidedCOMMIT = ibft_f.waitForQuorum(commitValues, consensusNumber, message_type.COMMIT,
					socket, bC.getInstance(), bC);

		if(!ibft_f.compareLists(valueDecidedPREPARE, valueDecidedCOMMIT)){
			return null;
		}

		return valueDecidedCOMMIT;
	}

	//Byzantine process tries to send PrePrepare even though he is not the leader and doesnt respect Prepare and Commit messages
	public static List<operation> byzantineProcessPP(DatagramSocket socket, Integer consensusNumber, Integer leaderPort,
						List<Integer> serverports, Integer port, blockChain bC, String path){

		Map<List<operation>, List<Integer>> prepareValues = new HashMap<List<operation>, List<Integer>>();
		Map<List<operation>, List<Integer>> commitValues = new HashMap<List<operation>, List<Integer>>();

		List<operation> op = new ArrayList<operation>();

		bC.increaseInstance();
		ibft_f.sendMessageToAll(message_type.PREPREPARE, op, bC.getPorts(), port,
								socket,  bC.getConsensusMajority(), bC.getInstance(), path);

		ibft_f.sendMessageToAll(message_type.PREPARE, op, serverports,
								port, socket, consensusNumber, bC.getInstance(), path);

		prepareValues.put(op, new ArrayList<Integer>());
		prepareValues.get(op).add(port);

		ibft_f.waitForQuorum(prepareValues, consensusNumber, message_type.PREPARE, socket, bC.getInstance(), bC);

		ibft_f.sendMessageToAll(message_type.COMMIT, op,
									serverports, port, socket, consensusNumber, bC.getInstance(), path);

		commitValues.put(op, new ArrayList<Integer>());
		commitValues.get(op).add(port);

		List<operation> valueDecided = ibft_f.waitForQuorum(commitValues, consensusNumber, message_type.COMMIT, socket, bC.getInstance(), bC);

		if(valueDecided.isEmpty()){
			return null;
		}

		return valueDecided;
	}

	//Byzantine process sends several COMMITs and PREPAREs to other servers not respecting the algorithm
	public static List<operation> byzantineProcessPCT(DatagramSocket socket, Integer consensusNumber, Integer leaderPort,
					List<Integer> serverports, Integer port, blockChain bC, String path){

		Map<List<operation>, List<Integer>> prepareValues = new HashMap<List<operation>, List<Integer>>();
		Map<List<operation>, List<Integer>> commitValues = new HashMap<List<operation>, List<Integer>>();

		receivePrePrepare(socket, leaderPort, bC.getInstance(), bC);
		bC.increaseInstance();

		List<operation> op = new ArrayList<operation>();

		ibft_f.sendMessageToAll(message_type.PREPARE, op, serverports, port, socket,
									consensusNumber, bC.getInstance(), path);
		ibft_f.sendMessageToAll(message_type.PREPARE, op, serverports, port, socket,
									consensusNumber, bC.getInstance(), path);
		ibft_f.sendMessageToAll(message_type.PREPARE, op, serverports, port, socket,
									consensusNumber, bC.getInstance(), path);

		prepareValues.put(op, new ArrayList<Integer>());
		prepareValues.get(op).add(port);

		ibft_f.waitForQuorum(prepareValues, consensusNumber, message_type.PREPARE, socket, bC.getInstance(), bC);

		ibft_f.sendMessageToAll(message_type.COMMIT, op, serverports, port,
									socket, consensusNumber, bC.getInstance(), path);
		ibft_f.sendMessageToAll(message_type.COMMIT, op, serverports, port, socket,
									consensusNumber, bC.getInstance(), path);
		ibft_f.sendMessageToAll(message_type.COMMIT, op, serverports, port, socket,
									consensusNumber, bC.getInstance(), path);

		commitValues.put(op, new ArrayList<Integer>());
		commitValues.get(op).add(port);

		List<operation> valueDecided = ibft_f.waitForQuorum(commitValues, consensusNumber, message_type.COMMIT, socket, bC.getInstance(), bC);

		if(valueDecided.isEmpty()){
			return null;
		}

		return valueDecided;
	}

	public static void main(String[] args) throws IOException {
		// Check arguments
		if (args.length < 2) {
			System.err.println("Argument(s) missing! You only provided " + args.length);
			return;
		}

		//Local snapshot
		Map<PublicKey, Double> snapshot = new HashMap<PublicKey, Double>();
		List<String> snapShotSigntures = new ArrayList<String>();

		//Parse arguments
		final Integer port = Integer.parseInt(args[0]);
		final String serverType = args[1];

		//Create blockChain State
		blockChain bC = new blockChain();
		List<operation> block = new ArrayList<operation>();

		//Initialization algorithm variables
		List<operation> valueDecided;

		// Create server socket
		DatagramSocket socket = new DatagramSocket(port);
		System.out.printf("Server will receive packets on port %d %n", port);

		//List of signatures
		List<DatagramPacket> signatures = new ArrayList<DatagramPacket>();

		//Thread that receives inputs
		List<DatagramPacket> requests = new ArrayList<>();
		BlockingQueue<DatagramPacket> queue = new LinkedBlockingQueue<>();
		Callable<Void> callable = new receiveString(requests, port + 3000, queue);
		ExecutorService executor = Executors.newSingleThreadExecutor();
		executor.submit(callable);

		DatagramPacket clientPacket = null;

		while (true) {

			// Wait for client packets 
			Integer flag = 0;
			try{
				while(flag.equals(0)){
					clientPacket = queue.take();
					flag = 1;
				}
			} catch (Exception e){
				System.err.println("Queue error");
				System.err.println(e.getMessage());
			}
			
			//Switch client port to know with which key to decrypt
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

			//Switch port to know with which key to encrypt
			String path = null;
			switch(port.toString()){
				case "8000":
					path = keyPathPriv;
					break;
				case "8001":
					path = keyPathPriv1;
					break;
				case "8002":
					path = keyPathPriv2;
					break;
				case "8003":
					path = keyPathPriv3;
					break;
			}
			
			if(op.getID().toString().equals("BALANCE") && op.getMode().equals("strong")){
				System.out.println("Received a strong read, responding from blockChain");
				String responseToClient = null;
				if(bC.check_balance(op.getSource()) == null){
					responseToClient = "Account doesn't exist";
				}
				else{
					responseToClient = bC.check_balance(op.getSource()).toString();
				}
				sendMessageToClient(path, socket, responseToClient, port, op.getPort());
			}
			else if(op.getID().toString().equals("BALANCE") && op.getMode().equals("weak")){
				System.out.println("Received a weak read, responding from snapshot");
				JsonObject toSend = ibft_f.convertMapIntoJson(snapshot);
				sendSnapshotToClient(path, socket, toSend, port, op.getPort(), snapShotSigntures);
			}
			else{
				//If op is type CREATE or TRANSFER wait till block is full to run consensus
				block.add(op);
				signatures.add(clientPacket);

				if(((Integer)block.size()).equals(bC.getBlockSize())){
					switch(serverType){
						case "LEADER":
							System.out.println("Im the leader");
							//Broadcast PREPREPARE message
							bC.increaseInstance();
							ibft_f.sendMessageToAll(message_type.PREPREPARE, block, bC.getPorts(), port,
													socket,  bC.getConsensusMajority(), bC.getInstance(), path);
							//Run consensus algorythm
							valueDecided = leaderConsensus(socket, bC.getConsensusMajority(), block, bC.getPorts(), port, bC, path);

							respondToPendingProcesses(block, valueDecided, bC, path, socket, port, signatures);
	
							break;
						case "NORMAL":
							System.out.println("Im a normal server");
							//Run consensus algorythm
							valueDecided = normalConsensus(socket, bC.getConsensusMajority(), bC.getLeaderPort(),
										bC.getPorts(), port, bC, path);
	
							respondToPendingProcesses(block, valueDecided, bC, path, socket, port, signatures);
	
							break;
						case "B_PC":
							System.out.println("Im byzantine");
							// Caso o processo seja bizantino e não respeite o valor as mensagens COMMIT e PREPARE

							valueDecided = byzantineProcessPC(socket, bC.getConsensusMajority(), bC.getLeaderPort(),	
										bC.getPorts(), port, bC, path);

							respondToPendingProcesses(block, valueDecided, bC, path, socket, port, signatures);

							break;
						case "B_PP":
							System.out.println("Im byzantine");
							// Caso o processo seja bizantino e não respeite as mensagens PREPREPARE e o valor dos COMMITs e PREPAREs

							valueDecided = byzantineProcessPP(socket, bC.getConsensusMajority(), bC.getLeaderPort(),
										bC.getPorts(), port, bC, path);
							respondToPendingProcesses(block, valueDecided, bC, path, socket, port, signatures);

							break;
						case "B_PC_T":
							System.out.println("Im byzantine");
							// Caso o processo seja bizantino e envie várias vezes PREPARE E COMMIT fora de ordem

							valueDecided = byzantineProcessPCT(socket, bC.getConsensusMajority(), bC.getLeaderPort(),
										bC.getPorts(), port, bC, path);

							respondToPendingProcesses(block, valueDecided, bC, path, socket, port, signatures);

							break;
					}
					bC.printState();
	
					block.clear();

					signatures.clear();

					snapshot = bC.getAccounts();

					if(bC.getInstance() % snapshotPeriod == 0){
						snapShotSigntures = ibft_f.doSnapshot(snapshot, path, port, bC.getPorts(), bC, socket);
					}
				}
			}
		}
	}
}