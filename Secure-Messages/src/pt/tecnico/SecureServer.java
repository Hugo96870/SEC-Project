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

	public static List<String> waitSnapshot(Map<PublicKey, Double> snapshot, String signature,
						Integer consensusMajority, DatagramSocket socket, blockChain bC){
		List<String> signatures = new ArrayList<String>();

		signatures.add(signature);

		DatagramPacket messageFromServer = new DatagramPacket(ibft_f.buf, ibft_f.buf.length);

		String signatureReceived = null;

		while(true){
			try{
				socket.receive(messageFromServer);

				String clientText = null;
		
				try{
					clientText = auxF.ConvertReceived(Base64.getEncoder().encodeToString(messageFromServer.getData()),
						messageFromServer.getLength());
				}
				catch(Exception e){
					System.err.println("Message conversion failed");
					System.err.println(e.getMessage());
				}
				JsonObject requestJson = null;

				JsonObject received = JsonParser.parseString(clientText).getAsJsonObject();
				String receivedFromJson = null, signatureEncrypted = null;
				{
					receivedFromJson = received.get("payload").getAsString();
					signatureEncrypted = received.get("signature").getAsString();
				}
				// Parse JSON and extract arguments
				try{
					requestJson = JsonParser.parseString(receivedFromJson).getAsJsonObject();
				} catch (Exception e){
					System.err.println("Failed to parse Json received");
					System.err.println(e.getMessage());
				}
				String idMainProcess = null;
				{
					idMainProcess = requestJson.get("idMainProcess").getAsString();
				}
				String pathToKey = null;
				switch(idMainProcess){
					case "0":
						pathToKey = IBFT_Functions.keyPathPublicServer;
						break;
					case "1":
						pathToKey = IBFT_Functions.keyPathPublicServer1;
						break;
					case "2":
						pathToKey = IBFT_Functions.keyPathPublicServer2;
						break;
					case "3":
						pathToKey = IBFT_Functions.keyPathPublicServer3;
						break;
				}
				try{
					signatureReceived = auxF.do_RSADecryption(signatureEncrypted, pathToKey);
					byte[] payloadHash = auxF.digest(receivedFromJson.toString().getBytes(auxF.UTF_8), "SHA3-256");
					String hashString = new String(payloadHash, "UTF-8");
					hashString.equals(signatureReceived);
				}catch (Exception e){
					System.err.println("Error in assymetric decryption");
					System.err.println(e.getMessage());
					System.exit(1);
				}
				try{
					List<JsonObject> accs = new ArrayList<JsonObject>();

					Map<PublicKey, Double> valueReceived = new HashMap<PublicKey, Double>();

					for(int j = 0; j < bC.getAccounts().size(); j++){
						accs.add(requestJson.getAsJsonObject("acc" + j));
					}

					if(accs.get(0) != null)
						valueReceived = ibft_f.convertJsonToMap(accs);

					Integer counter = 0;

					for(PublicKey myKey: snapshot.keySet()){
						for(PublicKey keyReceived: valueReceived.keySet()){
							if(myKey.equals(keyReceived) && snapshot.get(myKey).equals(valueReceived.get(keyReceived))){
								counter++;
								if(counter.equals(snapshot.size())){
									signatures.add(signatureReceived);
									if(((Integer)signatures.size()).equals(consensusMajority)){
										return signatures;
									}
								}
								break;
							}
						}
					}

				} catch (Exception e){
					System.err.println("Failed to extract arguments from Json payload");
				}
					

			} catch (Exception e){
				System.err.println("Error parsing arguments");
			}
		}
	}

	private static List<String> doSnapshot(Map<PublicKey, Double> snapshot, String path, Integer port,
									List<Integer> serverPorts, blockChain bC, DatagramSocket socket){

		InetAddress serverToSend = null;
		try{
			serverToSend = InetAddress.getByName("localhost");
		}catch (Exception e){
			System.err.printf("Cant resolve host\n");
			System.err.println(e.getMessage());
		}

		JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
		Integer counter = 0;
		for(PublicKey key: snapshot.keySet()){
			JsonObject jsonObject = new JsonObject();
			jsonObject.addProperty("key", Base64.getEncoder().encodeToString(key.getEncoded()));
			jsonObject.addProperty("balance", snapshot.get(key).toString());
			requestJson.add("acc" + counter, jsonObject);
			counter++;
		}

		requestJson.addProperty("idMainProcess", ((Integer)(port % 8000)).toString());

		String signature = null;
		try{
			signature = auxF.do_RSAEncryption(auxF.digest(requestJson.toString().getBytes(auxF.UTF_8), "SHA3-256").toString(), path);
		}
		catch (Exception e){
			System.err.printf("RSA encryption failed\n");
			System.err.println(e.getMessage());
		}

		JsonObject message = JsonParser.parseString("{}").getAsJsonObject();
		{
			message.addProperty("payload", requestJson.toString());
			message.addProperty("signature", signature);
		}
		String clientData = null;
		try{
			clientData = auxF.ConvertToSend(message.toString());
		}
		catch (Exception e){
			System.err.printf("Error parsing message\n");
			System.err.println(e.getMessage());
		}

		ExecutorService executorService = Executors.newFixedThreadPool(serverPorts.size());
		List<sendAndReceiveAck> myThreads = new ArrayList<>();
		for(int i = 0; i < serverPorts.size(); i++){
			//We dont send message to ourselves, only assume we sent and received it
			if(!port.equals(serverPorts.get(i))){
				Integer portToSend = serverPorts.get(i);

				//Create datagram
				DatagramPacket packet = null;
				try{
					packet = new DatagramPacket(Base64.getDecoder().decode(clientData),
					Base64.getDecoder().decode(clientData).length, serverToSend, portToSend);
				} catch (Exception e){
					System.err.println("Failed to create Datagram");
					System.err.println(e.getMessage());
				}

				myThreads.add(new sendAndReceiveAck(packet, serverPorts.get(i), 0));
			}
		}

		try{
			for(int i = 0; i < serverPorts.size() - 1; i++){
				executorService.submit(myThreads.get(i));
			}
		}catch(Exception e){
			System.err.println("Error launching threads");
			System.err.println(e.getMessage());
		}

		return waitSnapshot(snapshot, signature, bC.getConsensusMajority(), socket, bC);
	}

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
			System.out.println("All good");
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
			String signatureReceived = auxF.do_RSADecryption(signatureEncrypted, pathToKey);
			byte[] payloadHash = auxF.digest(receivedFromJson.toString().getBytes(auxF.UTF_8), "SHA3-256");
			String hashString = new String(payloadHash, "UTF-8");
			hashString.equals(signatureReceived);

		}catch (Exception e){
			System.err.println("Error in assymetric decryption");
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

		System.out.println("Already decidded");

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

		System.out.println("Already decidded");

		if(!ibft_f.compareLists(valueAgreed, valueDecided)){
			System.out.println("Values prepare and commit not equal");
			return null;
		}

		return valueDecided;
	}

	//Sends encrypted message to client confirming the string appended
	public static void sendMessageToClient(String keyPathPriv,
									DatagramSocket socket, String valueToSend, Integer port, int clientPort){
		/* ------------------------------------- Consenso atingido, Enviar mensagem ao cliente ------------------------------ */

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
		
		Callable<Integer> callable = new sendAndReceiveAck(serverPacket, clientPort, port + 4000);

		ExecutorService executor = Executors.newSingleThreadExecutor();

		executor.submit(callable);

		System.out.printf("Response packet sent to %s:%d! and received ack \n", hostToSend, clientPort);

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
					System.out.println("Received message from client");
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
				String responseToClient = null;
				if(snapshot.get(op.getSource()) == null){
					responseToClient = "Account doesn't exist";
				}
				else{
					responseToClient = snapshot.get(op.getSource()).toString();
				}
				sendMessageToClient(path, socket, responseToClient, port, op.getPort());
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
	
							bC.printState();
	
							block.clear();

							signatures.clear();

							snapshot = bC.getAccounts();

							if(bC.getInstance() % snapshotPeriod == 0){
								snapShotSigntures = doSnapshot(snapshot, path, port, bC.getPorts(), bC, socket);
							}
	
							break;
						case "NORMAL":
							System.out.println("Im a normal server");
							//Run consensus algorythm
							valueDecided = normalConsensus(socket, bC.getConsensusMajority(), bC.getLeaderPort(),
										bC.getPorts(), port, bC, path);
	
							respondToPendingProcesses(block, valueDecided, bC, path, socket, port, signatures);
	
							bC.printState();
	
							block.clear();

							signatures.clear();

							if(bC.getInstance() % snapshotPeriod == 0){
								snapShotSigntures = doSnapshot(snapshot, path, port, bC.getPorts(), bC, socket);
							}
	
							break;
						case "B_PC":
							// Caso o processo seja bizantino e não respeite o valor as mensagens COMMIT e PREPARE
							//Run consensus algorythm
							valueDecided = byzantineProcessPC(socket, bC.getConsensusMajority(), bC.getLeaderPort(),	
										bC.getPorts(), port, bC, path);

							respondToPendingProcesses(block, valueDecided, bC, path, socket, port, signatures);

							bC.printState();

							block.clear();

							signatures.clear();

							if(bC.getInstance() % snapshotPeriod == 0){
								snapShotSigntures = doSnapshot(snapshot, path, port, bC.getPorts(), bC, socket);
							}

							break;
						case "B_PP":
							// Caso o processo seja bizantino e não respeite as mensagens PREPREPARE e o valor dos COMMITs e PREPAREs
							//Run consensus algorythm
							valueDecided = byzantineProcessPP(socket, bC.getConsensusMajority(), bC.getLeaderPort(),
										bC.getPorts(), port, bC, path);
							respondToPendingProcesses(block, valueDecided, bC, path, socket, port, signatures);

							bC.printState();

							block.clear();

							signatures.clear();

							if(bC.getInstance() % snapshotPeriod == 0){
								snapShotSigntures = doSnapshot(snapshot, path, port, bC.getPorts(), bC, socket);
							}

							break;
						case "B_PC_T":
							// Caso o processo seja bizantino e envie várias vezes PREPARE E COMMIT fora de ordem
							//Run consensus algorythm
							valueDecided = byzantineProcessPCT(socket, bC.getConsensusMajority(), bC.getLeaderPort(),
										bC.getPorts(), port, bC, path);

							respondToPendingProcesses(block, valueDecided, bC, path, socket, port, signatures);

							bC.printState();

							block.clear();

							signatures.clear();

							if(bC.getInstance() % snapshotPeriod == 0){
								snapShotSigntures = doSnapshot(snapshot, path, port, bC.getPorts(), bC, socket);
							}

							break;
					}
				}
			}
		}
	}
}