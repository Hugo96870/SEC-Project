package pt.tecnico;

import java.net.*;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
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
	private static final String keyPathClientPublic = "keys/userPub.der";
	private static final String keyPathPriv = "keys/serverPriv.der";
	private static final String keyPathPriv1 = "keys/serverPriv1.der";
	private static final String keyPathPriv2 = "keys/serverPriv2.der";
	private static final String keyPathPriv3 = "keys/serverPriv3.der";
	final static String keyPathSecret = "keys/secret.key";

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
									DatagramSocket socket, String valueToSend, Integer port, SecretKey key, String psm){
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

		String pSMEncrypted = null;
		try{
			pSMEncrypted = auxF.do_RSAEncryption(psm, keyPathPriv);
		}
		catch (Exception e){
			System.err.printf("RSA encryption failed\n");
			System.err.println(e.getMessage());
		}

		JsonObject message = JsonParser.parseString("{}").getAsJsonObject();
		{
			message.addProperty("payload", clientData);
			message.addProperty("PSM", pSMEncrypted);
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
		
		DatagramPacket serverPacket = new DatagramPacket( Base64.getDecoder().decode(dataToSend), Base64.getDecoder().decode(dataToSend).length, hostToSend, 10000);
		
		Callable<Integer> callable = new sendAndReceiveAck(serverPacket, 10000, port + 4000);

		ExecutorService executor = Executors.newSingleThreadExecutor();

		Future<Integer> future = executor.submit(callable);

		try{
			future.get();
		} catch (Exception e){
			System.err.println("Failed to wait for thread");
			System.err.println(e.getMessage());
		}

		System.out.printf("Response packet sent to %s:%d! and received ack \n", hostToSend, 10000);

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

		//Initialization algorithm variables
		String inputValue;
		String valueDecided;

		// Create server socket
		DatagramSocket socket = new DatagramSocket(port);
		System.out.printf("Server will receive packets on port %d %n", port);

		List<DatagramPacket> requests = new ArrayList<>();

		//Thread that receives inputs
		BlockingQueue<DatagramPacket> queue = new LinkedBlockingQueue<>();
		Callable<Void> callable = new receiveString(requests, port + 3000, queue);
		ExecutorService executor = Executors.newSingleThreadExecutor();
		executor.submit(callable);

		DatagramPacket clientPacket = null;

		// Wait for client packets 
		while (true) {

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

				String clientText = null;
				try{
					clientText = auxF.ConvertReceived(Base64.getEncoder().encodeToString(clientPacket.getData()), clientPacket.getLength());
				}catch (Exception e){
					System.err.println("Error parsing arguments");
					System.err.println(e.getMessage());
				}

				//Parse Json with payload and hmac
				JsonObject received = JsonParser.parseString(clientText).getAsJsonObject();
				String receivedFromJson = null, pMS = null;
				{
					receivedFromJson = received.get("payload").getAsString();
					pMS = received.get("PSM").getAsString();
				}

				String pMSDecrypted = null;
				try{
					pMSDecrypted = auxF.do_RSADecryption(pMS, keyPathClientPublic);
				}catch (Exception e){
					System.err.println("Error in assymetric decryption");
					System.err.println(e.getMessage());
				}

				byte[] secretKeyinByte = auxF.digest(pMSDecrypted.getBytes(auxF.UTF_8), "SHA3-256");
				SecretKey key = new SecretKeySpec(secretKeyinByte, 0, secretKeyinByte.length, "AES");

				try{
					receivedFromJson = auxF.do_Decryption(receivedFromJson, key, 32);
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
				String body = null;
				{
					body = requestJson.get("body").getAsString();
				}

				inputValue = body;

				System.out.printf("Identity certified and received message: " + body + "\n");

			//Algoritmo 1
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

				String response = valueDecided + "\n";

				respondToClient(keyPathPriv, socket, response, port, key, pMSDecrypted);

				bC.addToRound(bC.getInstance(), valueDecided);
			}
			else if (serverType.equals(server_type.NORMAL.toString())){
			/* ------------------------------------- Algoritmo de consenso  ------------------------------ */
				System.out.println("Im a normal server");

				valueDecided = normalConsensus(socket, bC.getConsensusMajority(), bC.getLeaderPort(), bC.getPorts(), port, bC);

				String response = valueDecided + "\n";

				String path = null;
				switch(port.toString()){
					case "8001":
						path = keyPathPriv1;
						break;
					case "8002":
						path = keyPathPriv2;
						break;
				}

				respondToClient(path, socket, response, port, key, pMSDecrypted);

				System.out.printf("Im a normal server and this was the value agreed: " + valueDecided + "\n");

				bC.addToRound(bC.getInstance(), valueDecided);
	/* --------------------------------------------------------------------------------------------------------------------------- */
			}

			// Caso o processo seja bizantino e não respeite o valor as mensagens COMMIT e PREPARE
			else if (serverType.equals(server_type.B_PC.toString())){
				valueDecided = byzantineProcessPC(socket, bC.getConsensusMajority(), bC.getLeaderPort(), bC.getPorts(), port, bC);

				String response = valueDecided + "\n";

				respondToClient(keyPathPriv3, socket, response, port, key, pMSDecrypted);

				bC.addToRound(bC.getInstance(), valueDecided);

				System.out.printf("Im byzantine and i got this value " + valueDecided);
			}
			// Caso o processo seja bizantino e não respeite as mensagens PREPREPARE e o valor dos COMMITs e PREPAREs
			else if (serverType.equals(server_type.B_PP.toString())){
				valueDecided = byzantineProcessPP(socket, bC.getConsensusMajority(), bC.getLeaderPort(), bC.getPorts(), port, bC);

				String response = valueDecided + "\n";

				respondToClient(keyPathPriv3, socket, response, port, key, pMSDecrypted);

				bC.addToRound(bC.getInstance(), valueDecided);

				System.out.printf("Im byzantine and i got this value " + valueDecided);
			}
			// Caso o processo seja bizantino e envie várias vezes PREPARE E COMMIT fora de ordem
			else if (serverType.equals(server_type.B_PC_T.toString())){
				valueDecided = byzantineProcessPCT(socket, bC.getConsensusMajority(), bC.getLeaderPort(), bC.getPorts(), port, bC);

				String response = valueDecided + "\n";

				respondToClient(keyPathPriv3, socket, response, port, key, pMSDecrypted);

				bC.addToRound(bC.getInstance(), valueDecided);

				System.out.printf("Im byzantine and i got this value " + valueDecided);
			}
		}
	}
}