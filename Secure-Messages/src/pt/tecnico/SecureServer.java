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

	private static Integer consensusCounter = 0;

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

	public static String receivePrePrepare(DatagramSocket socket, Integer leaderPort){

		System.out.println("vou esperar por preprepare");

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

	public static void broadcast(String text, Integer port, List<Integer> serverPorts, DatagramSocket socket, Integer consensusNumber){
		consensusCounter++;

		ibft_f.sendMessageToAll(message_type.PREPREPARE, text, serverPorts, port, socket, consensusNumber, consensusCounter);
	}

	public static String leaderConsensus(DatagramSocket socket, Integer consensusNumber, String input,
								List<Integer> serverports, Integer port){

		//Create prepare and commit messages maps
		Map<String, List<Integer>> prepareValues = new HashMap<String, List<Integer>>();
		Map<String, List<Integer>> commitValues = new HashMap<String, List<Integer>>();

		//Send Prepare to all, we assume we received preprepare from ourselves
		ibft_f.sendMessageToAll(message_type.PREPARE, input, serverports, port, socket, consensusNumber, consensusCounter);

		//add value to prepare map
		prepareValues.put(input, new ArrayList<Integer>());
		prepareValues.get(input).add(port);

		//wait for prepare quorum
		String valueAgreed = ibft_f.waitForQuorum(prepareValues, consensusNumber, message_type.PREPARE, socket, consensusCounter);

		//Once the quorum is reached, send commit to all
		ibft_f.sendMessageToAll(message_type.COMMIT, valueAgreed, serverports, port, socket, consensusNumber, consensusCounter);

		//add value to commit map
		commitValues.put(input, new ArrayList<Integer>());
		commitValues.get(input).add(port);

		//wait for commit quorum
		String valueDecided = ibft_f.waitForQuorum(commitValues, consensusNumber, message_type.COMMIT, socket, consensusCounter);

		if(!valueAgreed.equals(valueDecided)){
			return "No Decision";
		}

		return valueDecided;
	}

	public static String normalConsensus(DatagramSocket socket, Integer consensusNumber, Integer leaderPort,
								List<Integer> serverports, Integer port){

		//Create commit and prepare maps
		Map<String, List<Integer>> prepareValues = new HashMap<String, List<Integer>>();
		Map<String, List<Integer>> commitValues = new HashMap<String, List<Integer>>();

		//Wait for preprepare message
		String valueReceived = receivePrePrepare(socket, leaderPort);

		//send prepare message to all
		ibft_f.sendMessageToAll(message_type.PREPARE, valueReceived, serverports, port, socket, consensusNumber, consensusCounter);

		//add value of preprepare to map
		prepareValues.put(valueReceived, new ArrayList<Integer>());
		prepareValues.get(valueReceived).add(port);

		//wait for prepare quorum
		String valueAgreed = ibft_f.waitForQuorum(prepareValues, consensusNumber, message_type.PREPARE, socket, consensusCounter);

		//send commit message to all
		ibft_f.sendMessageToAll(message_type.COMMIT, valueAgreed, serverports, port, socket, consensusNumber, consensusCounter);

		//add value sent in commits to commit map
		commitValues.put(valueAgreed, new ArrayList<Integer>());
		commitValues.get(valueAgreed).add(port);

		//wait for commit quorum
		String valueDecided = ibft_f.waitForQuorum(commitValues, consensusNumber, message_type.COMMIT, socket, consensusCounter);

		if(!valueAgreed.equals(valueDecided)){
			return "No Decision";
		}

		return valueDecided;
	}

	//Sends encrypted message to client confirming the string appended
	public static void respondToClient(String tokenRcvd, String keyPathPriv,
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
			System.out.printf("RSA encryption failed\n");
			System.out.println(e.getMessage());
		}

		String pSMEncrypted = null;
		try{
			pSMEncrypted = auxF.do_RSAEncryption(psm, keyPathPriv);
		}
		catch (Exception e){
			System.out.printf("RSA encryption failed\n");
			System.out.println(e.getMessage());
		}

		System.out.println(key);

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
			System.out.printf("RSA encryption failed\n");
			System.out.println(e.getMessage());
		}

		// Create Datagram Packet
		InetAddress hostToSend = null;
		try{
			hostToSend = InetAddress.getByName("localhost");
		}catch (Exception e){
			System.out.printf("Cant resolve host\n");
		}
		
		DatagramPacket serverPacket = new DatagramPacket( Base64.getDecoder().decode(dataToSend), Base64.getDecoder().decode(dataToSend).length, hostToSend, 10000);
		
		Callable<Integer> callable = new sendAndReceiveAck(serverPacket, 10000, port + 4000);

		ExecutorService executor = Executors.newSingleThreadExecutor();

		Future<Integer> future = executor.submit(callable);

		Integer result = null;
		try{
			result = future.get();
		} catch (Exception e){
			System.out.println("Failed to wait for thread");
		}

		System.out.println("Thread já acabou com valor: " + result);

		System.out.printf("Response packet sent to %s:%d! and received ack \n", hostToSend, 10000);

/* --------------------------------------------------------------------------------------------------------------------------- */
	}


	    //Byzantine process doesnt respect Prepare and Commit values
        public static String byzantineProcessPC(DatagramSocket socket, Integer consensusNumber, Integer leaderPort,
                                List<Integer> serverports, Integer port){

            Map<String, List<Integer>> prepareValues = new HashMap<String, List<Integer>>();
            Map<String, List<Integer>> commitValues = new HashMap<String, List<Integer>>();

            receivePrePrepare(socket, leaderPort);

            ibft_f.sendMessageToAll(message_type.PREPARE, "Vou trollar", serverports, port, socket, consensusNumber, consensusCounter);

            prepareValues.put("Vou trollar", new ArrayList<Integer>());
            prepareValues.get("Vou trollar").add(port);

            ibft_f.waitForQuorum(prepareValues, consensusNumber, message_type.PREPARE, socket, consensusCounter);

            ibft_f.sendMessageToAll(message_type.COMMIT, "Vou trollar no commit", serverports, port, socket, consensusNumber, consensusCounter);

            commitValues.put("Vou trollar no commit", new ArrayList<Integer>());
            commitValues.get("Vou trollar no commit").add(port);

            String valueDecided = ibft_f.waitForQuorum(commitValues, consensusNumber, message_type.COMMIT, socket, consensusCounter);

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

            ibft_f.sendMessageToAll(message_type.PREPARE, "Vou trollar", serverports, port, socket, consensusNumber, consensusCounter);

            prepareValues.put("Vou trollar", new ArrayList<Integer>());
            prepareValues.get("Vou trollar").add(port);

            ibft_f.waitForQuorum(prepareValues, consensusNumber, message_type.PREPARE, socket, consensusCounter);

            ibft_f.sendMessageToAll(message_type.COMMIT, "Vou trollar no commit", serverports, port, socket, consensusNumber, consensusCounter);

            commitValues.put("Vou trollar no commit", new ArrayList<Integer>());
            commitValues.get("Vou trollar no commit").add(port);

            String valueDecided = ibft_f.waitForQuorum(commitValues, consensusNumber, message_type.COMMIT, socket, consensusCounter);

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

            ibft_f.sendMessageToAll(message_type.PREPARE, "Vou trollar", serverports, port, socket, consensusNumber, consensusCounter);
            ibft_f.sendMessageToAll(message_type.PREPARE, "Vou trollar", serverports, port, socket, consensusNumber, consensusCounter);
            ibft_f.sendMessageToAll(message_type.PREPARE, "Vou trollar", serverports, port, socket, consensusNumber, consensusCounter);

            prepareValues.put("Vou trollar", new ArrayList<Integer>());
            prepareValues.get("Vou trollar").add(port);

            ibft_f.waitForQuorum(prepareValues, consensusNumber, message_type.PREPARE, socket, consensusCounter);

            ibft_f.sendMessageToAll(message_type.COMMIT, "Vou trollar no commit", serverports, port, socket, consensusNumber, consensusCounter);
            ibft_f.sendMessageToAll(message_type.COMMIT, "Vou trollar no commit", serverports, port, socket, consensusNumber, consensusCounter);
            ibft_f.sendMessageToAll(message_type.COMMIT, "Vou trollar no commit", serverports, port, socket, consensusNumber, consensusCounter);

            commitValues.put("Vou trollar no commit", new ArrayList<Integer>());
            commitValues.get("Vou trollar no commit").add(port);

            String valueDecided = ibft_f.waitForQuorum(commitValues, consensusNumber, message_type.COMMIT, socket, consensusCounter);

            if("Vou trollar no commit" != valueDecided){
                return "No Decision";
            }

            return valueDecided;
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


		//Thread taht receives inputs
		BlockingQueue<DatagramPacket> queue = new LinkedBlockingQueue<>();

		Callable<Void> callable = new receiveString(requests, port + 3000, queue);

		ExecutorService executor = Executors.newSingleThreadExecutor();

		executor.submit(callable);

		String tokenRcvd = null;
		DatagramPacket clientPacket = null;

		// Wait for client packets 
		while (true) {

				/* ---------------------------------------Recebi mensagem do cliente e desencriptei------------------------------ */
				Integer flag = 0;
				try{
					while(flag.equals(0)){
						clientPacket = queue.take();
						System.out.println("Recebi mensagem do cliente");
						flag = 1;
					}
				} catch (Exception e){
					System.out.println("Queue error");
				}

				String clientText = null;
				try{
					clientText = auxF.ConvertReceived(Base64.getEncoder().encodeToString(clientPacket.getData()), clientPacket.getLength());
				}catch (Exception e){
					System.out.println(e.getMessage());
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
					System.out.println(e.getMessage());
				}

				byte[] secretKeyinByte = auxF.digest(pMSDecrypted.getBytes(auxF.UTF_8), "SHA3-256");
				SecretKey key = new SecretKeySpec(secretKeyinByte, 0, secretKeyinByte.length, "AES");

				try{
					receivedFromJson = auxF.do_Decryption(receivedFromJson, key, 32);
				}catch (Exception e){
					System.out.println(e.getMessage());
				}

				// Parse JSON and extract arguments
				JsonObject requestJson = null;
				try{
					requestJson = JsonParser.parseString(receivedFromJson).getAsJsonObject();
				} catch (Exception e){
					System.out.println("Failed to parse Json received");
				}

				// Parse JSON and extract arguments
				requestJson = JsonParser.parseString(receivedFromJson).getAsJsonObject();
				String body = null;
				{
					body = requestJson.get("body").getAsString();
				}

				inputValue = body;

				System.out.printf("Identity cerified and received message: " + body + "\n");

			//Algoritmo 1
			if(port == leaderPort){
				System.out.println("Sou lider");
	/* ------------------------------------- Broadcast PREPREPARE message ------------------------------ */

				broadcast(inputValue, port, serverPorts, socket, consensusNumber);

/* --------------------------------------------------------------------------------------------------------------------------- */
			
			/* ------------------------------------- Algoritmo de consenso  ------------------------------ */

				valueDecided = leaderConsensus(socket, consensusNumber, inputValue, serverPorts, port);

/* --------------------------------------------------------------------------------------------------------------------------- */

				String response = valueDecided + "\n";

				System.out.println("path: " + keyPathPriv);

				respondToClient(tokenRcvd, keyPathPriv, socket, response, port, key, pMSDecrypted);

				consensusRounds.put(consensusCounter,valueDecided);

			}
			else if (serverType.equals("N")){
			/* ------------------------------------- Algoritmo de consenso  ------------------------------ */
				System.out.println("Sou normal");

				valueDecided = normalConsensus(socket, consensusNumber, leaderPort, serverPorts, port);

				String response = valueDecided + "\n";

				String path = null;
				switch(port.toString()){
					case "8001":
						System.out.println("path: " + keyPathPriv1);
						path = keyPathPriv1;
						break;
					case "8002":
						System.out.println("path: " + keyPathPriv2);
						path = keyPathPriv2;
						break;
				}

				respondToClient(tokenRcvd, path, socket, response, port, key, pMSDecrypted);

				System.out.printf("Sou normal e concordamos com isto: " + valueDecided + "\n");

				consensusRounds.put(consensusCounter, valueDecided);

	/* --------------------------------------------------------------------------------------------------------------------------- */
			}

			// Caso o processo seja bizantino e não respeite o valor as mensagens COMMIT e PREPARE
			else if (serverType.equals("B-PC")){
				valueDecided = byzantineProcessPC(socket, consensusNumber, leaderPort, serverPorts, port);

				String response = valueDecided + "\n";

				respondToClient(tokenRcvd, keyPathPriv3, socket, response, port, key, pMSDecrypted);

				consensusRounds.put(consensusCounter, valueDecided);

				System.out.printf("Sou bizantino e tentei trollar mas não deu e eles concordaram nisto " + valueDecided);
			}
			// Caso o processo seja bizantino e não respeite as mensagens PREPREPARE e o valor dos COMMITs e PREPAREs
			else if (serverType.equals("B-PP")){
				valueDecided = byzantineProcessPP(socket, consensusNumber, leaderPort, serverPorts, port);

				String response = valueDecided + "\n";

				respondToClient(tokenRcvd, keyPathPriv3, socket, response, port, key, pMSDecrypted);

				consensusRounds.put(consensusCounter, valueDecided);

				System.out.printf("Sou bizantino e tentei trollar mas não deu e eles concordaram nisto " + valueDecided);
			}
			// Caso o processo seja bizantino e envie várias vezes PREPARE E COMMIT fora de ordem
			else if (serverType.equals("B-PC-T")){
				valueDecided = byzantineProcessPCT(socket, consensusNumber, leaderPort, serverPorts, port);

				String response = valueDecided + "\n";

				respondToClient(tokenRcvd, keyPathPriv3, socket, response, port, key, pMSDecrypted);

				consensusRounds.put(consensusCounter, valueDecided);

				System.out.printf("Sou bizantino e tentei trollar mas não deu e eles concordaram nisto " + valueDecided);
			}
		}
	}
}