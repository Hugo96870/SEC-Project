package pt.tecnico;

import java.net.*;
import java.util.Base64;
import java.util.HashMap;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.PublicKey;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;

public class IBFT_Functions{

	public final static String keyPathPublicServer = "keys/serverPub.der";
	public final static String keyPathPublicServer1 = "keys/serverPub1.der";
	public final static String keyPathPublicServer2 = "keys/serverPub2.der";
	public final static String keyPathPublicServer3 = "keys/serverPub3.der";

	/**
	 * Maximum size for a UDP packet. The field size sets a theoretical limit of
	 * 65,535 bytes (8 byte header + 65,527 bytes of data) for a UDP datagram.
	 * However the actual limit for the data length, which is imposed by the IPv4
	 * protocol, is 65,507 bytes (65,535 − 8 byte UDP header − 20 byte IP header.
	 */
	private static final int MAX_UDP_DATA_SIZE = (64 * 1024 - 1) - 8 - 20;

	/** Buffer size for receiving a UDP packet. */
	private static final int BUFFER_SIZE = MAX_UDP_DATA_SIZE;

	public static byte[] buf = new byte[BUFFER_SIZE];

	//Create auxFunctions instance
	private static auxFunctions auxF = new auxFunctions();

	//Create messages types
	enum message_type{
		PREPREPARE,
		PREPARE,
		COMMIT;
	}

	public message_type mT;

	//Function that waits until we have a quorum of snapshot signatures
	public static List<String> waitSnapshot(Map<PublicKey, Double> snapshot, String signature,
						Integer consensusMajority, DatagramSocket socket, blockChain bC){

		System.out.println("Waiting for quorum of snapshot signatures");
		List<String> signatures = new ArrayList<String>();
						
		//Add self signature to the list of signatures
		signatures.add(signature);

		DatagramPacket messageFromServer = new DatagramPacket(buf, buf.length);

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
				String receivedFromJson = null, signatureEncrypted = null, idMainProcess = null;
				{
					receivedFromJson = received.get("payload").getAsString();
					signatureEncrypted = received.get("signature").getAsString();
					idMainProcess = received.get("idMainProcess").getAsString();
				}
				// Parse JSON and extract arguments
				try{
					requestJson = JsonParser.parseString(receivedFromJson).getAsJsonObject();
				} catch (Exception e){
					System.err.println("Failed to parse Json received");
					System.err.println(e.getMessage());
				}
				String pathToKey = null;

				//Check from which server the message was sent
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
					auxF.verifySignature(signatureEncrypted, pathToKey, receivedFromJson);
				}catch (Exception e){
					System.err.println("Error in the verification of digital signature");
					System.err.println(e.getMessage());
					System.exit(1);
				}

				try{
					List<JsonObject> accs = new ArrayList<JsonObject>();

					Map<PublicKey, Double> valueReceived = new HashMap<PublicKey, Double>();

					//Receive map from Json and parse it into a map of accounts
					for(int j = 0; j < bC.getAccounts().size(); j++){
						accs.add(requestJson.getAsJsonObject("acc" + j));
					}

					if(accs.get(0) != null)
						valueReceived = convertJsonToMap(accs);

					Integer counter = 0;
					
					//Compare received map with the local map and if they are equal add signature to list
					for(PublicKey myKey: snapshot.keySet()){
						for(PublicKey keyReceived: valueReceived.keySet()){
							if(myKey.equals(keyReceived) && snapshot.get(myKey).equals(valueReceived.get(keyReceived))){
								counter++;
								if(counter.equals(snapshot.size())){
									signatures.add(signatureEncrypted);
									if(((Integer)signatures.size()).equals(bC.getNrPorts())){
										System.out.println("Got a quorum of snapshiot signatures");
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

	//Function that sends snapshot request to all servers
	public List<String> doSnapshot(Map<PublicKey, Double> snapshot, String path, Integer port,
									List<Integer> serverPorts, blockChain bC, DatagramSocket socket){

		InetAddress serverToSend = null;
		try{
			serverToSend = InetAddress.getByName("localhost");
		}catch (Exception e){
			System.err.printf("Cant resolve host\n");
			System.err.println(e.getMessage());
		}

		//Create request message
		JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
		Integer counter = 0;
		for(PublicKey key: snapshot.keySet()){
			JsonObject jsonObject = new JsonObject();
			jsonObject.addProperty("key", Base64.getEncoder().encodeToString(key.getEncoded()));
			jsonObject.addProperty("balance", snapshot.get(key).toString());
			requestJson.add("acc" + counter, jsonObject);
			counter++;
		}

		String signature = null;

		//Sign message
		try{
			signature = auxF.do_RSAEncryption(auxF.digest(requestJson.toString().getBytes(auxF.UTF_8), "SHA3-256").toString(), path);
		}
		catch (Exception e){
			System.err.printf("Digital signature failed\n");
			System.err.println(e.getMessage());
		}

		JsonObject message = JsonParser.parseString("{}").getAsJsonObject();
		{
			message.addProperty("payload", requestJson.toString());
			message.addProperty("signature", signature);
			message.addProperty("idMainProcess", ((Integer)(port % 8000)).toString());
		}
		String clientData = null;
		try{
			clientData = auxF.ConvertToSend(message.toString());
		}
		catch (Exception e){
			System.err.printf("Error parsing message\n");
			System.err.println(e.getMessage());
		}

		//Create thread pool 
		ExecutorService executorService = Executors.newFixedThreadPool(serverPorts.size());
		List<sendAndReceiveAck> myThreads = new ArrayList<>();

		//For to fill threads' pool
		for(int i = 0; i < serverPorts.size(); i++){
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

		//Send message to every other servers 
		try{
			for(int i = 0; i < serverPorts.size() - 1; i++){
				executorService.submit(myThreads.get(i));
			}
		}catch(Exception e){
			System.err.println("Error launching threads");
			System.err.println(e.getMessage());
		}

		System.out.println("Sent snapshot signed to every server");


		return waitSnapshot(snapshot, signature, bC.getConsensusMajority(), socket, bC);
	}

	//Function that receives a Map and converts it into a Json Object
	public JsonObject convertMapIntoJson(Map<PublicKey, Double> snapshot){

		JsonObject requestJson = JsonParser.parseString("{}").getAsJsonObject();
		Integer counter = 0;

		//Each map entry is a Json Object
		for(PublicKey key: snapshot.keySet()){
			JsonObject jsonObject = new JsonObject();
			jsonObject.addProperty("key", Base64.getEncoder().encodeToString(key.getEncoded()));
			jsonObject.addProperty("balance", snapshot.get(key).toString());
			requestJson.add("acc" + counter, jsonObject);
			counter++;
		}

		return requestJson;
	}

	//Function that receives a Json and converts it into Map
	public static Map<PublicKey, Double> convertJsonToMap(List<JsonObject> accs){

		Map<PublicKey, Double> valueReturn = new HashMap<PublicKey, Double>();

		for(int j = 0; j < accs.size(); j++){
			PublicKey pK = auxF.convertStrToPK(accs.get(j).get("key").getAsString());
			Double balance = Double.parseDouble(accs.get(j).get("balance").getAsString());

			valueReturn.put(pK, balance);
		}

		return valueReturn;
	}

	//Function that converts Json Objects to a list of operations
	public List<operation> convertJsonToOp(List<JsonObject> ops){

		List<operation> value = new ArrayList<operation>();

		for(int j = 0; j < ops.size(); j++){
			if(ops.get(j).get("type").getAsString().equals("CREATE")){
				operation operation = new operation(ops.get(j).get("type").getAsString(),
				auxF.convertStrToPK(ops.get(j).get("source").getAsString()),
					Integer.parseInt(ops.get(j).get("port").getAsString()));
				value.add(operation);
			}
			else if(ops.get(j).get("type").getAsString().equals("TRANSFER")){
				operation operation = new operation(ops.get(j).get("type").getAsString(),
				auxF.convertStrToPK(ops.get(j).get("source").getAsString()),
				auxF.convertStrToPK(ops.get(j).get("dest").getAsString()), 
							Integer.parseInt(ops.get(j).get("amount").getAsString()),
								Integer.parseInt(ops.get(j).get("port").getAsString()));
				value.add(operation);
			}
		}

		return value;
	}

	//Function that compares two lists of operations and returns true if they're equal
	public boolean compareLists(List<operation> list1, List<operation> list2){
		Integer counterValidEntries = 0;
		for(int j = 0; j < list2.size(); j++){
			for(int k = 0; k < list1.size(); k++){
				if(list1.get(k).equals(list2.get(j))){
					counterValidEntries++;
					if(counterValidEntries.equals(list2.size())){
						return true;
					}
					break;
				}
			}
		}
		return false;
	}

	//Functions that waits for a quorum of a certain message
	public List<operation> waitForQuorum(Map<List<operation>, List<Integer>> values, Integer consensusNumber,
						message_type type, DatagramSocket socket, Integer instanceNumber, blockChain bC){

		//Cycle waitin for quorum
		String messageType = null, instance = null, idMainProcess = null;
		while(true){
			DatagramPacket messageFromServer = new DatagramPacket(buf, buf.length);
			System.out.printf("Waiting for this request " + type + "\n");
			List<operation> value = null;
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

				//Prepare messages are digitally signed 
				if(type.equals(message_type.PREPARE)){

					//Parse Json with payload and digital signature
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
					{
						idMainProcess = requestJson.get("idMainProcess").getAsString();
					}
					String pathToKey = null;

					//Switch to get the public key of the server that sent the PREPARE message
					switch(idMainProcess){
						case "0":
							pathToKey = keyPathPublicServer;
							break;
						case "1":
							pathToKey = keyPathPublicServer1;
							break;
						case "2":
							pathToKey = keyPathPublicServer2;
							break;
						case "3":
							pathToKey = keyPathPublicServer3;
							break;
					}
					try{
						auxF.verifySignature(signatureEncrypted, pathToKey, receivedFromJson);
					}catch (Exception e){
						System.err.println("Error in digital signature");
						System.err.println(e.getMessage());
						System.exit(1);
					}
				}

				//Others aren't digitaly sign
				else{
					//Parse Json with payload and hmac
					JsonObject received = JsonParser.parseString(clientText).getAsJsonObject();
					String hmac = null, receivedFromJson = null;
					{
						hmac = received.get("hmac").getAsString();
						receivedFromJson = received.get("payload").getAsString();
					}
	
					// Parse JSON and extract arguments
					try{
						requestJson = JsonParser.parseString(receivedFromJson).getAsJsonObject();
					} catch (Exception e){
						System.err.println("Failed to parse Json received");
						System.err.println(e.getMessage());
					}
	
					boolean integrityCheck = auxF.checkIntegrity(hmac, requestJson);
	
					if(!integrityCheck){
						System.err.println("Integrity violated");
						System.exit(1);
					}
				}

				//Parse the block received into a list of operations
				try{
					List<JsonObject> ops = new ArrayList<JsonObject>(bC.getBlockSize());
					{
						messageType = requestJson.get("messageType").getAsString();
						instance = requestJson.get("instance").getAsString();
						idMainProcess = requestJson.get("idMainProcess").getAsString();
					}

					for(int j = 0; j < bC.getBlockSize(); j++){
						ops.add(requestJson.getAsJsonObject("op" + j));
					}

					if(ops.get(0) == null){
						value = new ArrayList<operation>();
					}
					else{
						value = convertJsonToOp(ops);
					}

				} catch (Exception e){
					System.err.println("Failed to extract arguments from Json payload");
					System.err.println(e.getMessage());
				}

				auxF.sendAck(socket, messageFromServer);

				// If consensus instance is expected
				if(Integer.parseInt(instance) == instanceNumber){
					List<operation> entry = null; 	//entry = key in which we added another vote

					// If we receive message type expected
					if (messageType.equals(type.toString())){
						//For that iterates the received block
						for (List<operation> key : values.keySet()) {
							//Check if in the vote's list there are already an entry with that block
							if(compareLists(key, value)){
								//Verify if the current process add already voted for that block
								if(!values.get(key).contains(8000 + Integer.parseInt(idMainProcess))){
									//Add vote to blockChain list of prepared value for this round
									if(type.toString().equals("PREPARE")){
										bC.addPrepareToRound(bC.getRound(), messageFromServer);
									}
									values.get(key).add(8000 + Integer.parseInt(idMainProcess));
								}
								entry = key;
							}
						}
						//if vote didnt match any existing key
						if(entry == null){
							//Add vote to blockChain list of prepared value for this round
							if(type.toString().equals("PREPARE")){
								bC.addPrepareToRound(bC.getRound(), messageFromServer);
							}
							values.put(value, new ArrayList<Integer>());
							values.get(value).add(8000 + Integer.parseInt(idMainProcess));
							entry = value;
						}

						// If we reached consensus
						if(values.get(entry).size() >= consensusNumber){
							System.out.printf("Agreed on value for type " + type + "\n");
							return value;
						}
					}
				}
			
			}catch(Exception e){
				System.err.println("Failed in message");
				System.err.println(e.getMessage());
			}
		}
	}

	//Function that does the broadcast of a message type to all other servers
	public void sendMessageToAll(message_type type, List<operation> valueToSend, List<Integer> serverPorts,
						Integer port, DatagramSocket socket, Integer consensusNumber, Integer instanceNumber, String myPriv){

		InetAddress serverToSend = null;

		try{
			serverToSend = InetAddress.getByName("localhost");
		}catch (Exception e){
			System.err.printf("Cant resolve host\n");
			System.err.println(e.getMessage());
		}

		//Send message to servers
		System.out.println("Going to send the following requests " + type);

		//Create thread pool
		ExecutorService executorService = Executors.newFixedThreadPool(serverPorts.size());
		List<sendAndReceiveAck> myThreads = new ArrayList<>();

		Integer basePort = 8000;

		for(int i = 0; i < serverPorts.size(); i++){
			//We dont send message to ourselves, only assume we sent and received it
			if(!port.equals(serverPorts.get(i))){
				Integer portToSend = serverPorts.get(i);

				JsonObject message = null;
				// Create request message
				try{
					message = JsonParser.parseString("{}").getAsJsonObject();
					{
						message.addProperty("messageType", type.name());
						message.addProperty("instance", instanceNumber.toString());
						message.addProperty("idMainProcess", ((Integer)(port % basePort)).toString());
					}
					//Add operations to message
					for(int j = 0; j < valueToSend.size(); j++){
						JsonObject jsonObject = new JsonObject();
						jsonObject.addProperty("type", valueToSend.get(j).getID().toString());
						if(valueToSend.get(j).getID().toString().equals("CREATE")){
							jsonObject.addProperty("source", Base64.getEncoder().encodeToString(valueToSend.get(j).getSource().getEncoded()));
							jsonObject.addProperty("port", valueToSend.get(j).getPort().toString());
						}
						else if(valueToSend.get(j).getID().toString().equals("TRANSFER")){
							jsonObject.addProperty("amount", valueToSend.get(j).getAmount().toString());
							jsonObject.addProperty("source", Base64.getEncoder().encodeToString(valueToSend.get(j).getSource().getEncoded()));
							jsonObject.addProperty("dest", Base64.getEncoder().encodeToString(valueToSend.get(j).getDestination().getEncoded()));
							jsonObject.addProperty("port", valueToSend.get(j).getPort().toString());
						}
						message.add("op" + j, jsonObject);
					}

				} catch (Exception e){
					System.err.println("Failed to create Json and arguments");
					System.err.println(e.getMessage());
				}
				String clientData = null;
				//Prepare messages need to be digitally signed
				if(type.equals(message_type.PREPARE)){
					String signature = null;
					//Sign PREPARE messages
					try{
						signature = auxF.do_RSAEncryption(auxF.digest(message.toString().getBytes(auxF.UTF_8), "SHA3-256").toString()
															, myPriv);
					}
					catch (Exception e){
						System.err.printf("RSA encryption failed\n");
						System.err.println(e.getMessage());
					}
					
					//Create PREPARE message
					JsonObject messageToSend = JsonParser.parseString("{}").getAsJsonObject();
					{
						messageToSend.addProperty("payload", message.toString());
						messageToSend.addProperty("signature", signature);
					}
			
					try{
						clientData = auxF.ConvertToSend(messageToSend.toString());
					}
					catch (Exception e){
						System.err.printf("Error parsing message\n");
						System.err.println(e.getMessage());
					}
				}
				//Others doesn't
				else{
					//Create hmac to assure integrity
					byte[] hmac = null;
					try{
						hmac = auxF.digest(message.toString().getBytes(auxF.UTF_8), "SHA3-256");
					}catch (IllegalArgumentException e){
						System.err.println("Failed to hash value");
						System.err.println(e.getMessage());
					}

					//ENVIAR HMAC EM BASE 64
					JsonObject messageWithHMAC = JsonParser.parseString("{}").getAsJsonObject();
					{
						messageWithHMAC.addProperty("payload", message.toString());
						messageWithHMAC.addProperty("hmac", Base64.getEncoder().encodeToString(hmac));
					}

					//Encrypt datagram with AES and simetric key
					try{
						clientData = auxF.ConvertToSend(messageWithHMAC.toString());
					}
					catch (Exception e){
						System.err.printf("Error in message parsing\n");
						System.err.println(e.getMessage());
					}
				}

				//Create datagram
				DatagramPacket packet = null;
				try{
					packet = new DatagramPacket(Base64.getDecoder().decode(clientData),
					Base64.getDecoder().decode(clientData).length, serverToSend, portToSend);
				} catch (Exception e){
					System.err.println("Failed to create Datagram");
					System.err.println(e.getMessage());
				}

				//Populate thread pool
				myThreads.add(new sendAndReceiveAck(packet, serverPorts.get(i), 0));

			}
		}

		//Execute pool thread
		try{
			for(int i = 0; i < serverPorts.size() - 1; i++){
				executorService.submit(myThreads.get(i));
			}
		}catch(Exception e){
			System.err.println("Error launching threads");
			System.err.println(e.getMessage());
		}

		System.out.println("Sent message to all");
	}
}