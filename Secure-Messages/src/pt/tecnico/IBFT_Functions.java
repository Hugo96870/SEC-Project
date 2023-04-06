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

	/**
	 * Maximum size for a UDP packet. The field size sets a theoretical limit of
	 * 65,535 bytes (8 byte header + 65,527 bytes of data) for a UDP datagram.
	 * However the actual limit for the data length, which is imposed by the IPv4
	 * protocol, is 65,507 bytes (65,535 − 8 byte UDP header − 20 byte IP header.
	 */

	 public final static String keyPathPublicServer = "keys/serverPub.der";
	 public final static String keyPathPublicServer1 = "keys/serverPub1.der";
	 public final static String keyPathPublicServer2 = "keys/serverPub2.der";
	 public final static String keyPathPublicServer3 = "keys/serverPub3.der";

	private static final int MAX_UDP_DATA_SIZE = (64 * 1024 - 1) - 8 - 20;

	/** Buffer size for receiving a UDP packet. */
	private final int BUFFER_SIZE = MAX_UDP_DATA_SIZE;

	public byte[] buf = new byte[BUFFER_SIZE];

	private static auxFunctions auxF = new auxFunctions();

	enum message_type{
		PREPREPARE,
		PREPARE,
		COMMIT;
	}

	public message_type mT;

	public Map<PublicKey, Double> convertJsonToMap(List<JsonObject> accs){

		Map<PublicKey, Double> valueReturn = new HashMap<PublicKey, Double>();

		for(int j = 0; j < accs.size(); j++){
			PublicKey pK = auxF.convertStrToPK(accs.get(j).get("key").getAsString());
			Double balance = Double.parseDouble(accs.get(j).get("balance").getAsString());

			valueReturn.put(pK, balance);
		}

		return valueReturn;
	}

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
					//Parse Json with payload and hmac
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
						String signatureReceived = auxF.do_RSADecryption(signatureEncrypted, pathToKey);
						byte[] payloadHash = auxF.digest(receivedFromJson.toString().getBytes(auxF.UTF_8), "SHA3-256");
						String hashString = new String(payloadHash, "UTF-8");
						hashString.equals(signatureReceived);
					}catch (Exception e){
						System.err.println("Error in assymetric decryption");
						System.err.println(e.getMessage());
						System.exit(1);
					}
				}
				//Others aren't
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

				for(int k = 0; k < values.size(); k++){
					for(int j = 0; j < bC.getBlockSize(); j++){
					}
				}

				// If consensus instance is expected
				if(Integer.parseInt(instance) == instanceNumber){
					// If we receive message type expected
					List<operation> entry = null; 	//entry = key in which we added another vote
					if (messageType.equals(type.toString())){
						// Add to list of received
						for (List<operation> key : values.keySet()) {
							if(compareLists(key, value)){
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
						message.addProperty("instance", instanceNumber.toString());
						message.addProperty("idMainProcess", ((Integer)(port % basePort)).toString());
					}
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
					try{
						signature = auxF.do_RSAEncryption(auxF.digest(message.toString().getBytes(auxF.UTF_8), "SHA3-256").toString()
															, myPriv);
					}
					catch (Exception e){
						System.err.printf("RSA encryption failed\n");
						System.err.println(e.getMessage());
					}
			
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
				//Other doesn't
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

		System.out.println("Sent message to all");
	}
}