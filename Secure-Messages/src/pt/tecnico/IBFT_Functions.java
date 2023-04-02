package pt.tecnico;

import java.net.*;
import java.util.Base64;
import java.util.Collection;
import java.util.Iterator;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
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

	public List<operation> convertJsonToOp(List<JsonObject> ops){

		List<operation> value = new ArrayList<operation>();

		for(int j = 0; j < ops.size(); j++){
			if(ops.get(j).get("type").getAsString().equals("CREATE")){
				operation operation = new operation(ops.get(j).get("type").getAsString(),
				auxF.convertStrToPK(ops.get(j).get("source").getAsString()));
				value.add(operation);
			}
			else if(ops.get(j).get("type").getAsString().equals("TRANSFER")){
				operation operation = new operation(ops.get(j).get("type").getAsString(),
				auxF.convertStrToPK(ops.get(j).get("source").getAsString()),
				auxF.convertStrToPK(ops.get(j).get("dest").getAsString()), 
							Integer.parseInt(ops.get(j).get("amount").getAsString()));
				value.add(operation);
			}
		}

		return value;
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
					clientText = auxF.ConvertReceived(Base64.getEncoder().encodeToString(messageFromServer.getData()), messageFromServer.getLength());
				}
				catch(Exception e){
					System.err.println("Message conversion failed");
					System.err.println(e.getMessage());
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
					System.err.println("Failed to parse Json received");
					System.err.println(e.getMessage());
				}

				boolean integrityCheck = auxF.checkIntegrity(hmac, requestJson);

				if(!integrityCheck){
					System.err.println("Integrity violated");
				}
				else{
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

					System.out.println(8000 + Integer.parseInt(idMainProcess));

					// If consensus instance is expected
					if(Integer.parseInt(instance) == instanceNumber){
						// If we receive message type expected
						List<operation> entry = null; 	//entry = key in which we added another vote
						if (messageType.equals(type.toString())){
							// Add to list of received
							for (List<operation> key : values.keySet()) {
								System.out.println(values.get(key));
								Integer counterValidEntries = 0;
								for(int j = 0; j < value.size(); j++){
									for(int k = 0; k < key.size(); k++){
										if(key.get(k).equals(value.get(j))){
											counterValidEntries++;
											if(counterValidEntries.equals(value.size())){
												if(!values.get(key).contains(8000 + Integer.parseInt(idMainProcess)))
													values.get(key).add(8000 + Integer.parseInt(idMainProcess));
												entry = key;
											}
											break;
										}
									}
								}
							}
							//if vote didnt match any existing key
							if(entry == null){
								values.put(value, new ArrayList<Integer>());
								values.get(value).add(8000 + Integer.parseInt(idMainProcess));
								entry = value;
							}

							// If we reached consensus
							if(values.get(entry).size() >= consensusNumber){
								System.out.printf("Agreed on value " + value + " for type " + type + "\n");
								return value;
							}
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
						Integer port, DatagramSocket socket, Integer consensusNumber, Integer instanceNumber){

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
						}
						else if(valueToSend.get(j).getID().toString().equals("TRANSFER")){
							jsonObject.addProperty("amount", valueToSend.get(j).getAmount().toString());
							jsonObject.addProperty("source", Base64.getEncoder().encodeToString(valueToSend.get(j).getSource().getEncoded()));
							jsonObject.addProperty("dest", Base64.getEncoder().encodeToString(valueToSend.get(j).getDestination().getEncoded()));
						}
						message.add("op" + j, jsonObject);
					}

				} catch (Exception e){
					System.err.println("Failed to create Json and arguments");
					System.err.println(e.getMessage());
				}

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

				String clientData = null;
				//Encrypt datagram with AES and simetric key
				try{
					clientData = auxF.ConvertToSend(messageWithHMAC.toString());
				}
				catch (Exception e){
					System.err.printf("Error in message parsing\n");
					System.err.println(e.getMessage());
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
	}
}