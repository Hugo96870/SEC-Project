package pt.tecnico;

import java.net.*;
import java.util.Base64;
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

	public String waitForQuorum(Map<String, List<Integer>> values, Integer consensusNumber,
						message_type type, DatagramSocket socket, Integer instanceNumber){

		//Cycle waitin for quorum
		String messageType = null, instance = null, value = null, idMainProcess = null;
		while(true){
			DatagramPacket messageFromServer = new DatagramPacket(buf, buf.length);
			System.out.printf("Waiting for this request " + type + "\n");
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
						{
							messageType = requestJson.get("messageType").getAsString();
							instance = requestJson.get("instance").getAsString();
							value = requestJson.get("value").getAsString();
							idMainProcess = requestJson.get("idMainProcess").getAsString();
						}
					} catch (Exception e){
						System.err.println("Failed to extract arguments from Json payload");
						System.err.println(e.getMessage());
					}

					auxF.sendAck(socket, messageFromServer);

					// If consensus instance is expected
					if(Integer.parseInt(instance) == instanceNumber){
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
								System.out.printf("Agrred on value " + value + " for type " + type + "\n");
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

	public void sendMessageToAll(message_type type, String valueToSend, List<Integer> serverPorts,
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
						message.addProperty("value", valueToSend);
						message.addProperty("idMainProcess", ((Integer)(port % basePort)).toString());
					}
				} catch (Exception e){
					System.err.println("Failed to parse Json and arguments");
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