package pt.tecnico;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.PublicKey;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

public class clientWaitResponse implements Callable<Integer> {

    private final static String keyPathPublicServer = "keys/serverPub.der";
	private final static String keyPathPublicServer1 = "keys/serverPub1.der";
	private final static String keyPathPublicServer2 = "keys/serverPub2.der";
	private final static String keyPathPublicServer3 = "keys/serverPub3.der";

	private static final int MAX_UDP_DATA_SIZE = (64 * 1024 - 1) - 8 - 20;

	/* Buffer size for receiving a UDP packet. */
	private final int BUFFER_SIZE = MAX_UDP_DATA_SIZE;

    private Integer myPort;

    private Integer consensusNumber;

    private static auxFunctions auxF;

	private static Integer weakReadFlag;

	private static Map<PublicKey, Double> lastSnapShot;
	private static JsonObject lastSnapShotJson;
	private static PublicKey myPub;

    public clientWaitResponse(Integer myPort, auxFunctions auxFunction, Integer consensusNumber, Integer flag, PublicKey pubKey){
        auxF = auxFunction;
        this.myPort = myPort;
        this.consensusNumber = consensusNumber;
		weakReadFlag = flag;
		lastSnapShot = new HashMap<PublicKey, Double>();
		myPub = pubKey;
    }

	//Function that receives message and parses it
    private static String parseReceivedMessage(DatagramPacket serverPacket, Integer weakReadFlag){

		String clientText = null;
		try{
			clientText = auxF.ConvertReceived(Base64.getEncoder().encodeToString(serverPacket.getData()), serverPacket.getLength());
		}catch (Exception e){
			System.err.println("Error parsing");
			System.err.println(e.getMessage());
		}

		//Parse Json with payload and digital signature
		JsonObject received = JsonParser.parseString(clientText).getAsJsonObject();
		String receivedFromJson = null, signatureEncrypted = null;
		{
			receivedFromJson = received.get("payload").getAsString();
			signatureEncrypted = received.get("signature").getAsString();
		}

		//Tries verify digital signature with all known server keys
		try{
			auxF.verifySignature(signatureEncrypted, keyPathPublicServer, receivedFromJson);
		}catch (Exception e){
			try{
				auxF.verifySignature(signatureEncrypted, keyPathPublicServer1, receivedFromJson);
			}catch (Exception ex){
				try{
					auxF.verifySignature(signatureEncrypted, keyPathPublicServer2, receivedFromJson);
				}catch (Exception exc){
					try{
						auxF.verifySignature(signatureEncrypted, keyPathPublicServer3, receivedFromJson);
					}catch (Exception exce){
						System.err.println("Error verifying digital signature");
						System.err.println(exce.getMessage());
						System.exit(1);
					}
				}
			}
		}

		// Parse JSON and extract arguments
		JsonObject requestJson = null;
		try{
			requestJson = JsonParser.parseString(receivedFromJson).getAsJsonObject();
		} catch (Exception e){
			System.err.println("Failed to parse Json received");
			System.err.println(e.getMessage());
		}

		//If it's a weak read
		if(weakReadFlag.equals(0)){
			String body = null;
			// Parse JSON and extract arguments
			{
				body = requestJson.get("body").getAsString();
			}
			return body;
		}
		else{
			Map<PublicKey, Double> infoReceived = new HashMap<PublicKey, Double>();
			String signatures = null;
			JsonObject JsonReceived = null;
			// Parse JSON and extract arguments
			{
				signatures = requestJson.get("signatures").getAsString();
				JsonReceived = requestJson.get("state").getAsJsonObject();
			}

			List<JsonObject> accs = new ArrayList<JsonObject>();

			int j = 0;

			//If received snapshot is empty
			if(JsonReceived.toString().equals("{}")){
				lastSnapShot = null;
				lastSnapShotJson = null;
			}

			//Receives accounts info and parse them
			else{
				while(JsonReceived.getAsJsonObject("acc" + j) != null){
					accs.add(JsonReceived.getAsJsonObject("acc" + j));
					j++;
				}
	
				if(accs.get(0) != null)
					infoReceived = IBFT_Functions.convertJsonToMap(accs);
	
				lastSnapShot = infoReceived;
				lastSnapShotJson = JsonReceived;
			}

			return signatures;
		}
	}
    
    @Override
    public Integer call() throws Exception {
        // Code to be executed in this thread
        Map<String, List<Integer>> receivedResponses = new HashMap<String, List<Integer>>();

        DatagramSocket socket = new DatagramSocket(myPort);
		System.out.println("Wait for quorum of responses on port" + myPort);
		//Cycle waitin for quorum
		while(true){
			byte[] serverData = new byte[BUFFER_SIZE];
			DatagramPacket serverPacket = new DatagramPacket(serverData, serverData.length);
			try{
				// Receive response
				socket.receive(serverPacket);

				System.out.println("Received message from " + serverPacket.getPort());

				//Send ack 
				auxF.sendAck(socket, serverPacket);

				String body = parseReceivedMessage(serverPacket, weakReadFlag);

				//If it's not a weak read
				if(weakReadFlag.equals(0)){
					// Add to list of received
					if (receivedResponses.get(body) != null){
						if(!receivedResponses.get(body).contains(serverPacket.getPort())){
							receivedResponses.get(body).add(serverPacket.getPort());
						}
					}
					else{
						receivedResponses.put(body, new ArrayList<Integer>());
						receivedResponses.get(body).add(serverPacket.getPort());
					}
					// If we reached consensus
					if(receivedResponses.get(body).size() >= consensusNumber){
						// Close socket
						socket.close();
						System.out.printf("Received quorum of responses: %s \n", body);
						return 0;
					}
				}

				//If it's a weak read
				else{
					//Split signatures in an array
					String[] responseSplit = body.split(" ");

					Boolean verifiedSignatures = true;

					//If there's already a snapshot
					if(lastSnapShot != null){

						//For to decrypt every signature and verify its validity
						for(String signture: responseSplit){
							byte[] payloadHash = auxF.digest(lastSnapShotJson.toString().getBytes(auxF.UTF_8), "SHA3-256");
							String hashString = new String(payloadHash, "UTF-8");
							try{
								String signatureReceived = auxF.do_RSADecryption(signture, keyPathPublicServer);
								hashString.equals(signatureReceived);
							}catch(Exception e){
								try{
									String signatureReceived = auxF.do_RSADecryption(signture, keyPathPublicServer1);
									hashString.equals(signatureReceived);
								}catch(Exception exc){
									try{
										String signatureReceived = auxF.do_RSADecryption(signture, keyPathPublicServer2);
										hashString.equals(signatureReceived);
									}catch(Exception excep){
										try{
											String signatureReceived = auxF.do_RSADecryption(signture, keyPathPublicServer3);
											hashString.equals(signatureReceived);
										}catch(Exception exception){
											verifiedSignatures = false;
											System.err.println("Signature Invalid");
										}
									}
								}
							}
						}

						//If the valid signatures are enough to reach consensus number
						if(responseSplit.length >= consensusNumber && verifiedSignatures){
							Double value = lastSnapShot.get(myPub);
	
							// Close socket
							socket.close();
					
							System.out.printf("Received Balance: %s \n", value);
	
							return 0;
						}
						else{
							System.out.printf("Received response that was invalid\n");
							return 1;
						}
					}
					else{
						// Close socket
						socket.close();
				
						System.out.println("Received Balance: Account doesnt exist");

						return 0;
					}
				}
			}catch(Exception e){
				System.err.println("Failed in message");
				System.err.println(e.getMessage());
			}
		}
	}
}