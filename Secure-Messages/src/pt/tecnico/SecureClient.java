package pt.tecnico;

import java.net.*;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.*;
import java.util.Map;
import java.util.Random;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Scanner;

import java.io.IOException;
import java.net.DatagramPacket;
import java.security.PublicKey;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;


//Client Class
public class SecureClient {

	//Create auxFunction class instance
	private static auxFunctions auxF = new auxFunctions();

	private static final String SPACE = " ";

	//Variable to client private key
	private static String myPriv;

	//Key paths
	private final static String keyPathPrivAlice = "keys/userPriv.der";
	private final static String keyPathPubAlice = "keys/userPub.der";
	private final static String keyPathPrivBob = "keys/userBobPriv.der";
	private final static String keyPathPubBob = "keys/userBobPub.der";
	private final static String keyPathPrivCharlie = "keys/userCharliePriv.der";
	private final static String keyPathPubCharlie = "keys/userCharliePub.der";

	//Map where we have the clients ID's associated to their private key path
	private static Map<String, String> keyByUser = new HashMap<String, String>(); 

	private static Scanner scanner = new Scanner(System.in);

	//Flag to indicate if it's a weak read or not
	private static Integer weakReadNext = 0;

	//Function to wait for terminal input
	public static String createRequestMessage(Integer port){

		JsonObject requestJson;
		while(true){
			System.out.print("> ");
			while (!scanner.hasNextLine()) {
				// wait for input
			}

			String line = scanner.nextLine();
			String cmd = line.split(SPACE)[0];
			String keySource = null, keyDestination = null, path = null;
			PublicKey publickey = null;

			//Switch to verify which of the three main possible command we received and create Json message to send
			switch (cmd) {
				case("CREATE"):
					path = keyByUser.get(line.split(SPACE)[1]);
					publickey = auxF.getPublicKey(path);

					try{
						keySource = Base64.getEncoder().encodeToString(publickey.getEncoded());
					} catch(Exception e){
						System.err.println("Error converting key");
						System.err.println(e.getMessage());
					}

					requestJson = JsonParser.parseString("{}").getAsJsonObject();
					{
						requestJson.addProperty("type", cmd);
						requestJson.addProperty("port", port.toString());
						requestJson.addProperty("pubKey", keySource);
					}

					break;
				case("TRANSFER"):
					String pathSource = keyByUser.get(line.split(SPACE)[1]);
					PublicKey publicKeySource = auxF.getPublicKey(pathSource);
					String pathDest = keyByUser.get(line.split(SPACE)[2]);
					PublicKey publicKeyDest = auxF.getPublicKey(pathDest);

					try{
						keySource = Base64.getEncoder().encodeToString(publicKeySource.getEncoded());
						keyDestination = Base64.getEncoder().encodeToString(publicKeyDest.getEncoded());
					} catch(Exception e){
						System.err.println("Error converting key");
						System.err.println(e.getMessage());
					}

					requestJson = JsonParser.parseString("{}").getAsJsonObject();
					{
						requestJson.addProperty("type", cmd);
						requestJson.addProperty("source", keySource);
						requestJson.addProperty("dest", keyDestination);
						requestJson.addProperty("amount", line.split(SPACE)[3]);
						requestJson.addProperty("port", port.toString());
					}
					break;
				case("BALANCE"):
					path = keyByUser.get(line.split(SPACE)[1]);
					publickey = auxF.getPublicKey(path);
					String mode = line.split(SPACE)[2]; //if it is a weak or strong read

					try{
						keySource = Base64.getEncoder().encodeToString(publickey.getEncoded());
					} catch(Exception e){
						System.err.println("Error converting key");
						System.err.println(e.getMessage());
					}

					requestJson = JsonParser.parseString("{}").getAsJsonObject();
					{
						requestJson.addProperty("type", cmd);
						requestJson.addProperty("port", port.toString());
						requestJson.addProperty("pubKey", keySource);
						requestJson.addProperty("mode", mode);
					}
					if(mode.equals("weak")){
						weakReadNext = 1;
					}
					break;
				default:
					System.out.println("Invalid command. Please try again.");
					continue;
			}
			break;
		}
		// Create request message

		String signature = null;

		//Create digital signature using RSA
		try{
			signature = auxF.do_RSAEncryption(auxF.digest(requestJson.toString().getBytes(auxF.UTF_8), "SHA3-256").toString(), myPriv);
		}
		catch (Exception e){
			System.err.printf("Failed to create digital signatura using RSA\n");
			System.err.println(e.getMessage());
		}

		JsonObject message = JsonParser.parseString("{}").getAsJsonObject();
		{
			message.addProperty("payload", requestJson.toString());
			message.addProperty("signature", signature);
		}

		String dataToSend = null;
		try{
			dataToSend = auxF.ConvertToSend(message.toString());
		}
		catch (Exception e){
			System.err.printf("Error parsing message\n");
			System.err.println(e.getMessage());
		}

		return dataToSend;
	}
	
	//Function that parses the message received
	public static String parseReceivedMessage(DatagramPacket serverPacket, String path){

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

		//Verify digital signature
		try{
			auxF.verifySignature(signatureEncrypted, path, receivedFromJson);
		}catch (Exception e){
			System.err.println("Digital signature verification failed");
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
		String body = null;
		{
			body = requestJson.get("body").getAsString();
		}

		return body;

	}

	public static void main(String[] args) throws IOException {
		// Check arguments
		if (args.length < 4) {
			System.err.println("Argument(s) missing!");
			System.err.printf("Usage: java %s host port%n", SecureClient.class.getName());
			System.exit(1);
		}


		final String serverHost = args[0];
		final InetAddress serverAddress = InetAddress.getByName(serverHost);
		final Integer nrServers = Integer.parseInt(args[1]);
		final String id = args[2]; //Client id (name)
		final Integer port = Integer.parseInt(args[3]); //Client port

		//Switch to attribute the key to the client
		switch(id){
			case "Alice":
				myPriv = keyPathPrivAlice;
				break;
			case "Bob":
				myPriv = keyPathPrivBob;
				break;
			case "Charlie":
				myPriv = keyPathPrivCharlie;
				break;
		}

		//List with all the servers' ports
		List<Integer> serverPorts = new ArrayList<Integer>(nrServers);
		Integer consensusNumber = (nrServers-1)/3 + 1;

		for(int i = 0; i < nrServers; i++){
			serverPorts.add(8000 + i);
		}

		//Populate ID and Paths Map
		keyByUser.put("Alice", keyPathPubAlice);
		keyByUser.put("Bob", keyPathPubBob);
		keyByUser.put("Charlie", keyPathPubCharlie);

		while(true){
			Random random = new Random();

			//Generate a random number between 49152 and 65535 to generate socket threads in these ports
			int randomNumber = random.nextInt(65535 - 49152 + 1) + 49152;

			String dataToSend = createRequestMessage(randomNumber);

			//In the case the command is not a weak read
			if(weakReadNext.equals(0)){

				//Create threads that execute sendAndReceiveAck.java call method
				ExecutorService executorService = Executors.newFixedThreadPool(serverPorts.size());
				List<sendAndReceiveAck> myThreads = new ArrayList<>();
				List<Future<Integer>> future = new ArrayList<>();
				
				//SendMessagetoAll
				for(int i = 0; i < nrServers; i++){
					
					//Create sockets in the range of 11000 to 11000 + nrServers
					DatagramPacket clientPacket = new DatagramPacket(Base64.getDecoder().decode(dataToSend),
							Base64.getDecoder().decode(dataToSend).length, serverAddress, serverPorts.get(i) + 3000);
					
					myThreads.add(new sendAndReceiveAck(clientPacket, serverPorts.get(i) + 3000, port + 3));
				}
				
				//Execute threads
				try{
					for(int i = 0; i < serverPorts.size(); i++){
						future.add(executorService.submit(myThreads.get(i)));
						future.get(i).get();
					}
				}catch(Exception e){
					System.err.println("Error launching threads");
					System.err.println(e.getMessage());
				}
			}

			//In the case it is a weak read
			else{
				ExecutorService executorService = Executors.newSingleThreadExecutor();
				Future<Integer> future;

				//Create sockets in the range of 11000 to 11000 + nrServers
				DatagramPacket clientPacket = new DatagramPacket(Base64.getDecoder().decode(dataToSend),
				Base64.getDecoder().decode(dataToSend).length, serverAddress, serverPorts.get(3) + 3000);

				sendAndReceiveAck process = new sendAndReceiveAck(clientPacket, serverPorts.get(3) + 3000, port + 3);
	
				//Execute threads
				try{
					future = executorService.submit(process);
					future.get();
				}catch(Exception e){
					System.err.println("Error launching thread");
					System.err.println(e.getMessage());
				}
			}


			ExecutorService executorServiceReceive = Executors.newSingleThreadExecutor();

			//Execute thread that waits for a quorum of responses
			executorServiceReceive.submit(new clientWaitResponse(randomNumber, auxF, consensusNumber,
													weakReadNext, auxF.getPublicKey(keyByUser.get(id))));

			weakReadNext = 0;
		}
	}
}