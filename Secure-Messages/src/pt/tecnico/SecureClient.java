package pt.tecnico;

import java.net.*;
import java.util.Base64;
import java.io.IOException;
import java.net.DatagramPacket;
import java.security.PublicKey;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.*;
import java.util.Map;
import java.util.Random;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Scanner;

public class SecureClient {

	private static auxFunctions auxF = new auxFunctions();

	/** Buffer size for receiving a UDP packet. */

	private static final String SPACE = " ";

	private static String myPriv;

	//Key paths
	private final static String keyPathPrivAlice = "keys/userPriv.der";
	private final static String keyPathPubAlice = "keys/userPub.der";
	private final static String keyPathPrivBob = "keys/userBobPriv.der";
	private final static String keyPathPubBob = "keys/userBobPub.der";
	private final static String keyPathPrivCharlie = "keys/userCharliePriv.der";
	private final static String keyPathPubCharlie = "keys/userCharliePub.der";

	private static Map<String, String> keyByUser = new HashMap<String, String>(); 
	private static Scanner scanner = new Scanner(System.in);

	public static String createRequestMessage(Integer port){

		System.out.print("> ");
		while (!scanner.hasNextLine()) {
			// wait for input
		}
		String line = scanner.nextLine();
		String cmd = line.split(SPACE)[0];
		JsonObject requestJson;
		String keySource = null, keyDestination = null, path = null;
		PublicKey publickey = null;

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
				String pathS = keyByUser.get(line.split(SPACE)[1]);
				PublicKey publicKeyS = auxF.getPublicKey(pathS);
				String pathD = keyByUser.get(line.split(SPACE)[2]);
				PublicKey publicKeyD = auxF.getPublicKey(pathD);

				try{
					keySource = Base64.getEncoder().encodeToString(publicKeyS.getEncoded());
					keyDestination = Base64.getEncoder().encodeToString(publicKeyD.getEncoded());
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
				String mode = line.split(SPACE)[2];

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
				break;
			default:
				requestJson = null;
				break;
		}
		// Create request message

		String signature = null;
		try{
			signature = auxF.do_RSAEncryption(auxF.digest(requestJson.toString().getBytes(auxF.UTF_8), "SHA3-256").toString(), myPriv);
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
	
	public static String parseReceivedMessage(DatagramPacket serverPacket, String path){

		String clientText = null;
		try{
			clientText = auxF.ConvertReceived(Base64.getEncoder().encodeToString(serverPacket.getData()), serverPacket.getLength());
		}catch (Exception e){
			System.err.println("Error parsing");
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
			String signatureReceived = auxF.do_RSADecryption(signatureEncrypted, path);
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
		final String id = args[2];
		final Integer port = Integer.parseInt(args[3]);

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

			// generate a random number between 49152 and 65535
			int randomNumber = random.nextInt(65535 - 49152 + 1) + 49152;

			String dataToSend = createRequestMessage(randomNumber);

			ExecutorService executorService = Executors.newFixedThreadPool(serverPorts.size());
			List<sendAndReceiveAck> myThreads = new ArrayList<>();
			List<Future<Integer>> future = new ArrayList<>();

			for(int i = 0; i < nrServers; i++){
				//SendMessagetoAll

				DatagramPacket clientPacket = new DatagramPacket(Base64.getDecoder().decode(dataToSend),
						Base64.getDecoder().decode(dataToSend).length, serverAddress, serverPorts.get(i) + 3000);

				myThreads.add(new sendAndReceiveAck(clientPacket, serverPorts.get(i) + 3000, port + 3));
			}

			try{
				for(int i = 0; i < serverPorts.size(); i++){
					future.add(executorService.submit(myThreads.get(i)));
					future.get(i).get();
				}
			}catch(Exception e){
				System.err.println("Error launching threads");
				System.err.println(e.getMessage());
			}

			ExecutorService executorServiceReceive = Executors.newSingleThreadExecutor();
			executorServiceReceive.submit(new clientWaitResponse(randomNumber, auxF, consensusNumber));

		}
	}
}