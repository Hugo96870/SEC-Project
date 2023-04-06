package pt.tecnico;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.concurrent.Callable;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.util.Base64;


public class receiveString implements Callable<Void> {

	private static final int MAX_UDP_DATA_SIZE = (64 * 1024 - 1) - 8 - 20;

	/* Buffer size for receiving a UDP packet. */
	private static final int BUFFER_SIZE = MAX_UDP_DATA_SIZE;

	private static byte[] buf = new byte[BUFFER_SIZE];

    private static auxFunctions auxF = new auxFunctions();

    private List<DatagramPacket> requests = new ArrayList<>();
    private Integer port;
    private BlockingQueue<DatagramPacket> queue = new LinkedBlockingQueue<>();

    public receiveString(List<DatagramPacket> requests,Integer port, BlockingQueue<DatagramPacket> queue){
        this.requests = requests;
        this.port = port;
        this.queue = queue;
    }
    
    @Override
    public Void call() throws Exception {
        // Code to be executed in this thread
        DatagramSocket socket = new DatagramSocket(port);

        while(true){
            System.out.println("Thread started");

            DatagramPacket clientPacket = new DatagramPacket(buf, buf.length);

            socket.receive(clientPacket);

            requests.add(clientPacket);

            queue.add(clientPacket);

            // Create request message
            JsonObject message = JsonParser.parseString("{}").getAsJsonObject();
            {
                message.addProperty("value", "ack");
            }

            String clientDataToSend = auxF.ConvertToSend(message.toString());

            DatagramPacket ackPacket = new DatagramPacket(Base64.getDecoder().decode(clientDataToSend),
            Base64.getDecoder().decode(clientDataToSend).length, clientPacket.getAddress(), clientPacket.getPort());

            //send ack datagram
            socket.send(ackPacket);
        }
    }
}