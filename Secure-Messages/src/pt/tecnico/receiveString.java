package pt.tecnico;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.concurrent.Callable;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;


public class receiveString implements Callable<Void> {

	private static final int MAX_UDP_DATA_SIZE = (64 * 1024 - 1) - 8 - 20;

	/* Buffer size for receiving a UDP packet. */
	private static final int BUFFER_SIZE = MAX_UDP_DATA_SIZE;

	private static byte[] buf = new byte[BUFFER_SIZE];

    List<DatagramPacket> requests = new ArrayList<>();
    Integer port;
    BlockingQueue<DatagramPacket> queue = new LinkedBlockingQueue<>();

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
        }
    }

}