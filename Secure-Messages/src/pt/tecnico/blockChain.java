package pt.tecnico;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;

public class blockChain{

    //Types of servers
	enum server_type{
		NORMAL,
		LEADER,
		B_PC,
        B_PC_T,
        B_PP;
	}

    public server_type sT;

    //Number of servers
    private Integer nrPorts;

    private Integer leaderPort;

    private List<Integer> serverPorts;
    //Number of current instance
	private static Integer instanceNumber;
    //Number to achieve consensus
    private Integer consensusMajority;

    Map<Integer, String> consensusRounds;

    public blockChain(){
        nrPorts = 4;

        serverPorts = new ArrayList<Integer>(nrPorts);
        for(int i = 0; i < nrPorts; i++){
            serverPorts.add(8000 + i);
        }

        leaderPort = 8000;

        consensusMajority = (nrPorts + (nrPorts-1)/3)/2 + 1;

        consensusRounds = new HashMap<Integer,String>();

        instanceNumber = 0;
    }

    public Integer getNrPorts(){
        return nrPorts;
    }

    public Integer getLeaderPort(){
        return leaderPort;
    }

    public List<Integer> getPorts(){
        return serverPorts;
    }

    public Boolean isLeader(Integer port){
        return leaderPort.equals(port);
    }

    public Integer getConsensusMajority(){
        return consensusMajority;
    }

    public void addToRound(Integer round, String value){
        consensusRounds.put(round, value);
    }

    public Integer getInstance(){
        return instanceNumber;
    }

    public void increaseInstance(){
        instanceNumber++;
    }

}