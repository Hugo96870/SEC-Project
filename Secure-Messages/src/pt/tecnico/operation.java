package pt.tecnico;

import java.security.PublicKey;

public class operation{

    enum operation_type{
        TRANSFER,
        CREATE,
        BALANCE;
    }

    private operation_type identifier;
    private PublicKey source;
    private PublicKey destination;
    private Integer amount;
    private Integer port;
    private String mode;

    //Constructor for TRANSFER operation
    public operation(String identifier, PublicKey source, PublicKey destination, Integer amount, Integer port){
        this.identifier = operation_type.TRANSFER;
        this.source = source;
        this.destination = destination;
        this.amount = amount;
        this.port = port;
        this.mode = null;
    }
    //Constructor for CREATE operation
    public operation(String identifier, PublicKey source, Integer port){
        this.identifier = operation_type.CREATE;
        this.source = source;
        this.destination = null;
        this.amount = null;
        this.port = port;
        this.mode = null;
    }
    //Constructor for BALANCE operation
    public operation(String identifier, PublicKey source, Integer port, String mode){
        this.identifier = operation_type.BALANCE;
        this.source = source;
        this.destination = null;
        this.amount = null;
        this.port = port;
        this.mode = mode;
    }

    public PublicKey getSource(){
        return source;
    }

    public PublicKey getDestination(){
        return destination;
    }

    public Integer getAmount(){
        return amount;
    }

    public operation_type getID(){
        return identifier;
    }

    //Return class into String
    public String toString(){
        if(this.identifier.equals(operation_type.CREATE)){
            return this.identifier.toString() + " " + this.source.toString();
        }
        else{
            return this.identifier.toString() + " " + this.source.toString() + " " + this.destination.toString() + " " + this.amount.toString();
        }
    }

    //Compare two operations
    public boolean equals(operation op){
        if(op.getID().equals(operation_type.CREATE)){
            return this.identifier.toString().equals(op.identifier.toString()) && this.source.equals(op.source);
        }
        else{
            return this.identifier.toString().equals(op.identifier.toString()) && this.amount.equals(op.amount) &&
                this.source.equals(op.source) && this.destination.equals(op.destination);
        }
    }

    public Integer getPort(){
        return port;
    }

    public String getMode(){
        return mode;
    }

}