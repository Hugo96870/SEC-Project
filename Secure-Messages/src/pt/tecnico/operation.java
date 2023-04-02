package pt.tecnico;

import java.security.PublicKey;

import pt.tecnico.IBFT_Functions.message_type;

public class operation{

    enum operation_type{
        TRANSFER,
        CREATE;
    }

    operation_type identifier;
    PublicKey source;
    PublicKey destination;
    Integer amount;

    public operation(String identifier, PublicKey source, PublicKey destination, Integer amount){
        this.identifier = operation_type.TRANSFER;
        this.source = source;
        this.destination = destination;
        this.amount = amount;
    }

    public operation(String identifier, PublicKey source){
        this.identifier = operation_type.CREATE;
        this.source = source;
        this.destination = null;
        this.amount = null;
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

    public String toString(){
        if(this.identifier.equals(operation_type.CREATE)){
            return this.identifier.toString() + " " + this.source.toString();
        }
        else{
            return this.identifier.toString() + " " + this.source.toString() + " " + this.destination.toString() + " " + this.amount.toString();
        }
    }

    public boolean equals(operation op){
        if(op.getID().equals(operation_type.CREATE)){
            return this.identifier.toString().equals(op.identifier.toString()) && this.source.equals(op.source);
        }
        else{
            return this.identifier.toString().equals(op.identifier.toString()) && this.amount.equals(op.amount) &&
                this.source.equals(op.source) && this.destination.equals(op.destination);
        }
    }

}