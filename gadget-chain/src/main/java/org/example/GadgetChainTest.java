package org.example;

import java.io.*;

public class GadgetChain {
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        Exploit exploit = new Exploit();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(out);
        objectOutputStream.writeObject(exploit);
        byte[] bytes = out.toByteArray();

        ObjectInputStream inputStream = new ObjectInputStream(new ByteArrayInputStream(bytes));
        inputStream.readObject();
    }
}
