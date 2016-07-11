package com.joseprio.example;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;

import com.joseprio.httpserver.DigestAuthenticator;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

public class DigestHttpServer {

  public static void main(String[] args) throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
    server.createContext("/info", new InfoHandler());
    HttpContext hc1 = server.createContext("/get", new GetHandler());
    hc1.setAuthenticator(new DigestAuthenticator("get") {
		@Override
		public String gethAuthToken(String username) {
			return this.calculateAuthToken("admin", "password");
		}
    });

    server.setExecutor(null); // creates a default executor
    server.start();
    System.out.println("The server is running");
  }

  // http://localhost:8000/info
  static class InfoHandler implements HttpHandler {
    public void handle(HttpExchange httpExchange) throws IOException {
      String response = "Use /get to authenticate (user:admin pwd:password)";
      DigestHttpServer.writeResponse(httpExchange, response.toString());
    }
  }

  static class GetHandler implements HttpHandler {
    public void handle(HttpExchange httpExchange) throws IOException {
      StringBuilder response = new StringBuilder();
      response.append("<html><body>");
      response.append("hello " + httpExchange.getPrincipal().getUsername());
      response.append("</body></html>");
      DigestHttpServer.writeResponse(httpExchange, response.toString());
    }
  }

  public static void writeResponse(HttpExchange httpExchange, String response) throws IOException {
    httpExchange.sendResponseHeaders(200, response.length());
    OutputStream os = httpExchange.getResponseBody();
    os.write(response.getBytes());
    os.close();
  }

}
