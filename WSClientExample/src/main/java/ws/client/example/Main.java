package ws.client.example;

import java.net.MalformedURLException;

public class Main {

	
	public static void main(String[] args) throws MalformedURLException {
		System.setProperty("javax.xml.soap.SAAJMetaFactory", "com.sun.xml.messaging.saaj.soap.SAAJMetaFactoryImpl");
		new ExampleClient().run();
	}

}
