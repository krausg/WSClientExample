package ws.client.example;

import java.net.MalformedURLException;
import java.net.URL;

import org.tempuri.Calculator;

public class ExampleClient {

	public void run() throws MalformedURLException {
		Calculator service;
		service = new Calculator(new URL("http://www.dneonline.com/calculator.asmx?WSDL"));
		System.out.println(service.getCalculatorSoap().add(12, 12));
	}

}
