package ws.client.example;

import java.net.MalformedURLException;
import java.net.URL;

import javax.xml.ws.BindingProvider;

import org.tempuri.Calculator;
import org.tempuri.CalculatorSoap;

public class ExampleClient {

	private String user = "";
	private String password = "";

	public void run() throws MalformedURLException {
		// erstellt client
		CalculatorSoap calculatorSoap =  new Calculator(new URL("http://www.dneonline.com/calculator.asmx?WSDL")).getCalculatorSoap();
		// fuegt die security hinzu mit user und pw
		calculatorSoap = (CalculatorSoap) WSSecurityHeaderHelper.addWSSecurity((BindingProvider) calculatorSoap, user, password);
		// ausfuehrung
		System.out.println(calculatorSoap.add(12, 12));
	}

}
