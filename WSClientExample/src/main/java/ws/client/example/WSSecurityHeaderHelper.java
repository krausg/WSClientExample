package ws.client.example;

import java.util.ArrayList;

import javax.xml.ws.BindingProvider;


public class WSSecurityHeaderHelper {

	/**
	 * Fuegt einem Binding Provider ein WSSecurity Header hinzu mit  Benutzer und Password
	 * @param inBindingProvider Instanz von einem BindingProvider
	 * @param benutzer String username zur authentizierung 
	 * @param passwort String passwort zur authentizierung
	 * @return Liefert die {@link BindingProvider} Instanz mit eingestelltem WSSecurityHeader
	 */
	public static BindingProvider addWSSecurity(BindingProvider bindingProvider, String benutzer, String passwort) {
		bindingProvider.getRequestContext().putIfAbsent("ws-security.username", benutzer);
		bindingProvider.getRequestContext().putIfAbsent("ws-security.password", passwort);

		var handlerChain = bindingProvider.getBinding().getHandlerChain();
		if (handlerChain == null) {
			handlerChain = new ArrayList<>();
		}

		handlerChain.add(new WSSecurityHeaderSOAPHandler(benutzer, passwort, false));
		bindingProvider.getBinding().setHandlerChain(handlerChain);


		return bindingProvider;
	}

}

