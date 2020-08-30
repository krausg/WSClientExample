package ws.client.example;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Objects;
import java.util.Set;
import java.util.TimeZone;
import java.util.UUID;

import javax.xml.namespace.QName;
import javax.xml.soap.Node;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPHeader;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;


public class WSSecurityHeaderSOAPHandler implements SOAPHandler<SOAPMessageContext> {
 
	private static final String SOAP_ELEMENT_PASSWORD = "Password";
	private static final String SOAP_ELEMENT_USERNAME = "Username";
	private static final String SOAP_ELEMENT_USERNAME_TOKEN = "UsernameToken";
	private static final String SOAP_ELEMENT_SECURITY = "Security";
	private static final String SOAP_ATTRIBUTE_MUSTUNDERSTAND = "soap:mustUnderstand";

	private static final String NAMESPACE_SECURITY = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
	private static final String PREFIX_SECURITY = "wsse";

	private static final String NAMESPACE_UTILITY = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
	private static final String PREFIX_UTILITY = "wsu";

	private static final String SOAP_ELEMENT_NONCE = "Nonce";
	private static final String SOAP_ELEMENT_CREATED = "Created";
	private static final String SOAP_ELEMENT_EXPIRES = "Expires";
	private static final String SOAP_ELEMENT_TIMESTAMP = "Timestamp";

	private static final QName SECURITY = new QName(NAMESPACE_SECURITY, SOAP_ELEMENT_SECURITY);

	private String usernameText;
	private String passwordText;
	private boolean ignoreMustunderstand = false;

	private boolean timestamp = false;

	private ThreadLocal<SimpleDateFormat> fmt;
	public static ThreadLocal<Node> securityNodeHolder = new ThreadLocal<>();

	public WSSecurityHeaderSOAPHandler() {
		this("username", "password", false);
	}

	public WSSecurityHeaderSOAPHandler(String usernameText, String passwordText, boolean ignoreMustUnderstand,
			boolean timestamp) {
		this.timestamp = timestamp;
		this.usernameText = usernameText;
		this.passwordText = passwordText;
		ignoreMustunderstand = ignoreMustUnderstand;
		fmt = new ThreadLocal<SimpleDateFormat>() {

			@Override
			protected SimpleDateFormat initialValue() {
				SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSX");
				sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
				return sdf;
			}
		};
	}

	public WSSecurityHeaderSOAPHandler(String usernameText, String passwordText, boolean ignoreMustUnderstand) {
		this(usernameText, passwordText, ignoreMustUnderstand, false);
	}

	@Override
	public boolean handleMessage(SOAPMessageContext soapMessageContext) {

		Boolean outboundProperty = (Boolean) soapMessageContext.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);

		if (outboundProperty.booleanValue()) {

			try {
				SOAPEnvelope soapEnvelope = soapMessageContext.getMessage().getSOAPPart().getEnvelope();

				SOAPHeader header = soapEnvelope.getHeader();
				if (header == null) {
					header = soapEnvelope.addHeader();
				}


				if ((WSSecurityHeaderSOAPHandler.securityNodeHolder != null)
						&& (WSSecurityHeaderSOAPHandler.securityNodeHolder.get() != null)) {
					header.addChildElement((SOAPElement) WSSecurityHeaderSOAPHandler.securityNodeHolder.get());
					WSSecurityHeaderSOAPHandler.securityNodeHolder.set(null);
					return true;
				}

				SOAPElement soapElementSecurityHeader = header.addChildElement(SOAP_ELEMENT_SECURITY, PREFIX_SECURITY,
						NAMESPACE_SECURITY);
				soapElementSecurityHeader.addNamespaceDeclaration(PREFIX_UTILITY, NAMESPACE_UTILITY);

				java.util.Date now = new java.util.Date();
				String createdText = fmt.get().format(now);
				if (timestamp) {
					java.util.Date expiresDate = addSeconds(now, 300);
					String expiresText = fmt.get().format(expiresDate);
					SOAPElement soapElementTimestamp = soapElementSecurityHeader.addChildElement(SOAP_ELEMENT_TIMESTAMP,
							PREFIX_UTILITY);
					SOAPElement soapElementTSCreated = soapElementTimestamp.addChildElement(SOAP_ELEMENT_CREATED,
							PREFIX_UTILITY);
					SOAPElement soapElementTSExpires = soapElementTimestamp.addChildElement(SOAP_ELEMENT_EXPIRES,
							PREFIX_UTILITY);
					soapElementTSCreated.addTextNode(createdText);
					soapElementTSExpires.addTextNode(expiresText);
				}

				SOAPElement soapElementUsernameToken = soapElementSecurityHeader
						.addChildElement(SOAP_ELEMENT_USERNAME_TOKEN, PREFIX_SECURITY);
				SOAPElement soapElementUsername = soapElementUsernameToken.addChildElement(SOAP_ELEMENT_USERNAME,
						PREFIX_SECURITY);
				soapElementUsername.addTextNode(usernameText);
				soapElementUsernameToken.setAttribute("wsu:Id", UUID.randomUUID().toString());

				SOAPElement soapElementPassword = soapElementUsernameToken.addChildElement(SOAP_ELEMENT_PASSWORD,
						PREFIX_SECURITY);

				SOAPElement soapElementNonce = soapElementUsernameToken.addChildElement(SOAP_ELEMENT_NONCE,
						PREFIX_SECURITY);
				soapElementNonce.setAttribute("EncodingType",

						"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
				String nonce = UUID.randomUUID().toString();
				String nonceBase64 = Base64.encodeBase64String(nonce.getBytes());
				soapElementNonce.addTextNode(nonceBase64);

				SOAPElement soapElementCreated = soapElementUsernameToken.addChildElement(SOAP_ELEMENT_CREATED,
						PREFIX_UTILITY);
 
				soapElementCreated.addTextNode(createdText);

				soapElementPassword.setAttribute("Type",
						"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest");

				byte[] passwortDigest = DigestUtils.sha1(nonce + createdText + passwordText);
				String passwortDigestBase64 = Base64.encodeBase64String(passwortDigest);
				soapElementPassword.addTextNode(passwortDigestBase64);

			} catch (Exception e) {
				throw new IllegalStateException("Error on wsSecurityHandler: " + e.getMessage());
			}

		}
		return true;
	}
	
	/*
	 * Kann  
	 */
	private static Date addSeconds(final Date date,final int amount) {
        Objects.requireNonNull(date);
        final Calendar c = Calendar.getInstance();
        c.setTime(date);
        c.add( Calendar.SECOND, amount);
        return c.getTime();
    }

	@Override
	public void close(MessageContext context) {
		// Nichts zu tun hier
	}

	@Override
	public boolean handleFault(SOAPMessageContext context) {
		return true;
	}

	@Override
	public Set<QName> getHeaders() {
		return null;
	}
}
