import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;

import org.apache.commons.codec.binary.Base64;

import org.apache.log4j.Logger;

import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.core.util.MultivaluedMapImpl;
import javax.ws.rs.core.MultivaluedMap;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Iterator;

import org.w3c.dom.*;
import org.xml.sax.SAXException;
import javax.xml.parsers.*;
import javax.xml.xpath.*;
import javax.xml.transform.*;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.namespace.NamespaceContext;

public class AIMClientLogin {
    private static Client client = Client.create();
    private static Logger logger = Logger.getLogger(AIMClientLogin.class);
    private static String URL_START_OSCAR_SESSION = "http://api.oscar.aol.com/aim/startOSCARSession";
    private static String URL_AUTH_CLIENT_LOGIN = "https://api.screenname.aol.com/auth/clientLogin";

    // login parameters
    private String host;
    private int port;
    private String cookie;

    // user parameters
    private String id;
    private String password;

    public AIMClientLogin(String id, String password) {
        this.id = id;
        this.password = password;
    }

    private String oscarUrlEncode(final String original) {
        String encoded = null;
        try {
            encoded = URLEncoder.encode(original, "UTF-8");
        } catch (UnsupportedEncodingException uee) {
            logger.error(uee.getMessage(), uee);
        }
        return encoded;
    }
    
    public static byte [] hmacSHA256Base64(byte [] key, byte [] data) {
        byte[] finalbytes=null;
        Base64 base64 = new Base64();
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(key,hmac.getAlgorithm()));
            finalbytes = hmac.doFinal(data);

        } catch (NoSuchAlgorithmException e) {
            logger.error(e.getMessage(), e);
        } catch (InvalidKeyException e) {
            logger.error(e.getMessage(), e);
        }
        return base64.encode(finalbytes);
    }

    /**
     * Using clientLogin requires a developer ID. This key is for libpurple.
     * It is the default key for all libpurple-based clients. AOL encourages
     * UIs (especially ones with lots of users) to override this with their
     * own key.  This key is owned by the AIM account "markdoliner"
     *
     * Keys can be managed at http://developer.aim.com/manageKeys.jsp
     */
    public static String DEFAULT_CLIENT_KEY = "ma15d7JTxbmVG-RP";

    private String getDevId() {
        return DEFAULT_CLIENT_KEY;
    }

    private String generateSignature(String method, String url, String queryString, byte [] sessionKey) {
        String encodedUrl = oscarUrlEncode(url);
        String encodedParameters = oscarUrlEncode(queryString);
        String signatureBaseString = String.format("%s&%s&%s", method, encodedUrl, encodedParameters);
        String signature = new String(hmacSHA256Base64(sessionKey, signatureBaseString.getBytes()));
        logger.debug("got signature value of " + signature);
        return signature;
    }

    private InputStream startOSCARSession(String token, byte [] sessionkey, String hostTime) {
        InputStream inputStream = null;

        String encodedToken = oscarUrlEncode(token);
        String queryString = String.format("a=%s&f=xml&k=%s&ts=%s&useTLS=0", encodedToken, getDevId(), hostTime);
        logger.debug("query string set to " + queryString);
        String signature = generateSignature("GET", URL_START_OSCAR_SESSION, queryString, sessionkey);

        MultivaluedMap<String, String> queryParams = new MultivaluedMapImpl();
        queryParams.add("a", encodedToken);
        queryParams.add("f", "xml");
        queryParams.add("k", getDevId());
        queryParams.add("ts", hostTime);
        queryParams.add("useTLS", "0");
        queryParams.add("sig_sha256", signature);
        WebResource webResource = client.resource(URL_START_OSCAR_SESSION);
        ClientResponse clientResponse = webResource.queryParams(queryParams).get(ClientResponse.class);
        logger.debug("client response returns : " + clientResponse.getStatus());
        if (clientResponse.hasEntity()) {
            logger.debug("has entity");
            inputStream = clientResponse.getEntityInputStream();
        }
        return inputStream;
    }
        
    private InputStream clientLogin() {
        InputStream inputStream = null;

        MultivaluedMap<String, String> formData = new MultivaluedMapImpl();
        formData.add("devId", getDevId());
        formData.add("f", "xml");
        formData.add("s", oscarUrlEncode(id));
        formData.add("pwd", oscarUrlEncode(password));
        WebResource webResource = client.resource(URL_AUTH_CLIENT_LOGIN);
        ClientResponse clientResponse = webResource.type("application/x-www-form-urlencoded").post(ClientResponse.class, formData);
        logger.debug("client response returns : " + clientResponse.getStatus());
        if (clientResponse.hasEntity()) {
            logger.debug("has entity");
            inputStream = clientResponse.getEntityInputStream();
        }
        return inputStream;
    }

    private void debugOutDocument(Document document) throws Exception {
        // Set up the output transformer
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");

        // Print the DOM node
        StringWriter stringWriter = new StringWriter();
        StreamResult streamResult = new StreamResult(stringWriter);
        DOMSource domSource = new DOMSource(document);
        transformer.transform(domSource, streamResult);
        String xmlString = stringWriter.toString();
        logger.debug("\n" + xmlString);
    }

    public String getPassword() {
        return password;
    }

    public String getId() {
        return id;
    }

    public String getHost() {
        return this.host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public int getPort() {
        return this.port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getCookie() {
        return this.cookie;
    }

    public void setCookie(String cookie) {
        this.cookie = cookie;
    }

    /**
       <?xml version="1.0" encoding="UTF-8" standalone="no"?>
       <response xmlns="https://api.login.aol.com">
         <statusCode>200</statusCode>
         <statusText>OK</statusText>
         <data>
           <token>
             <expiresIn>1209600</expiresIn>
             <a>%2FwQAAAAAAAA%2BrpUZ4KXhjVysxCPm3UlKt81S2gchw0bSK%2BHROw4vxVa1RB1MSN8fHvnJsyZGAgiS9OcMRYtOct8OEWzmR9I0VJiE6zoZZaRSmWlPj8%2F6zuSiJbFMFSyRzndJpVFVefEUynwEiWUT6VJwT0%2BnClMd6lpNMIEItQ8gt3bowK8Ggt6dmWM%3D</a>
           </token>
           <sessionSecret>3m8sKw4puJVVE5Nb</sessionSecret>
           <hostTime>1311369996</hostTime>
           <loginId>********</loginId>
           <luid>FBA5AFB9-E951-DAC1-E7FB-26052F0B02D2</luid>
         </data>
       </response>

       <?xml version="1.0" encoding="UTF-8" standalone="no"?>
       <response xmlns="http://developer.aim.com/xsd/aim.xsd">
         <statusCode>200</statusCode>
         <statusText>Ok</statusText>
         <data>
           <ts>1311690729</ts>
           <host>64.12.24.44</host>
           <port>443</port>
           <cookie>ip1C2ujkZ8prutdZXGM4izwYVb8MemGlCNfsLvi22P2BaxKN4BXz9+4pU1zmnJXKvW6IMZSioTHLdmmdCGdiz8WKeAjAzrEK79nzh9HXJWZp8uWNkejhGjD0cHdqRTUu2e9s3m0v2f2kY2Uc1roF73rXwX0Mes/CkgXlB0jNG4gIZPLmvDK5l9AL6lYAJgwyEknRo1ff4H6qHVmby8u97NFioqKejFGvtB/ljc1jD5o7EvaOGZ5f/asnF4pEtb/ZKMpr7lUqI+ubqg6vmrkqiJC1ENO0b+rlOEDO96CNAzIG2P8oO70Hp0/NK9b0cKtA4TqhLWFvbLMDeyBmG8Nvyw==</cookie>
           <upgradeData/>
           <betaData/>
         </data>
       </response>
    */

    public void getLoginCredentials() throws Exception {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true); // never forget this!
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        Document document = documentBuilder.parse(clientLogin());

        if (logger.isDebugEnabled()) 
            debugOutDocument(document);

        XPathFactory factory = XPathFactory.newInstance();
        XPath xpath = factory.newXPath();
        xpath.setNamespaceContext(new NamespaceContext() {
                public String getNamespaceURI(String prefix) {
                    String uri = null;
                    if (prefix.equals("aol"))
                        uri = "https://api.login.aol.com";
                    return uri;
                }
               
                // Dummy implementation - not used!
                public Iterator getPrefixes(String val) {
                    return null;
                }
               
                // Dummy implemenation - not used!
                public String getPrefix(String uri) {
                    return null;
                }
            });

        //XPathExpression expr = xpath.compile();
        String statusText = (String)xpath.evaluate("/aol:response/aol:statusText", document, XPathConstants.STRING);
        String token = URLDecoder.decode((String)xpath.evaluate("/aol:response/aol:data/aol:token/aol:a", document, XPathConstants.STRING), "UTF-8");
        String sessionSecret = (String)xpath.evaluate("/aol:response/aol:data/aol:sessionSecret", document, XPathConstants.STRING);
        String hostTime = (String)xpath.evaluate("/aol:response/aol:data/aol:hostTime", document, XPathConstants.STRING);
        logger.debug("statusText : " + statusText);
        logger.debug("token : " + token);
        logger.debug("sessionSecret : " + sessionSecret);
        logger.debug("hostTime : " + hostTime);
            
        byte [] sessionKey = hmacSHA256Base64(oscarUrlEncode(getPassword()).getBytes(), sessionSecret.getBytes());
        document = documentBuilder.parse(startOSCARSession(token, sessionKey, hostTime));

        if (logger.isDebugEnabled()) 
            debugOutDocument(document);

        xpath.setNamespaceContext(new NamespaceContext() {
                public String getNamespaceURI(String prefix) {
                    String uri = null;
                    if (prefix.equals("aim"))
                        uri = "http://developer.aim.com/xsd/aim.xsd";
                    return uri;
                }
               
                // Dummy implementation - not used!
                public Iterator getPrefixes(String val) {
                    return null;
                }
               
                // Dummy implemenation - not used!
                public String getPrefix(String uri) {
                    return null;
                }
            });

        String statusCode = (String)xpath.evaluate("/aim:response/aim:statusCode", document, XPathConstants.STRING);
        setHost((String)xpath.evaluate("/aim:response/aim:data/aim:host", document, XPathConstants.STRING));
        String portString = (String)xpath.evaluate("/aim:response/aim:data/aim:port", document, XPathConstants.STRING);
        setPort(Integer.parseInt(portString));
        setCookie((String)xpath.evaluate("/aim:response/aim:data/aim:cookie", document, XPathConstants.STRING));
        logger.debug("statusCode : " + statusCode);
        logger.debug("host : " + getHost());
        logger.debug("port : " + getPort());
        logger.debug("cookie : " + getCookie());
    }

    public static void main(String [] args) {
        AIMClientLogin aimClientLogin = new AIMClientLogin(args[0], args[1]);
        try {
            aimClientLogin.getLoginCredentials();
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
    }
}
