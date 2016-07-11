package com.joseprio.httpserver;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.*;
import java.io.UnsupportedEncodingException;

import com.sun.net.httpserver.Authenticator;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpPrincipal;

/**
 * DigestAuthenticator provides an implementation of HTTP Digest
 * authentication. It is an abstract class and must be extended
 * to provide an implementation of {@link #checkCredentials(String,String)}
 * which is called to verify each incoming request.
 */
public abstract class DigestAuthenticator extends Authenticator {
	final private int STATUS_UNAUTHORIZED = 401;
	
	// In-code configuration
	
	// Prevent insecure legacy digest auth calls
	private boolean disallowLegacyAuth = true;
	
	// Amount of hashes to store in order to prevent replay attacks
	private int maxPreviousHashes = 2000;
	
	// Encoding to use for converting strings
	private String transportCharacterEncoding = "ISO-8859-1";
	
	// Maximum life for a nonce in millis
	private long maxNonceLifeMillis = 5 * 60 * 1000; // 5 minutes
	
	// END In-code configuration

    protected String realm;
    
    private Set<String> previousHashes = new HashSet<String>();
    private Deque<String> previousHashesStack = new ArrayDeque<String>();

    /**
     * Creates a DigestAuthenticator for the given HTTP realm
     * @param realm The HTTP Digest authentication realm
     * @throws NullPointerException if the realm is an empty string
     */
    public DigestAuthenticator (String realm) {
    	if (realm == null || realm.length() < 1) {
    		throw new NullPointerException();
    	}
    	
        this.realm = realm;
    }

    /**
     * returns the realm this DigestAuthenticator was created with
     * @return the authenticator's realm string.
     */
    public String getRealm () {
        return realm;
    }
    
    public Result authenticate (HttpExchange t)
    {
        Headers rmap = (Headers) t.getRequestHeaders();
        
        // Check if the authorization header is present
        String auth = rmap.getFirst ("Authorization");
        if (auth == null) {
            Headers map = (Headers) t.getResponseHeaders();
            map.set ("WWW-Authenticate", getAuthenticateHeader());
            return new Retry(STATUS_UNAUTHORIZED);
        }
        
        // Make sure we're getting a digest authentication request
        int sp = auth.indexOf (' ');
        if (sp == -1 || !auth.substring(0, sp).equals ("Digest")) {
            return new Failure(STATUS_UNAUTHORIZED);
        }
        
        String method = t.getRequestMethod();
        
        Map<String,String> authParams = parseHeader(auth);
        String targetUser = authParams.get("username");
        
        String ha1 = gethAuthToken(targetUser);
        
        String qop = authParams.get("qop");

        String reqURI = authParams.get("uri");
        String ha2 = calculateMD5(method + ":" + reqURI);
        String nonce = authParams.get("nonce");

        String clientResponse = authParams.get("response");
        
        // Make sure we haven't processed the same hash before
        if (isDuplicatedHash(clientResponse) || !validateNonce(nonce)) {
            Headers map = (Headers) t.getResponseHeaders();
            map.set ("WWW-Authenticate", getAuthenticateHeader());
            return new Retry(STATUS_UNAUTHORIZED);
        }
        
        // Mark this hash as processed
        addPreviousHash(clientResponse);

        String serverResponse;

        if (qop == null || qop.length() < 1) {
        	if (disallowLegacyAuth) {
                return new Failure(STATUS_UNAUTHORIZED);
        	}
        	
            serverResponse = calculateMD5(ha1 + ":" + nonce + ":" + ha2);

        } else {
            String nonceCount = authParams.get("nc");
            String clientNonce = authParams.get("cnonce");

            serverResponse = calculateMD5(ha1 + ":" + nonce + ":"
                    + nonceCount + ":" + clientNonce + ":" + qop + ":" + ha2);

        }

        if (serverResponse.equals(clientResponse)) {
            return new Success (
                new HttpPrincipal (
                		targetUser, realm
                )
            );
        } else {
            // reject the request again with status unauthorized
            Headers map = (Headers) t.getResponseHeaders();
            map.set ("WWW-Authenticate", getAuthenticateHeader());
            return new Failure(STATUS_UNAUTHORIZED);
        }
    }
    
    private boolean isDuplicatedHash(String hash) {
    	return previousHashes.contains(hash);
    }
    
    private void addPreviousHash(String hash) {
    	previousHashes.add(hash);
    	
    	// Make sure we don't pass the limit
    	while (previousHashesStack.size() > maxPreviousHashes) {
    		String lastElement = previousHashesStack.pop();
    		previousHashes.remove(lastElement);
    	}
    }
    
    private boolean validateNonce(String nonce) {
    	String[] parts = nonce.split(":");
    	// Must have 2 parts
    	if (parts.length != 2) {
    		return false;
    	}
    	try {
    		long timestamp = Long.parseLong(parts[0]);
    		long current = System.currentTimeMillis();
    		
    		// Check if expired
    		if ((current - timestamp) > maxNonceLifeMillis) {
    			return false;
    		}
    	} catch (NumberFormatException nfex) {
    		// First part is not a number, return false
    		return false;
    	}
    	
		// Everything seems ok!
		return true;
    }
    

    /**
     * Gets the Authorization header string minus the "AuthType" and returns a
     * hashMap of keys and values
     *
     * @param headerString
     * @return
     */
    private Map<String, String> parseHeader(String headerString) {
        // Separate out the part of the string which tells you which Auth scheme is it
        String headerStringWithoutScheme = headerString.substring(headerString.indexOf(" ") + 1).trim();
        HashMap<String, String> values = new HashMap<String, String>();
        String keyValueArray[] = headerStringWithoutScheme.split(",");
        for (String keyval : keyValueArray) {
            if (keyval.contains("=")) {
                String key = keyval.substring(0, keyval.indexOf("="));
                String value = keyval.substring(keyval.indexOf("=") + 1);
                values.put(key.trim(), value.replaceAll("\"", "").trim());
            }
        }
        return values;
	}
    
    /**
     * Calculate the nonce based on current time-stamp upto the second, and a
     * random seed
     *
     * @return
     */
    public String calculateNonce() {
    	long currentTime = System.currentTimeMillis();
        Random rand = new Random(100000);
        Integer randomInt = rand.nextInt();
        return "" + currentTime + ":" + calculateMD5(randomInt.toString());
    }
    
    private String getOpaque(String domain, String nonce) {
        return calculateMD5(domain + nonce);
    }
  
    private String getAuthenticateHeader() {
        String header = "";
        String nonce = calculateNonce();

        header = 
        		"Digest realm=\"" + realm + "\","
        		+ "qop=auth,"
        		+ "nonce=\"" + nonce + "\","
        		+ "opaque=\"" + getOpaque(realm, nonce) + "\"";

        return header;
    }
    
    private String calculateMD5(String target) {
    		try {
				return calculateMD5(target.getBytes(transportCharacterEncoding));
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
    		return null;
    }
    
    private String calculateMD5(byte[] originalArray) {
	   try {
	        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
	        byte[] array = md.digest(originalArray);
	        StringBuffer sb = new StringBuffer();
	        for (int i = 0; i < array.length; ++i) {
	          sb.append(Integer.toHexString((array[i] & 0xFF) | 0x100).substring(1,3));
	       }
	        return sb.toString();
	    } catch (java.security.NoSuchAlgorithmException e) {
	    	// We should never be here
	    	e.printStackTrace();
	    }
	    return null;
	}
    
    public String calculateAuthToken(String username, String password) {
    	String token = username + ":" + realm + ":" + password;
    	return calculateMD5(token);
    }
    
    /**
     * called for each incoming request to obtain the expected authorization
     * token for the user. Extending classes should implement this method.
     * The token is the MD5 hash resulting form a string concatenating
     * username, realm and password, using colons as separators.
     * A helper function is included for calculating the authorization tokens: 
     * {@link #calculateAuthToken(String,String)}
     * @param username the username
     * @return the auth token.
     */
    public abstract String gethAuthToken(String username);
}

class AuthenticationException extends Exception {
	private static final long serialVersionUID = 1L;
}
