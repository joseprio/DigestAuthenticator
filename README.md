## DigestAuthenticator
Since Java 6, the JRE ships with a simple built-in HTTP/S server. This
implementation includes support for authentication mechanisms, and also
includes HTTP Basic auth.

This projects implements the more secure Digest auth; that said, it is 
by no means a proper replacement for HTTPS, but may be useful for
scenarios where HTTPS is not a possibility.

## Usage
Extend the `com.joseprio.httpserver.DigestAuthenticator` class and
implement the `gethAuthToken(String user)` method; this method should
return the HA1 string for the specified `user`. The HA1 string is
the result of applying MD5 to a string composed by
`<<user>>:<<realm>>:<<password>>`. A helper method 
`calculateAuthToken(String user, String password)` is provided in
order to calculate the HA1 string if you've access to the password
in plaintext.

## Example
A simple implementation is included in the 
`com.joseprio.example.DigestHttpServer` class; it may be run from
the command line or from your favorite IDE.
