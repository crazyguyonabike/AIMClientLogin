This code exemplifies the protocol described at:

http://dev.aol.com/authentication_for_clients#clientLogin

For getting host, port and cookie for authentication to AIM services. 

To build, run:

mvn clean package
  which should create a one-jar jar file

To run with AIM credentials run:

java -jar target/aim-login-1.0.one-jar.jar <username> <password>
