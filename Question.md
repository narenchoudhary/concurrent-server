# Application 2

Client-Server programming using both TCP and UDP sockets

In this assignment, you require to implement two C programs, namely server and client to communicate with each other based on both TCP and UDP sockets. The aim is to implement a simple 2 stage communication protocol.  


Initially, server will be waiting for a TCP connection from the client. Then, client will connect to the server using server’s TCP port already known to the client. After successful connection, the client sends a Request Message (Type 1 message) to the server via TCP port to request a UDP port from server for future communication. After receiving the Request Message, server selects a UDP port number and sends this port number back to the client as a Response Message (Type 2 Message) over the TCP connection.After this negotiation phase, the TCP connection on both the server and client should be closed gracefully releasing the socket resource.


In the second phase, the client transmits a short Data Message (Type 3 message) over the earlier negotiated UDP port. The server will display the received Data Message and sends a Data Response (type 4 message) to indicate the successful reception. After this data transfer phase, both sides close their UDP sockets.

The messages used to communicate contain the following fields:  

        | Message_Type  | Message_Length| Message|
        |:-------------:|:-------------:|:------:|


1. Message_type : integer
2. Message_length : integer
3. Message : Character [MSG_LEN], where MSG_LEN is an integer constant

`<Data Message>` in **Client** will be a **Type 3** message with some content in its message section.

You also require implementing a **"Concurrent Server"**, i.e., a server that accepts connections from multiple clients and serves all of them concurrently.

You should accept the IP Address and Port number from the command line (Don't use a hard-coded port number). Prototype for command line is as follows:

**Prototypes for Client and Server**  
**Client**: `<executable code> <Server IP Address> <Server Port number>`  
**Server**: `<executable code> <Server Port number>`  


*Please make necessary and valid assumptions whenever required.