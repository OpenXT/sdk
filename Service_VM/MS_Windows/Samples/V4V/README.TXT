== Samples ==
v4vapp:
This is a sample that uses V4V in user mode in a variety of ways. It supports
using datagrams and streams in both blocking and non-blocking modes. This 
project is built with a Windows 6 or 7 WDK.

vs8cpp:
This is a Visual Studio 8 C++ client/server sample using datagrams.

== Sample Config Files ==
These are the values used in the v4vapp sample.

Section: V4V_Base

Role=None|Sender|Receiver|Connector|Listener
Protocol=Datagram|Stream
Async=False|True
ConnectOnly=False|True
PeerId=DOMID#|NONE
LocalPort=PORT#|NONE
RemotePort=PORT#|NONE
RingSize=<n>

Section: V4V_Data

Transfer=Internal|File
TransferFile=<path>
TransferTimeout=<ms>
TransmitSize=<n>
ReceiveSize=<n>
