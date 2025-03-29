pragma Profile (Ravenscar);

with Net.Buffers;
with Net.Interfaces;

generic
   Ifnet                 : in out Net.Interfaces.Ifnet_Type'Class;

   Max_Sockets_Count     : Positive;
   --  Maximum sockets that will be created

   Priority              : System.Priority := System.Default_Priority;
   --  Priority for the protected objects and read watchdog

package Net.Sockets.Tcp is

   type Socket_State_Kind is
     (Closed,
      Syn_Sent,
      --  A SYN has been sent, and TCP is awaiting the response SYN.
      Syn_Received,
      --  A SYN has been received, a SYN has been sent, and TCP is
      --  awaiting an ACK.
      Established,
      --  The three-way handshake has been completed.
      Fin_Wait_1,
      --  The local application initiated closing. TCP has sent a FIN,
      --  and is awaiting an ACK or a FIN.
      Fin_Wait_2,
      --  A FIN has been sent, and an ACK received. TCP is awaiting a
      --  FIN from the remote TCP layer.
      Close_Wait,
      --  TCP has received a FIN, and has sent an ACK. It is awaiting a
      --  close request from the local application before sending a FIN.
      Closing,
      --  A FIN has been sent, a FIN has been received, and an ACK has
      --  been sent. TCP is awaiting an ACK for the FIN that was sent.
      Last_Ack,
      --  A FIN has been received, and an ACK and a FIN have been sent.
      --  TCP is awaiting an ACK.
      Time_Wait
      --  Waiting for input from the other side. Will be closed after timeout
     );

   type Socket is limited private;
   type Socket_Access is access all Socket;

   type Tcp_Event_Kind is
     (Tcp_Event_State,  --  State changed
      Tcp_Event_Sent,   --  Data sent
      Tcp_Event_Recv,   --  Data received
      Tcp_Event_Abort); --  Operation aborted

   type Tcp_Event (Kind : Tcp_Event_Kind) is record
      case Kind is
         when Tcp_Event_State =>
            State : Socket_State_Kind;
         when others =>
            null;
      end case;
   end record;

   type Callback_Procedure is access procedure
     (This  : Socket_Access;
      Event : Tcp_Event);
   --  Called when some event occurred from the Socket's protected object, so
   --  it is not allowed to call any Socket's methods inside the callback.

   function Get_State (This : Socket) return Socket_State_Kind;

   procedure Set_Callback
     (This     : in out Socket;
      Callback : Callback_Procedure);

   procedure Bind
     (This   : in out Socket;
      Port   : Uint16;
      Status : out Error_Code)
     with Pre => (Get_State (This) = Closed);

   function Is_Binded (This : Socket) return Boolean;

   procedure Connect
     (This   : in out Socket;
      Addr   : Ip_Addr;
      Port   : Uint16;
      Status : out Error_Code)
     with Pre => (Get_State (This) = Closed and then Is_Binded (This));
   --  Setup connection to the remote Addr/Port and send the initial SYN
   --  segment. Calls Cb when the connection is established or rejected,
   --  as indicated by Ok callback's parameter.

   procedure Send
     (This   : in out Socket;
      Data   : Net.Buffers.Buffer_Type; --  Raw data
      Push   : Boolean;
      Status : out Error_Code)
     with Pre =>
       (Get_State (This) in Syn_Sent .. Established
        or else Get_State (This) = Close_Wait);
   --  Sends data. Set TCP header's Push flag if Push = True

   function Get_Send_Room (This : Socket) return Uint16
     with Pre => (Get_State (This) /= Closed);
   --  Returns how many data can be send

   procedure Receive
     (This     : in out Socket;
      Data     : in out Net.Buffers.Buffer_Type; --  Raw data
      Has_More : out Boolean)
     with Pre => (Get_State (This) /= Closed) and Data.Is_Null;
   --  Returns received raw data that Sockets holds. Data should be null.
   --  Returns null Data when no data received. Has_More = True when the Socket
   --  has more data received. Data should be released after by caller.

   function Get_Receive_Room (This : Socket) return Uint16
     with Pre => (Get_State (This) /= Closed);
   --  Returns how many data can be received

   procedure Close
     (This   : in out Socket;
      Status : out Error_Code)
     with Pre => (Get_State (This) /= Closed);
   --  Closes the connection

   procedure Drop
     (This   : in out Socket;
      Status : out Error_Code)
     with Pre => (Get_State (This) /= Closed);
   --  Sends RESET and drop the connestion

   procedure Check_Timeouts;
   --  Procedures that should be called in 500 microseconds interval to
   --  processs TTLs.

   procedure Received
     (Ifnet  : in out Net.Interfaces.Ifnet_Type'Class;
      Packet : in out Net.Buffers.Buffer_Type);
   --  Recived handler, called internaly

private

   ------------
   -- Socket --
   ------------

   type Socket is limited record
      Self     : Socket_Access := Socket'Unchecked_Access;
      State_No : Natural  := 0;
      Callback : Callback_Procedure := null;
   end record;

   procedure Received
     (This      : Socket_Access;
      Packet    : in out Net.Buffers.Buffer_Type;
      Length    : Uint16;
      Processed : out Boolean);
   --  Process received data. Processed = True if data has been processed

   procedure Check_Timeouts (This : Socket_Access);
   --  Proces TTLs.

   procedure Check_Time_Wait (This : Socket_Access);
   --  Check that we pass timeout

   procedure Send_Rst_Flag
     (Src_IP   : Ip_Addr;
      Src_Port : Uint16;
      Dst_IP   : Ip_Addr;
      Dst_Port : Uint16;
      Ack      : Boolean;
      Seq_Num  : Uint32;
      Ack_Num  : Uint32;
      Status   : out Error_Code);

end Net.Sockets.Tcp;
