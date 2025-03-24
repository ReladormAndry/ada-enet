
with Net.Utils;
with Net.Buffers; use Net.Buffers;
with Net.Headers; use Net.Headers;

with Net.Protos.Dispatchers;
with Net.Protos.IPv4;
with Net.Protos.Arp;

package body Net.Sockets.Tcp is

   Local_TCP_Window        : constant := 65495;
   TCP_Window              : constant := 2048;
   TCP_MAX_SYN_RTX         : constant := 6;
   --  Maximum retransmits for initial (SYN) segments
   TCP_MAX_RTX             : constant := 12;
   --  Maximum retransmits for data segments
   TCP_TTL                 : constant := 64;

   One_Second              : constant Ada.Real_Time.Time_Span :=
     Ada.Real_Time.Seconds (1);
   One_And_Half_Second     : constant Ada.Real_Time.Time_Span :=
     Ada.Real_Time.Microseconds (1500);

   TCP_Ticks               : Uint32   := 0;
   Fin_Wait_Timeout        : Uint32 := 0; -- 20 s
   Syn_Received_Timeout    : Uint32 := 0; -- 20 s
   Time_Wait_Timeout       : Uint32 := 0;

   Initial_Persist_Backoff : Int16 := 0;  -- 1.5 s
   Max_Persist_Backoff     : Int16 := 0;  -- 60 s

   package body Watchdog is separate;

   function TCP_Payload_Length
     (Packet : Net.Buffers.Buffer_Type)
      return Uint16;

   procedure To_Host (TCP : Net.Headers.TCP_Header_Access);
   --  Converts to host bytes order

   procedure To_Network (TCP : Net.Headers.TCP_Header_Access);
   --  Converts to network bytes order

   function Max_Packet_Size return Uint16;

   -----------
   -- State --
   -----------

   protected type State_Protected_Object is

      function Get_State return Socket_State_Type;
      function Is_Binded return Boolean;

      procedure Bind
        (This   : Socket_Access;
         Port   : Uint16;
         Status : out Status_Kind);

      procedure Connect
        (Addr   : Ip_Addr;
         Port   : Uint16;
         Status : out Status_Kind);

      procedure Send
        (Data   : Net.Buffers.Buffer_Type; --  Raw data
         Push   : Boolean;
         Status : out Status_Kind);

      function Get_Send_Room return Uint16;

      procedure Receive
        (Data     : in out Net.Buffers.Buffer_Type; --  Raw data
         Has_More : out Boolean);

      function Get_Receive_Room return Uint16;

      procedure Close (Status : out Status_Kind);

      procedure Drop (Status : out Status_Kind);

      procedure Received
        (Packet    : Net.Buffers.Buffer_Type;
         Length    : Uint16;
         Processed : out Boolean);

      procedure Check_Timeouts;
      procedure Check_Time_Wait;

   private
      Socket                  : Socket_Access := null;

      State                   : Socket_State_Type := Closed;

      Local_Addr              : Ip_Addr := (0, 0, 0, 0);
      Local_Port              : Uint16  := 0;

      Remote_Addr             : Ip_Addr := (0, 0, 0, 0);
      Remote_Port             : Uint16  := 0;

      Local_MSS               : Uint16; --  Maximum segment size for receiving
      Remote_MSS              : Uint16; --  Maximum segment size for sending

      Init_Sequence_Num       : Uint32;        -- ISS
      Next_Sequence_Num       : Uint32;        -- NSS

      --  Send
      Send_Window             : Uint16;        -- SND_WND
      Ssthresh                : Uint32 := 65_535;
      Cwnd                    : Uint32;
      Send_Unacknowledged     : Uint32;        -- SND_UNA
      Send_Next               : Uint32;        -- SND_NXT
      Sequence_Last_Update    : Uint32 := 0;   -- SND_WL1
      Ask_Last_Update         : Uint32 := 0;   -- SND_WL2

      --  Recive
      Init_Recive_Num         : Uint32 := 0; --  Initial receive sequence number IRS
      Recive_Window           : Uint16 := 0;   --  RCV_WND
      Recive_Next             : Uint32 := 0;   --  RCV_NXT

      Send_Queue              : Net.Buffers.Buffer_List;
      Unack_Queue             : Net.Buffers.Buffer_List;
      Recive_Queue            : Net.Buffers.Buffer_List;

      Retransmitting_Sequence : Uint32 := 0; --  RTT_Seq
      Retransmitting_Ticks    : Uint32 := 0; --  RTT_Ticks

      RTT_Average             : Uint16 := 0;
      RTT_Stddev              : Uint16 := 0;
      RTO                     : Uint16 := 0;

      Retransmit_Ticks        : Int16  := 0;
      Retransmit_Count        : Uint8  := 0;

      Watchdog_Ticks          : Uint32 := 0;
      --  TCP ticks for watchdog timer (used for idle/keepalive, and
      --  2MSL TIME_WAIT).

      Persist_Ticks           : Int16  := 0;
      Persist_Backoff         : Int16  := 0;
      --  TCP ticks value for persist timer (-1 if not running, ticks count
      --  since last reset if running, and current backoff count (0 if not
      --  running).

      procedure Init;
      procedure Set_State (New_State : Socket_State_Type);

      procedure Send_Control
        (Syn    : Boolean;
         Fin    : Boolean;
         Status : out Status_Kind);
      --  Send a TCP segment with no payload, just control bits set according
      --  to Syn and Fin. Ack will be set as well unless in Syn_Sent state.

      procedure Enqueue
        (Data   : Net.Buffers.Buffer_Type;
         Push   : Boolean;
         Syn    : Boolean;
         Fin    : Boolean;
         Status : out Status_Kind);
      --  Request push onto the Send_Queue for later output by TCP_Output.
      --  Data designates a buffer to be used as payload data or TCP
      --  options, according to Options, with segments cut to be MSS bytes max
      --  each.

      procedure Process_Send_Queue (Ack_Now : Boolean);
      --  Starts output from send queue. Check whether ACK have sent if
      --  Ack_Now = True.

      procedure Send_Packet
        (Packet : in out Buffer_Type;
         Status : out Error_Code);
      --  Send the segment over IP

      procedure Process_Ack (Packet : Net.Buffers.Buffer_Type);
      --  Process received ack in the packet

      procedure Send_Window_Probe;

      procedure Retransmit_Timeout;

   end State_Protected_Object;

   ------------
   -- Reestr --
   ------------

   type Sockets_List_Kind is (No_List, Active, Time_Wait);
   type Sockets_Array is array (1 .. Max_Sockets_Count) of Socket_Access;

   type Sockets_List_Type is record
      List : Sockets_Array;
      Last : Natural := 0;
   end record;
   type Sockets_List_Access is access all Sockets_List_Type;

   -- Reestr --

   protected Reestr
     with Priority => System.Default_Priority
   is

      procedure Add    (To   : Sockets_List_Kind; Socket : Socket_Access);
      procedure Delete (From : Sockets_List_Kind; Socket : Socket_Access);

      procedure Get_List_Copy (Kind : Sockets_List_Kind);
      --  Copy selected list to Processing_Sockets global variable

   private
      Reestr_Active    : aliased Sockets_List_Type;
      Reestr_Time_Wait : aliased Sockets_List_Type;

      Current          : Sockets_List_Access := null;

      procedure Find_Array (Kind : Sockets_List_Kind);
   end Reestr;

   States               : array (1 .. Max_Sockets_Count) of
     State_Protected_Object;
   --  Protected objects that handle Sockets

   Processing_Sockets   : Sockets_List_Type;
   --  Temporary storage for sockets that should be checked by "Tiks"
   --  procedures. To not have dynamic allocation.

   ------------
   -- Reestr --
   ------------

   protected body Reestr is

      ---------------
      -- Get_Array --
      ---------------

      procedure Find_Array (Kind : Sockets_List_Kind) is
      begin
         case Kind is
            when No_List   => Current := null;
            when Active    => Current := Reestr_Active'Access;
            when Time_Wait => Current := Reestr_Time_Wait'Access;
         end case;
      end Find_Array;

      ---------
      -- Add --
      ---------

      procedure Add
        (To     : Sockets_List_Kind;
         Socket : Socket_Access) is
      begin
         Find_Array (To);

         if Current = null then
            return;
         end if;

         Current.Last := Current.Last + 1;
         Current.List (Current.Last) := Socket;
      end Add;

      ------------
      -- Delete --
      ------------

      procedure Delete
        (From   : Sockets_List_Kind;
         Socket : Socket_Access) is
      begin
         Find_Array (From);

         if Current = null then
            return;
         end if;

         for Index in 1 .. Current.Last loop
            if Current.List (Index) = Socket then
               Current.List (Index .. Current.Last - 1) :=
                 Current.List (Index + 1 .. Current.Last);
               Current.Last := Current.Last - 1;
               return;
            end if;
         end loop;
      end Delete;

      -------------------
      -- Get_List_Copy --
      -------------------

      procedure Get_List_Copy (Kind : Sockets_List_Kind) is
      begin
         Find_Array (Kind);

         if Current = null then
            Processing_Sockets.Last := 0;
         else
            Processing_Sockets.Last := Current.Last;
            if Current.Last > 0 then
               Processing_Sockets.List (1 .. Current.Last) :=
                 Current.List (1 .. Current.Last);
            end if;
         end if;
      end Get_List_Copy;

   end Reestr;

   State_To_List : constant array (Socket_State_Type) of
     Sockets_List_Kind :=
       (Closed         => No_List,
        Syn_Sent     |
        Syn_Received |
        Established  |
        Fin_Wait_1   |
        Fin_Wait_2   |
        Close_Wait   |
        Closing      |
        Last_Ack     => Active,
        Time_Wait    => Time_Wait
       );

   ----------------------------
   -- State_Protected_Object --
   ----------------------------

   protected body State_Protected_Object is

      ----------
      -- Init --
      ----------

      procedure Init is
      begin
         --  Set default values
         if Socket /= null then
            Socket.State_No := 0;
            Socket          := null;
         end if;

         Local_Addr              := (0, 0, 0, 0);
         Local_Port              := 0;
         Local_MSS               := 536;
         Remote_MSS              := 536;
         State                   := Closed;
         Remote_Addr             := (0, 0, 0, 0);
         Remote_Port             := 0;
         Init_Sequence_Num       := 0;
         Init_Recive_Num         := 0;
         Send_Window             := 0;
         Ssthresh                := 65_535;
         Cwnd                    := 0;
         Send_Unacknowledged     := 0;
         Send_Next               := 0;
         Sequence_Last_Update    := 0;
         Ask_Last_Update         := 0;
         Recive_Window           := 0;
         Next_Sequence_Num       := 0;
         Recive_Next             := 0;
         Retransmitting_Sequence := 0;
         Retransmitting_Ticks    := 0;
         RTT_Average             := 0;
         RTT_Stddev              := 0;
         RTO                     := 0;
         Retransmit_Ticks        := 0;
         Retransmit_Count        := 0;
         Watchdog_Ticks          := 0;
         Persist_Ticks           := 0;
         Persist_Backoff         := 0;

         Release (Send_Queue);
         Release (Unack_Queue);
         Release (Recive_Queue);
      end Init;

      ---------------
      -- Get_State --
      ---------------

      function Get_State return Socket_State_Type is
      begin
         return State;
      end Get_State;

      ---------------
      -- Is_Binded --
      ---------------

      function Is_Binded return Boolean is
      begin
         return Local_Port /= 0;
      end Is_Binded;

      ----------
      -- Bind --
      ----------

      procedure Bind
        (This   : Socket_Access;
         Port   : Uint16;
         Status : out Status_Kind) is
      begin
         if Socket = null
           or else Socket = This
         then
            Status := Ok;
            Init;
            Socket     := This;
            Local_Addr := Ifnet.Ip;
            Local_Port := Port;
         else
            Status := Error;
         end if;
      end Bind;

      -------------
      -- Connect --
      -------------

      procedure Connect
        (Addr   : Ip_Addr;
         Port   : Uint16;
         Status : out Status_Kind) is
      begin
         Remote_Addr         := Addr;
         Remote_Port         := Port;

         Init_Sequence_Num   := Net.Utils.Random;
         Next_Sequence_Num   := Init_Sequence_Num;

         Send_Unacknowledged := Init_Sequence_Num - 1;
         Send_Next           := Init_Sequence_Num;

         Recive_Window       := Uint16'Min
           (Local_TCP_Window,
            Uint16
              (Net.Buffers.Packets_Count / 2 / Uint32 (Max_Sockets_Count)) *
                Max_Packet_Size);
         Send_Window         := TCP_Window;
         Cwnd                := TCP_Window;

         Set_State (Syn_Sent);

         pragma Assert (Is_Empty (Send_Queue));

         Send_Control (Syn => True, Fin => False, Status => Status);

      exception
         when others =>
            Status := Error;
      end Connect;

      ----------
      -- Send --
      ----------

      procedure Send
        (Data   : Net.Buffers.Buffer_Type;
         Push   : Boolean;
         Status : out Status_Kind) is
      begin
         case State is
            when Established | Close_Wait | Syn_Sent | Syn_Received =>
               Enqueue
                 (Data   => Data,
                  Push   => Push,
                  Syn    => False,
                  Fin    => False,
                  Status => Status);
            when others =>
               Status := Error;
         end case;
      end Send;

      -------------------
      -- Get_Send_Room --
      -------------------

      function Get_Send_Room return Uint16 is
      begin
         return Send_Window;
      end Get_Send_Room;

      -------------
      -- Receive --
      -------------

      procedure Receive
        (Data     : in out Net.Buffers.Buffer_Type; --  Raw data
         Has_More : out Boolean)
      is
      begin
         if Is_Empty (Recive_Queue) then
            Set_Length (Data, 0);
            Has_More := False;
         else
            Peek (Recive_Queue, Data);
            Recive_Window := Recive_Window + Get_Data_Size (Data, RAW_PACKET);
            Has_More := not Is_Empty (Recive_Queue);
         end if;
      end Receive;

      ----------------------
      -- Get_Receive_Room --
      ----------------------

      function Get_Receive_Room return Uint16 is
      begin
         return Recive_Window;
      end Get_Receive_Room;

      -----------
      -- Close --
      -----------

      procedure Close (Status : out Status_Kind) is

         ---------
         -- Fin --
         ---------

         procedure Fin (State : Socket_State_Type);
         procedure Fin (State : Socket_State_Type) is
         begin
            Send_Control (Syn => False, Fin => True, Status => Status);
            if Status = Ok then
               Set_State (State);
               Process_Send_Queue (Ack_Now => False);
            end if;
         end Fin;

      begin
         --  Except when the current PCB state is Closed already, we rely on
         --  Set_State to perform the necessary list operations.

         case State is
            when Closed =>
               null; -- Can't happen

            when Syn_Sent =>
               Set_State (Closed);
               Status := Ok;

            when Syn_Received | Established =>
               --  Transition to FIN_WAIT_1 after sending FIN
               Fin (Fin_Wait_1);

            when Close_Wait =>
               --  Transition to LAST_ACK after sending FIN
               Fin (Last_Ack);

            when others =>
               Status := Ok;
         end case;
      end Close;

      ----------
      -- Drop --
      ----------

      procedure Drop (Status : out Status_Kind) is
      begin
         --  Send RST
         Send_Rst
           (Src_IP   => Local_Addr,
            Src_Port => Local_Port,
            Dst_IP   => Remote_Addr,
            Dst_Port => Remote_Port,
            Ack      => True,
            Seq_Num  => Send_Next,
            Ack_Num  => Recive_Next,
            Status   => Status);

         Set_State (Closed);
      end Drop;

      ---------------
      -- Set_State --
      ---------------

      procedure Set_State (New_State : Socket_State_Type)
      is
         Old_List : Sockets_List_Kind := State_To_List (State);
         New_List : constant Sockets_List_Kind := State_To_List (New_State);
      begin
         pragma Assert (State /= New_State);

         case State is
            when Closed =>
               pragma Assert (New_State = Syn_Sent);
               Old_List := No_List;

            when Syn_Sent =>
               pragma Assert (New_State = Syn_Received
                              or else New_State = Established
                              or else New_State = Closed);
               null;

            when Syn_Received =>
               --  Similarly an incoming RST may abort an half-open passive
               --  connection.
               pragma Assert (New_State = Established
                              or else New_State = Fin_Wait_1
                              or else New_State = Closed);
               null;

            when Established =>
               pragma Assert (New_State = Fin_Wait_1
                              or else New_State = Close_Wait);
               null;

            when Fin_Wait_1 =>
               pragma Assert (New_State = Fin_Wait_2
                              or else New_State = Closing);
               null;

            when Fin_Wait_2 =>
               pragma Assert (New_State = Time_Wait);
               null;

            when Close_Wait =>
               pragma Assert (New_State = Last_Ack);
               null;

            when Closing =>
               pragma Assert (New_State = Time_Wait);
               null;

            when Last_Ack | Time_Wait =>
               pragma Assert (New_State = Closed);
               null;
         end case;

         if Old_List /= New_List then
            if Old_List /= No_List then
               Reestr.Delete (Old_List, Socket);
            end if;

            if New_List /= No_List then
               Reestr.Add (New_List, Socket);
            end if;

            if Socket.Callback_Kind = Tcp_Event_None then
               Socket.Callback_Kind := Tcp_Event_State;
            end if;
         end if;

         State := New_State;
         if State = Closed then
            Init;
         end if;
      end Set_State;

      ------------------
      -- Send_Control --
      ------------------

      procedure Send_Control
        (Syn    : Boolean;
         Fin    : Boolean;
         Status : out Status_Kind)
      is
         Empty : Buffer_Type;
      begin
         Enqueue
           (Data   => Empty,
            Push   => False,
            Syn    => Syn,
            Fin    => Fin,
            Status => Status);
      end Send_Control;

      -------------
      -- Enqueue --
      -------------

      procedure Enqueue
        (Data   : Buffer_Type;
         Push   : Boolean;
         Syn    : Boolean;
         Fin    : Boolean;
         Status : out Status_Kind)

      is
         Num        : Uint32;
         Queue      : Buffer_List;
         Packet     : Buffer_Type;
         Left       : Uint16 := Get_Data_Size (Data, RAW_PACKET);
         Pos        : Uint16 := 0;
         Tcp_Header : Net.Headers.TCP_Header_Access;

      begin
         Status := Error;

         pragma Assert (not (Syn and Fin));
         pragma Assert (not Syn or else not Fin);

         Num := Next_Sequence_Num;

         while Left > 0 or else (Syn or Fin) loop
            --  Split Data to chunks according to Send_Max_Segment_Size

            Allocate (Packet);
            if Is_Null (Packet) then
               --  No more memory
               Release (Queue);
               Release (Packet);

               return;
            end if;

            Set_Type (Packet, TCP_PACKET);

            if Left > Remote_MSS then
               Copy
                 (Packet,
                  Data,
                  Pos,
                  Pos + Remote_MSS - 1);
               Pos  := Pos + Remote_MSS;
               Left := Left - Remote_MSS;
               Num  := Num + Uint32 (Remote_MSS);

            elsif Left > 0 then
               Copy (Packet, Data, Pos, Pos + Left - 1);
               Num  := Num + Uint32 (Left);
               Left := 0;
            end if;

            --  Fill TCP header fields
            Tcp_Header := Packet.TCP;

            Tcp_Header.Th_Seq   := Num;
            Tcp_Header.Th_Ack   := 0;
            Tcp_Header.Th_Off   := TCP_Header_Net_Octets;
            Tcp_Header.Th_Flags := 0;
            if Left = 0 and then Push then
               Tcp_Header.Th_Flags := Th_Flags_Push;
            end if;
            if Syn then
               Tcp_Header.Th_Flags := Tcp_Header.Th_Flags or Th_Flags_Syn;
            end if;
            if Fin then
               Tcp_Header.Th_Flags := Tcp_Header.Th_Flags or Th_Flags_Fin;
            end if;

            if Tcp_Header.Th_Flags = Th_Flags_Syn
              and then Get_Data_Size (Packet, TCP_PACKET) = 0
            then
               Put_Uint8  (Packet, TCP_Option_MSS);
               Put_Uint8  (Packet, 4);
               Put_Uint16 (Packet, Max_Packet_Size);
               Tcp_Header.Th_Off := 96;
            end if;

            --  Use temporary queue to ensure that we have enought memory
            --  for all chunks
            Set_Length (Packet, Get_Data_Size (Packet, RAW_PACKET));
            Append (Queue, Packet);

            exit when Left = 0;
         end loop;

         if Syn or else Fin then
            Num := Num + 1;
         end if;

         --  Update next sequence number for stream
         Next_Sequence_Num := Num;

         --  Push the temporary queue on the Send_Queue for later processing
         --  by TCP_Output.

         if not Is_Empty (Queue) then
            Transfer (To => Send_Queue, From => Queue);
            Process_Send_Queue (Ack_Now => False);
         end if;

         Status := Ok;
      exception
         when others =>
            Release (Queue);
            Release (Packet);
      end Enqueue;

      ------------------------
      -- Process_Send_Queue --
      ------------------------

      procedure Process_Send_Queue (Ack_Now : Boolean) is
         ACK_Sent     : Boolean := False;
         Window       : constant Uint32 := Uint32'Min
           (Cwnd, Uint32 (Send_Window));
         Packet       : Buffer_Type;
         Segment_Size : Uint32;
         Tcp_Header   : TCP_Header_Access;
         Status       : Error_Code;

      begin
         while not Is_Empty (Send_Queue) loop
            --  We still have packets to send

            --  Get the first segment from Send_Queue
            Peek (Send_Queue, Packet);
            Tcp_Header := Packet.TCP;

            --  Get segment size
            Segment_Size := Tcp_Header.Th_Seq +
              Uint32 (Get_Data_Size (Packet, TCP_PACKET)) +
              Uint32 (Tcp_Header.Th_Flags and Th_Flags_Syn) +
              Uint32 (Tcp_Header.Th_Flags and Th_Flags_Fin);

            --  Check that we will not cross the Remote_Window
            if Segment_Size > Send_Unacknowledged + Window then
               --  return segment to Send_Queue
               Insert (Send_Queue, Packet);
               exit;
            end if;

            if State /= Syn_Sent then
               Tcp_Header.Th_Flags := Tcp_Header.Th_Flags or Th_Flags_Ack;
               ACK_Sent := True;
            end if;

            Send_Packet (Packet, Status);
            exit when Status in ENOBUFS .. ENETUNREACH;
            Send_Next := Send_Next + Segment_Size;
         end loop;

         --  Send an empty ACK segment if needed
         if Ack_Now
           and then not ACK_Sent
         then
            declare
               Ack_Packet : Buffer_Type;
            begin
               Allocate (Ack_Packet);
               if not Is_Null (Ack_Packet) then
                  Set_Type (Ack_Packet, TCP_PACKET);
                  Tcp_Header := Ack_Packet.TCP;

                  Tcp_Header.Th_Seq   := Send_Next;
                  Tcp_Header.Th_Ack   := 0;
                  Tcp_Header.Th_Off   := TCP_Header_Net_Octets;
                  Tcp_Header.Th_Flags := Th_Flags_Ack;

                  Send_Packet (Ack_Packet, Status);
               end if;

            exception
               when others =>
                  Release (Ack_Packet);
            end;
         end if;
      end Process_Send_Queue;

      -----------------
      -- Send_Packet --
      -----------------

      procedure Send_Packet
        (Packet : in out Buffer_Type;
         Status : out Error_Code)
      is
         Tcp_Header    : TCP_Header_Access;
         Pseudo_Header : TCP_Pseudo_Header;
         Local         : Buffer_Type;

      begin
         Allocate (Local);
         if Is_Null (Local) then
            Insert (Send_Queue, Packet);
            Status := ENOBUFS;
            return;
         end if;

         Copy (From => Packet, To => Local);

         Tcp_Header          := Packet.TCP;
         Tcp_Header.Th_Sport := Local_Port;
         Tcp_Header.Th_Dport := Remote_Port;

         --  Fill in the ACK number field and advertise our receiving
         --  window size
         if (Tcp_Header.Th_Flags and Th_Flags_Ack) = 1 then
            Tcp_Header.Th_Ack := Recive_Next;
         end if;
         Tcp_Header.Th_Win := Recive_Window;
         Tcp_Header.Th_Urp := 0;

         --  Compute checksum
         Pseudo_Header.Source_IP      := Local_Addr;
         Pseudo_Header.Destination_IP := Remote_Addr;
         Pseudo_Header.Zero           := 0;
         Pseudo_Header.Protocol       := Net.Protos.IPv4.P_TCP;
         Pseudo_Header.TCP_Length     := Get_Data_Size (Packet, IP_PACKET);

         Tcp_Header.Th_Sum := 0;
         Tcp_Header.Th_Sum := Net.Utils.TCP_Checksum (Pseudo_Header, Packet);

         --  Initialize retransmitting data
         if Retransmitting_Sequence = 0
           or else Retransmitting_Sequence < Tcp_Header.Th_Seq
         then
            Retransmitting_Sequence := Tcp_Header.Th_Seq;
            Retransmitting_Ticks    := TCP_Ticks;
         end if;

         --  Start retransmit timer if not already running
         if Retransmit_Ticks < 0 then
            Retransmit_Ticks := 0;
         end if;

         --  Convert header data to network order --
         To_Network (Tcp_Header);

         Net.Protos.IPv4.Make_Header
           (IP (Packet),
            Local_Addr,
            Remote_Addr,
            Net.Protos.IPv4.P_TCP,
            Get_Data_Size (Packet, Net.Buffers.ETHER_PACKET));
         Net.Protos.IPv4.Send_Raw (Ifnet, Remote_Addr, Packet, Status);

         if Status in ENOBUFS .. ENETUNREACH then
            --  Did not send, return segment to the Send_Queue
            Insert (Send_Queue, Local);
         else
            --  Append segment to the Unack_Queue
            Append (Unack_Queue, Local);
         end if;

      exception
         when others =>
            if not Is_Null (Local) then
               Insert (Send_Queue, Local);
            end if;
      end Send_Packet;

      --------------
      -- Received --
      --------------

      procedure Received
        (Packet    : Net.Buffers.Buffer_Type;
         Length    : Uint16;
         Processed : out Boolean)
      is
         Packet_IP    : constant IP_Header_Access  := Packet.IP;
         Packet_TCP   : constant TCP_Header_Access := Packet.TCP;
         Data         : Net.Buffers.Buffer_Type;

         Discard      : Boolean := False;
         --  Set True to prevent any further processing

         Win_L, Win_R : Uint32;
         --  Left and right edges of receive window

         Data_Len     : Uint16;
         --  Length of non-duplicate data in segment

         From         : Net.Uint16;
         --  Start point of data slice

         Status       : Status_Kind;

         ------------------------
         -- Setup_Flow_Control --
         ------------------------

         procedure Setup_Flow_Control;
         --  Shared processing between passive and active open: once the remote
         --  MSS is known, set up the congestion window and other flow control
         --  parameters.

         procedure Setup_Flow_Control
         is
            Data_Offset        : Uint16;
            Malformed_Options  : Boolean := False;
            Option_Offset      : Uint16;
            Option             : Uint8;
            Length             : Uint8;
            Value              : Uint8;
            MSS                : Uint16 := 0;
            Window_Scale       : Uint8 with Unreferenced;

            ----------------
            -- Get_Option --
            ----------------

            function Get_Option return Uint8;
            function Get_Option return Uint8
            is
               Result : constant Uint8 := Net.Buffers.Get_Uint8
                 (Packet, TCP_Position + Option_Offset);
            begin
               Option_Offset := Option_Offset + 1;
               return Result;
            end Get_Option;

            -------------------------
            -- Check_Option_Length --
            -------------------------

            procedure Check_Option_Length (Len : Uint8);
            procedure Check_Option_Length (Len : Uint8) is
               Actual_Len : Uint8;
            begin
               if Data_Offset - Option_Offset < Uint16 (Len) - 1 then
                  Malformed_Options := True;
               else
                  Actual_Len := Get_Option;
                  if Actual_Len /= Len then
                     Malformed_Options := True;
                  end if;
               end if;
            end Check_Option_Length;

         begin
            Data_Offset := TCP_Header_Length (Packet_TCP);

            --  Parse TCP options
            Option_Offset := TCP_Header_Octets;
            while Option_Offset < Data_Offset
              and then not Malformed_Options
            loop
               Option := Get_Option;

               case Option is
               when TCP_Option_End | TCP_Option_NOP =>
                  --  End of option list, No operation

                  null;

               when TCP_Option_MSS =>
                  --  Maximum segment size
                  Check_Option_Length (4);
                  if not Malformed_Options then
                     Value := Get_Option;
                     MSS   := Uint16 (Value) * 256;
                     Value := Get_Option;
                     MSS   := MSS + Uint16 (Value);
                  end if;

               when TCP_Option_Win_Scale =>
                  --  Window scale factor
                  Check_Option_Length (3);
                  if not Malformed_Options then
                     Window_Scale := Get_Option;
                  end if;

               when others =>
                  if Data_Offset - Option_Offset < 1 then
                     Malformed_Options := True;

                  else
                     Length := Get_Option;
                     if Length < 2
                       or else Data_Offset -
                         Option_Offset < Uint16 (Length) - 2
                     then
                        Malformed_Options := True;

                     else
                        --  Discard unknown option
                        Option_Offset := Option_Offset + Uint16 (Length) - 2;
                     end if;
                  end if;
               end case;
            end loop;

            --  Set remote MSS
            if MSS = 0 then
               Remote_MSS := 512;
            else
               Remote_MSS := MSS;
            end if;

            --  Slow start: initialize CWND to 1 segment
            Cwnd := Uint32 (Remote_MSS);

            --  Congestion avoidance: initialize SSthresh to 65_535
            Ssthresh := 65_535;
         end Setup_Flow_Control;

         --------------
         -- Teardown --
         --------------

         procedure Teardown (Callback : Boolean);
         --  Tear down the current connection, notify user if Callback is True

         procedure Teardown (Callback : Boolean) is
         begin
            if Callback then
               Socket.Callback_Kind := Tcp_Event_Abort;
            end if;
            Set_State (Closed);
            Discard := True;
         end Teardown;

      begin
         Processed := False;

         if Packet_IP.Ip_Dst /= Local_Addr
           or else Packet_IP.Ip_Src /= Remote_Addr
           or else Packet_TCP.Th_Dport /= Local_Port
           or else Packet_TCP.Th_Sport /= Remote_Port
         then
            return;
         end if;

         Processed := True;

         case State is
            when Syn_Sent =>
               if (Packet_TCP.Th_Flags and Th_Flags_Ack) = 1 then
                  --  Reject if ACK not in range
                  if Packet_TCP.Th_Ack - 1 <= Init_Sequence_Num
                    or else Packet_TCP.Th_Ack - 1 > Send_Next
                  then
                     if (Packet_TCP.Th_Flags and Th_Flags_Rst) = 0 then
                        Send_Rst
                          (Src_IP   => Packet_IP.Ip_Dst,
                           Src_Port => Packet_TCP.Th_Dport,
                           Dst_IP   => Packet_IP.Ip_Src,
                           Dst_Port => Packet_TCP.Th_Sport,
                           Ack      => False,
                           Seq_Num  => Packet_TCP.Th_Ack,
                           Ack_Num  => 0,
                           Status   => Status);
                     end if;
                     Discard := True;
                  end if;
               end if;

               if not Discard then
                  if (Packet_TCP.Th_Flags and Th_Flags_Rst) = 1 then
                     if (Packet_TCP.Th_Flags and Th_Flags_Ack) = 1 then
                        --  Connection refused
                        Teardown (True);
                        return;
                     end if;

                     Discard := True;
                  end if;
               end if;

               if not Discard then
                  if (Packet_TCP.Th_Flags and Th_Flags_Syn) = 1 then
                     Setup_Flow_Control;

                     Init_Recive_Num := Packet_TCP.Th_Seq + 1;
                     Recive_Next     := Init_Recive_Num + 1;

                     if (Packet_TCP.Th_Flags and Th_Flags_Ack) = 1 then
                        Process_Ack (Packet);
                     end if;

                     if Send_Unacknowledged > Init_Sequence_Num then
                        Set_State (Established);
                        Send_Control
                          (Syn    => False,
                           Fin    => False,
                           Status => Status);

                     else
                        Set_State (Syn_Received);
                        Send_Control
                          (Syn    => True,
                           Fin    => False,
                           Status => Status);
                     end if;
                  end if;
               end if;

            when others =>
               Allocate (Data);
               Discard := Is_Null (Data);

               if not Discard then
                  --  Check sequence number
                  Win_L := Recive_Next;
                  Win_R := Recive_Next + Uint32 (Recive_Window);

                  if not
                    ((Recive_Window = 0
                      and then Packet_TCP.Th_Seq = Recive_Next)
                     or else
                       (Win_L <= Packet_TCP.Th_Seq
                        and then Packet_TCP.Th_Seq < Win_R)
                     or else
                       (Win_L <= Packet_TCP.Th_Seq + Uint32 (Length) - 1
                        and then Packet_TCP.Th_Seq + Uint32 (Length) - 1 <
                            Win_R))
                  then
                     --  Segment is not acceptable: send ACK
                     --  (unless RST is present) and discard.

                     if (Packet_TCP.Th_Flags and Th_Flags_Rst) = 0 then
                        Send_Control
                          (Syn    => False,
                           Fin    => False,
                           Status => Status);
                     end if;
                     Discard := True;

                  else
                     --  Here if segment is acceptable

                     --  Check RST bit
                     if (Packet_TCP.Th_Flags and Th_Flags_Rst) = 1 then
                        Teardown (State in Established .. Close_Wait);
                     end if;
                  end if;
               end if;

               --  Check SYN bit
               if not Discard
                 and then (Packet_TCP.Th_Flags and Th_Flags_Syn) = 1
               then
                  --  SYN is in the window: error, tear down connection
                  Teardown (True);
               end if;

               --  Check ACK field
               if not Discard
                 and then (Packet_TCP.Th_Flags and Th_Flags_Ack) = 0
               then
                  Discard := True;
               end if;

               if not Discard then
                  if State = Syn_Received then
                     if Send_Unacknowledged <= Packet_TCP.Th_Ack
                       and then Packet_TCP.Th_Ack < Send_Next + 1
                     then
                        Set_State (Established);
                     else
                        Send_Rst
                          (Src_IP   => Packet_IP.Ip_Dst,
                           Src_Port => Packet_TCP.Th_Dport,
                           Dst_IP   => Packet_IP.Ip_Src,
                           Dst_Port => Packet_TCP.Th_Sport,
                           Ack      => False,
                           Seq_Num  => Packet_TCP.Th_Ack,
                           Ack_Num  => 0,
                           Status   => Status);
                        Teardown (False);
                     end if;
                  end if;
               end if;

               if not Discard then
                  case State is
                     when Syn_Received =>
                        --  Can't happen, processed previously
                        null;

                     when Established | Fin_Wait_1 | Fin_Wait_2 =>
                        Process_Ack (Packet);

                        From := TCP_Position + TCP_Header_Length (Packet_TCP);

                        if Packet_TCP.Th_Seq < Recive_Next then
                           --  Drop head of segment that was already received

                           Data_Len := Length -
                             Uint16 (Recive_Next - Packet_TCP.Th_Seq);

                           From := From +
                             Uint16 (Recive_Next - Packet_TCP.Th_Seq);
                        else
                           Data_Len := Length;
                        end if;

                        Recive_Next := Packet_TCP.Th_Seq + Uint32 (Data_Len);

                        if Packet_TCP.Th_Seq < Uint32 (Recive_Window) then
                           Recive_Window := Recive_Window - Data_Len;

                        else
                           Recive_Window := 0;
                        end if;

                        if Data_Len > 0 then
                           --  Store data in the recive list
                           Copy
                             (Data,
                              Packet,
                              From,
                              Get_Length (Packet) - 1);
                           Set_Length (Data, Get_Data_Size (Data, RAW_PACKET));
                           Append (Recive_Queue, Data);
                           Socket.Callback_Kind := Tcp_Event_Recv;

                           Process_Send_Queue (Ack_Now => False);
                        end if;

                     when others =>
                        --  Ignore urgent pointer and segment text
                        null;
                  end case;

                  --  Check FIN bit
                  if (Packet_TCP.Th_Flags and Th_Flags_Fin) = 1 then
                     case State is
                        when Closed | Syn_Sent =>
                           null;

                        when Established | Syn_Received =>
                           --  Notify connection closed: deliver 0 bytes of
                           --  data. First transition to Close_Wait, as the
                           --  application may decide to call Close from
                           --  within the callback.

                           Set_State (Close_Wait);

                        when Fin_Wait_1 =>
                           --  If our FIN has been Ack'd then we are already in
                           --  Closing or Fin_Wait_2.
                           Set_State (Closing);

                        when Fin_Wait_2 =>
                           Set_State (Time_Wait);

                           --  Start 2MSL timeout
                           Watchdog_Ticks := TCP_Ticks;

                        when Close_Wait | Closing | Last_Ack =>
                           null;

                        when Time_Wait =>
                           --  Restart 2MSL timeout
                           Watchdog_Ticks := TCP_Ticks;
                     end case;
                  end if;
               end if;
         end case;
         Release (Data);

      exception
         when others =>
            Release (Data);
      end Received;

      -----------------
      -- Process_Ack --
      -----------------

      procedure Process_Ack (Packet : Net.Buffers.Buffer_Type)
      is
         Packet_TCP : constant TCP_Header_Access := Packet.TCP;
         Prev       : Net.Buffers.Buffer_Type;
         Prev_TCP   : TCP_Header_Access;
         Length     : Uint16;
         Status     : Status_Kind;

         --------------------------
         -- Update_RTT_Estimator --
         --------------------------

         procedure Update_RTT_Estimator (Value : Uint16);
         procedure Update_RTT_Estimator (Value : Uint16)
         is
            M : Uint16;
         begin
            M := Value;

            --  Update average estimator

            M := M - RTT_Average / 8;
            RTT_Average := RTT_Average + M;

            --  Update standard deviation estimator

            M := M - RTT_Stddev / 4;
            RTT_Stddev := RTT_Stddev + M;

            --  Set new retransmit timeout

            RTO := RTT_Average / 8 + RTT_Stddev;
         end Update_RTT_Estimator;

      begin
         if Packet_TCP.Th_Ack < Send_Unacknowledged then
            --  Duplicated ack
            null;

         else
            --  Invalid ack for a seqno not sent yet should have been discarded,
            --  so we end up here for an ACK that acks new data.

            pragma Assert (Packet_TCP.Th_Ack <= Send_Next);

            Send_Unacknowledged := Packet_TCP.Th_Ack;

            --  Reset retransmit timer (but keep it running)

            Retransmit_Ticks := 0;
            Retransmit_Count := 0;

            --  Perform slow start and congestion avoidance

            if Cwnd < Ssthresh then
               Cwnd := Cwnd + Uint32 (Remote_MSS);
            else
               Cwnd := Cwnd + Uint32 (Remote_MSS * Remote_MSS) / Cwnd;
            end if;

            --  Update RTT estimator

            if Retransmitting_Ticks /= 0
              and then Retransmitting_Sequence <= Packet_TCP.Th_Ack
            then
               Update_RTT_Estimator
                 (Uint16 (TCP_Ticks - Retransmitting_Ticks));
               Retransmitting_Ticks := 0;
            end if;

            --  Purge entirely acked segments
            while not Is_Empty (Unack_Queue) loop
               Peek (Unack_Queue, Prev);

               Length := TCP_Payload_Length (Prev);
               Prev_TCP := Prev.TCP;

               if Prev_TCP.Th_Seq + Uint32 (Length) > Packet_TCP.Th_Ack then
                  Insert (Unack_Queue, Prev);
                  exit;
               end if;

               --  Packet entirely acked: notify user and remove from queue.
               --  Note: For a segment carrying a FIN, we do not signal it sent
               --  if the ack covers all of the data but not the FIN flag.

               if Socket.Callback_Kind = Tcp_Event_None then
                  Socket.Callback_Kind := Tcp_Event_Sent;
               end if;

               if (Prev_TCP.Th_Flags and Th_Flags_Fin) = 1 then
                  case State is
                     when Fin_Wait_1 =>
                        Set_State (Fin_Wait_2);

                        --  Start Fin_Wait_2 timeout
                        Watchdog_Ticks := TCP_Ticks;

                     when Closing =>
                        Set_State (Time_Wait);

                        --  Start 2MSL timeout
                        Watchdog_Ticks := TCP_Ticks;

                     when Last_Ack =>
                        Set_State (Closed);

                     when Time_Wait =>

                        --  Ack retransmitted FIN
                        Send_Control
                          (Syn    => False,
                           Fin    => False,
                           Status => Status);

                        --  Restart 2MSL timeout
                        Watchdog_Ticks := TCP_Ticks;

                     when others =>
                        --  Can't happen (we sent a FIN)
                        null;
                  end case;
               end if;

               --  Finally deallocate Packet
               Release (Prev);
            end loop;

            --  If nothing remains on the Unack_Queue, stop retransmit timer,
            --  else reset it.

            if Is_Empty (Unack_Queue) then
               Retransmit_Ticks := -1;
               Retransmit_Count := 0;
            else
               Retransmit_Ticks := 0;
            end if;

            --  Update window if:
            if Sequence_Last_Update < Packet_TCP.Th_Seq
              or else
                (Sequence_Last_Update = Packet_TCP.Th_Seq
                 and then
                   (Ask_Last_Update < Packet_TCP.Th_Seq
                    or else
                      (Ask_Last_Update = Packet_TCP.Th_Seq
                       and then Packet_TCP.Th_Win > Send_Window)))
            then
               Send_Window          := Packet_TCP.Th_Win;
               Sequence_Last_Update := Packet_TCP.Th_Seq;
               Ask_Last_Update      := Packet_TCP.Th_Ack;

               if Send_Window = 0 then
                  --  Start persist timer

                  Persist_Ticks   := 0;
                  Persist_Backoff := Initial_Persist_Backoff;
               else
                  --  Stop persist timer

                  Persist_Ticks   := -1;
                  Persist_Backoff := 0;
               end if;
            end if;
         end if;
      end Process_Ack;

      --------------------
      -- Check_Timeouts --
      --------------------

      procedure Check_Timeouts is
         Remove : Boolean := False;
      begin
         if (State = Fin_Wait_2
             and then TCP_Ticks - Watchdog_Ticks > Fin_Wait_Timeout)
           or else
             (State = Syn_Received
              and then TCP_Ticks - Watchdog_Ticks > Syn_Received_Timeout)
           or else
             (State = Last_Ack
              and then TCP_Ticks - Watchdog_Ticks > Time_Wait_Timeout)
         then
            Remove := True;

         else
            --  Persist timer: send window probe
            if Persist_Backoff > 0 then
               Persist_Ticks := Persist_Ticks + 1;

               if Persist_Ticks >= Persist_Backoff then
                  Persist_Ticks := 0;

                  --  Double persist backoff up to Max_Persist_Backoff
                  Persist_Backoff := Int16'Min
                    (Max_Persist_Backoff, Persist_Backoff * 2);

                  Send_Window_Probe;
               end if;

            else
               --  Retransmit timer
               if Retransmit_Ticks >= 0 then
                  Retransmit_Ticks := Retransmit_Ticks + 1;
               end if;

               if not Is_Empty (Unack_Queue)
                 and then Retransmit_Ticks > Int16 (RTO)
               then
                  if State = Syn_Sent then
                     --  SYN_SENT case: no backoff, MAX_SYN_RTX limit
                     if Retransmit_Count > TCP_MAX_SYN_RTX then
                        Remove := True;
                     end if;

                  else
                     --  All other cases: exponential backoff, MAX_RTS limit
                     if Retransmit_Count > TCP_MAX_RTX then
                        Remove := True;
                     else
                        RTO := RTO * 2;
                     end if;
                  end if;

                  if not Remove then
                     --  Update Ssthresh and congestion window
                     Ssthresh :=
                       Uint32'Max
                         (Uint32'Min (Uint32 (Send_Window), Cwnd) / 2,
                          2 * Uint32 (Remote_MSS));
                     Cwnd := Uint32 (Remote_MSS);

                     Retransmit_Timeout;
                  end if;
               end if;
            end if;
         end if;

         if Remove then
            if Socket.Callback_Kind = Tcp_Event_None then
               Socket.Callback_Kind := Tcp_Event_Abort;
            end if;
            Set_State (Closed);
         end if;
      end Check_Timeouts;

      ---------------------
      -- Check_Time_Wait --
      ---------------------

      procedure Check_Time_Wait is
      begin
         if TCP_Ticks - Watchdog_Ticks > Time_Wait_Timeout then
            Set_State (Closed);
         end if;
      end Check_Time_Wait;

      -----------------------
      -- Send_Window_Probe --
      -----------------------

      procedure Send_Window_Probe is
         --  Probe segment
         --  Buf       : Buffers.Buffer_Id;

         Packet     : Net.Buffers.Buffer_Type;
         Packet_TCP : TCP_Header_Access;
         Length     : Uint16;
         Probe_Fin  : Boolean;
         Probe      : Net.Buffers.Buffer_Type;
         Probe_TCP  : TCP_Header_Access;
         Status     : Error_Code;

      begin
         if not Is_Empty (Unack_Queue) then
            Copy (Unack_Queue, Packet);

         elsif not Is_Empty (Send_Queue) then
            Copy (Send_Queue, Packet);
         end if;

         if not Is_Null (Packet) then
            Length := TCP_Payload_Length (Packet);
            Packet_TCP := Packet.TCP;

            Probe_Fin := (Packet_TCP.Th_Flags and Th_Flags_Fin) = 1
              and then Length = 1;

            Allocate (Probe);
            if not Is_Null (Probe) then
               Set_Type (Probe, TCP_PACKET);
               Probe_TCP := Probe.TCP;
               Probe_TCP.Th_Off := TCP_Header_Net_Octets;
               Probe_TCP.Th_Seq := Packet_TCP.Th_Seq;
               if Probe_Fin then
                  Probe_TCP.Th_Flags := (Th_Flags_Fin or Th_Flags_Ack);
               else
                  Probe_TCP.Th_Flags := Th_Flags_Ack;
               end if;

               if not Probe_Fin then
                  Put_Uint8
                    (Probe,
                     Get_Uint8
                       (Packet,
                        TCP_Position + TCP_Header_Length (Packet_TCP)));
               end if;

               Send_Packet (Probe, Status);
            end if;
         end if;

      exception
         when others =>
            Release (Probe);
      end Send_Window_Probe;

      ------------------------
      -- Retransmit_Timeout --
      ------------------------

      procedure Retransmit_Timeout is
      begin
         --  Bump retransmit count, reset timer
         Retransmit_Count := Retransmit_Count + 1;
         Retransmit_Ticks := 0;

         --  Disable RTT estimate while retransmitting
         Retransmitting_Ticks := 0;

         --  Move all packets from Unack_Queue to head of Send_Queue:
         --  first concatenate Send_Queue at end of Unack_Queue, then move
         --  Unack_Queue to Send_Queue.

         if not Is_Empty (Send_Queue) then
            --  Concatenate Send_Queue at end of Unack_Queue
            Transfer (To => Unack_Queue, From => Send_Queue);
         end if;

         Transfer (To => Send_Queue, From => Unack_Queue);

         --  Start output
         Process_Send_Queue (Ack_Now => False);
      end Retransmit_Timeout;

   end State_Protected_Object;

   -------------------
   -- Call_Callback --
   -------------------

   procedure Call_Callback (This : in out Socket) is
   begin
      if This.Callback_Proc /= null then
         if This.Callback_Kind /= Tcp_Event_None then
            This.Callback_Proc.all (This.Self, This.Callback_Kind);
         end if;
      end if;

      This.Callback_Kind := Tcp_Event_None;
   end Call_Callback;

   ----------
   -- Bind --
   ----------

   procedure Bind
     (This   : in out Socket;
      Port   : Uint16;
      Cb     : Callback;
      Status : out Status_Kind) is
   begin
      This.Callback_Proc := Cb;
      Status             := Error;

      if This.State_No = 0 then
         for Index in 1 .. Max_Sockets_Count loop
            States (Index).Bind (This.Self, Port, Status);
            if Status = Ok then
               This.State_No := Index;
               exit;
            end if;
         end loop;
      else
         States (This.State_No).Bind (This.Self, Port, Status);
      end if;

      if Status = Ok then
         This.Callback_Kind := Tcp_Event_None;
      else
         This.Callback_Proc := null;
      end if;
      Call_Callback (This);
   end Bind;

   -------------
   -- Connect --
   -------------

   procedure Connect
     (This   : in out Socket;
      Addr   : Ip_Addr;
      Port   : Uint16;
      Status : out Status_Kind) is
   begin
      States (This.State_No).Connect (Addr, Port, Status);
      Call_Callback (This);
   end Connect;

   --------------
   -- Received --
   --------------

   procedure Received
     (This      : Socket_Access;
      Packet    : Net.Buffers.Buffer_Type;
      Length    : Uint16;
      Processed : out Boolean) is
   begin
      States (This.State_No).Received (Packet, Length, Processed);
      Call_Callback (This.all);
   end Received;

   --------------------
   -- Check_Timeouts --
   --------------------

   procedure Check_Timeouts (This : Socket_Access) is
   begin
      States (This.State_No).Check_Timeouts;
      Call_Callback (This.all);
   end Check_Timeouts;

   ---------------------
   -- Check_Time_Wait --
   ---------------------

   procedure Check_Time_Wait (This : Socket_Access) is
   begin
      States (This.State_No).Check_Time_Wait;
      Call_Callback (This.all);
   end Check_Time_Wait;

   ---------------
   -- Get_State --
   ---------------

   function Get_State (This : Socket) return Socket_State_Type is
   begin
      if This.State_No = 0 then
         return Closed;
      else
         return States (This.State_No).Get_State;
      end if;
   end Get_State;

   ---------------
   -- Is_Binded --
   ---------------

   function Is_Binded (This : Socket) return Boolean is
   begin
      return This.State_No /= 0
        and then States (This.State_No).Is_Binded;
   end Is_Binded;

   ----------
   -- Send --
   ----------

   procedure Send
     (This   : in out Socket;
      Data   : Net.Buffers.Buffer_Type;
      Push   : Boolean;
      Status : out Status_Kind) is
   begin
      if Is_Null (Data) or else Get_Data_Size (Data, RAW_PACKET) = 0 then
         Status := Error;
      else
         States (This.State_No).Send (Data, Push, Status);
      end if;
      Call_Callback (This);
   end Send;

   -------------------
   -- Get_Send_Room --
   -------------------

   function Get_Send_Room (This : Socket) return Uint16 is
   begin
      return States (This.State_No).Get_Send_Room;
   end Get_Send_Room;

   -------------
   -- Receive --
   -------------

   procedure Receive
     (This     : in out Socket;
      Data     : in out Net.Buffers.Buffer_Type; --  Raw data
      Has_More : out Boolean) is
   begin
      if not Is_Null (Data) then
         States (This.State_No).Receive (Data, Has_More);
      end if;
      Call_Callback (This);
   end Receive;

   ----------------------
   -- Get_Receive_Room --
   ----------------------

   function Get_Receive_Room (This : Socket) return Uint16 is
   begin
      return States (This.State_No).Get_Receive_Room;
   end Get_Receive_Room;

   -----------
   -- Close --
   -----------

   procedure Close
     (This   : in out Socket;
      Status : out Status_Kind) is
   begin
      if This.State_No /= 0 then
         States (This.State_No).Close (Status);
         if Status = Ok then
            This.Callback_Proc := null;
         else
            Call_Callback (This);
         end if;
      end if;
   end Close;

   ----------
   -- Drop --
   ----------

   procedure Drop
     (This   : in out Socket;
      Status : out Status_Kind) is
   begin
      States (This.State_No).Drop (Status);
      if Status = Ok then
         This.Callback_Proc := null;
      else
         Call_Callback (This);
      end if;
   end Drop;

   --------------
   -- Received --
   --------------

   procedure Received (Packet : Net.Buffers.Buffer_Type)
   is
      Payload_Length   : Uint16;
      Packet_IP        : constant IP_Header_Access  := Packet.IP;
      Packet_TCP       : constant TCP_Header_Access := Packet.TCP;
      Pseudo_Header    : TCP_Pseudo_Header;
      Data_Offset      : Uint16;
      Processed        : Boolean;

      Ack              : Boolean;
      Seq_Num, Ack_Num : Uint32;
      Status           : Status_Kind;

   begin

      To_Host (Packet_TCP);

      Payload_Length := Packet_IP.Ip_Len - IP_Header_Length (Packet_IP);

      --  Verify TCP checksum
      if Check_Incoming_Checksums
        and then Packet_TCP.Th_Sum /= 0
      then
         Pseudo_Header.Source_IP      := Packet_IP.Ip_Src;
         Pseudo_Header.Destination_IP := Packet_IP.Ip_Dst;
         Pseudo_Header.Zero           := 0;
         Pseudo_Header.Protocol       := Net.Protos.IPv4.P_TCP;
         Pseudo_Header.TCP_Length     := Payload_Length;

         if not Net.Utils.Check_TCP_Checksum (Pseudo_Header, Packet) then
            --  Not valid checksum, do not process the packet
            return;
         end if;
      end if;

      Data_Offset := TCP_Header_Length (Packet_TCP);

      Payload_Length := Payload_Length - Data_Offset +
        Uint16 (Packet_TCP.Th_Flags and Th_Flags_Syn) +
        Uint16 (Packet_TCP.Th_Flags and Th_Flags_Fin);

      --  Get copy of active socets
      Reestr.Get_List_Copy (Active);

      for Position in 1 .. Processing_Sockets.Last loop
         Received
           (This      => Processing_Sockets.List (Position),
            Packet    => Packet,
            Length    => Payload_Length,
            Processed => Processed);
         exit when Processed;
      end loop;

      if not Processed then
         if (Packet_TCP.Th_Flags and Th_Flags_Rst) = 1 then
            --  Discard incoming RST without associated socket
            null;

         else
            --  Calculate logical TCP segment length, including the data payload,
            --  as well as the SYN and FIN flags.

            if (Packet_TCP.Th_Flags and Th_Flags_Ack) = 0 then
               Seq_Num := 0;
               Ack_Num := Packet_TCP.Th_Seq + Uint32 (Payload_Length);
               Ack     := True;
            else
               Seq_Num := Packet_TCP.Th_Ack;
               Ack_Num := 0;
               Ack     := False;
            end if;

            Send_Rst
              (Src_IP   => Packet_IP.Ip_Dst,
               Src_Port => Packet_TCP.Th_Dport,
               Dst_IP   => Packet_IP.Ip_Src,
               Dst_Port => Packet_TCP.Th_Sport,
               Ack      => Ack,
               Seq_Num  => Seq_Num,
               Ack_Num  => Ack_Num,
               Status   => Status);
         end if;
      end if;
   end Received;

   --------------
   -- Send_Rst --
   --------------

   procedure Send_Rst
     (Src_IP   : Ip_Addr;
      Src_Port : Uint16;
      Dst_IP   : Ip_Addr;
      Dst_Port : Uint16;
      Ack      : Boolean;
      Seq_Num  : Uint32;
      Ack_Num  : Uint32;
      Status   : out Status_Kind)
   is
      Buffer     : Buffer_Type;
      Buffer_TCP : TCP_Header_Access;
      Code       : Error_Code;

   begin
      Status := Error;

      Allocate (Buffer);
      if Is_Null (Buffer) then
         return;
      end if;

      Set_Type (Buffer, TCP_PACKET);
      Buffer_TCP := Buffer.TCP;

      Buffer_TCP.Th_Dport := Dst_Port;
      Buffer_TCP.Th_Sport := Src_Port;
      Buffer_TCP.Th_Seq   := Seq_Num;
      Buffer_TCP.Th_Ack   := Ack_Num;
      Buffer_TCP.Th_Off   := TCP_Header_Net_Octets;
      if Ack then
         Buffer_TCP.Th_Flags := Th_Flags_Ack or Th_Flags_Rst;
      else
         Buffer_TCP.Th_Flags := Th_Flags_Rst;
      end if;
      Buffer_TCP.Th_Win := 0;
      Buffer_TCP.Th_Sum := 0;
      Buffer_TCP.Th_Urp := 0;

      Net.Protos.IPv4.Make_Header
        (IP (Buffer),
         Src_IP,
         Dst_IP,
         Net.Protos.IPv4.P_TCP,
         Get_Data_Size (Buffer, Net.Buffers.RAW_PACKET) - 14);
      Net.Protos.IPv4.Send_Raw (Ifnet, Dst_IP, Buffer, Code);

      Status := (if Code = EOK then Ok else Error);

   exception
      when others =>
         Release (Buffer);
   end Send_Rst;

   --------------------
   -- Check_Timeouts --
   --------------------

   procedure Check_Timeouts is
   begin
      TCP_Ticks := TCP_Ticks + 1;

      Reestr.Get_List_Copy (Active);

      for Pos in 1 .. Processing_Sockets.Last loop
         Check_Timeouts (Processing_Sockets.List (Pos));
      end loop;

      --  Purge old TIME_WAIT PCBs

      Reestr.Get_List_Copy (Time_Wait);
      for Pos in 1 .. Processing_Sockets.Last loop
         Check_Time_Wait (Processing_Sockets.List (Pos));
      end loop;
   end Check_Timeouts;

   ----------------
   -- Initialize --
   ----------------

   procedure Initialize is
   begin
      --  Ticks per second
      TCP_Ticks := Uint32
        (Ada.Real_Time."/"(One_Second, Check_TCP_Status_Time));

      Fin_Wait_Timeout := Uint32 (20 * TCP_Ticks); --  20 s

      Syn_Received_Timeout := Uint32 (20 * TCP_Ticks); --  20 s

      Time_Wait_Timeout := 2 * (2 * TCP_TTL) * TCP_Ticks;

      Initial_Persist_Backoff :=
        Int16 (Ada.Real_Time."/"(One_And_Half_Second, Check_TCP_Status_Time));
      --  1.5s

      Max_Persist_Backoff := Int16 (60 * TCP_Ticks); --  60s
   end Initialize;

   ------------------------
   -- TCP_Payload_Length --
   ------------------------

   function TCP_Payload_Length
     (Packet : Net.Buffers.Buffer_Type)
      return Uint16
   is
      Packet_IP  : constant IP_Header_Access  := Packet.IP;
      Packet_TCP : constant TCP_Header_Access := Packet.TCP;
      Result     : Uint16;
   begin
      if Packet_IP.Ip_Len /= 0 then
         Result := Packet_IP.Ip_Len - IP_Header_Length (Packet_IP);
      else
         Result := Get_Data_Size (Packet, IP_PACKET);
      end if;

      return Result -
        (TCP_Header_Length (Packet_TCP) +
        Uint16 (Packet_TCP.Th_Flags and Th_Flags_Syn) +
        Uint16 (Packet_TCP.Th_Flags and Th_Flags_Fin));
   end TCP_Payload_Length;

   -------------
   -- To_Host --
   -------------

   procedure To_Host (TCP : TCP_Header_Access) is
   begin
      TCP.Th_Sport := To_Host (TCP.Th_Sport);
      TCP.Th_Dport := To_Host (TCP.Th_Dport);
      TCP.Th_Seq   := To_Host (TCP.Th_Seq);
      TCP.Th_Ack   := To_Host (TCP.Th_Ack);
      TCP.Th_Win   := To_Host (TCP.Th_Win);
      TCP.Th_Sum   := To_Host (TCP.Th_Sum);
      TCP.Th_Urp   := To_Host (TCP.Th_Urp);
   end To_Host;

   ----------------
   -- To_Network --
   ----------------

   procedure To_Network (TCP : Net.Headers.TCP_Header_Access) is
   begin
      TCP.Th_Sport := To_Network (TCP.Th_Sport);
      TCP.Th_Dport := To_Network (TCP.Th_Dport);
      TCP.Th_Seq   := To_Network (TCP.Th_Seq);
      TCP.Th_Ack   := To_Network (TCP.Th_Ack);
      TCP.Th_Win   := To_Network (TCP.Th_Win);
      TCP.Th_Sum   := To_Network (TCP.Th_Sum);
      TCP.Th_Urp   := To_Network (TCP.Th_Urp);
   end To_Network;

   ---------------------
   -- Max_Packet_Size --
   ---------------------

   function Max_Packet_Size return Uint16 is
   begin
      return Uint16 (NET_BUF_SIZE - 14 - 20 - 20 - 40);
   end Max_Packet_Size;

end Net.Sockets.Tcp;
