
with Net.Utils;
with Net.Buffers; use Net.Buffers;
with Net.Headers; use Net.Headers;

with Net.Protos.IPv4;

package body Net.Sockets.Tcp is

   use type Int32;

   Default_TCP_Window      : constant := 65495;
   Initial_Send_Window     : constant := 2048;
   Maximum_SYN_Retransmits : constant := 6;
   --  Maximum retransmits for initial (SYN) segments
   Maximum_Retransmits     : constant := 12;
   --  Maximum retransmits for data segments
   TTL                     : constant := 64;
   Timeouts_Ticks_Count    : Uint32   := 0;

   Timeout_Ticks_Per_Second : constant Uint32 := 2000;
   Fin_Wait_Timeout         : constant Uint32 :=
     Timeout_Ticks_Per_Second * 20; -- 20 s
   Syn_Received_Timeout     : constant Uint32 :=
     Timeout_Ticks_Per_Second * 20; -- 20 s
   Time_Wait_Timeout        : constant Uint32 :=
     2 * (2 * TTL) * Timeout_Ticks_Per_Second;

   Initial_Persist_Backoff  : constant Int32  :=
     Int32 (Timeout_Ticks_Per_Second + Timeout_Ticks_Per_Second / 2); --  1.5 s
   Maximum_Persist_Backoff  : constant Int32  :=
     Int32 (Timeout_Ticks_Per_Second * 60);  -- 60 s

   function TCP_Data_Length
     (Packet : Net.Buffers.Buffer_Type;
      Header : Net.Headers.TCP_Header_Access)
      return Uint16;

   procedure To_Host (TCP : Net.Headers.TCP_Header_Access);
   --  Converts to host bytes order

   procedure To_Network (TCP : Net.Headers.TCP_Header_Access);
   --  Converts to network bytes order

   function Max_Packet_Size return Uint16;

   -----------
   -- State --
   -----------

   protected type State_Protected_Object
     with Priority => Priority
   is

      function Get_State return Socket_State_Kind;
      function Is_Binded return Boolean;

      procedure Bind
        (This   : Socket_Access;
         Port   : Uint16;
         Status : out Error_Code);

      procedure Connect
        (Addr   : Ip_Addr;
         Port   : Uint16;
         Status : out Error_Code);

      procedure Send
        (Data   : Net.Buffers.Buffer_Type; --  Raw data
         Push   : Boolean;
         Status : out Error_Code);

      function Get_Send_Room return Uint16;

      procedure Receive
        (Data     : in out Net.Buffers.Buffer_Type; --  Raw data
         Has_More : out Boolean);

      function Get_Receive_Room return Uint16;

      procedure Close (Status : out Error_Code);

      procedure Drop (Status : out Error_Code);

      procedure Received
        (Packet    : in out Net.Buffers.Buffer_Type;
         Length    : Uint16;
         Processed : out Boolean);

      procedure Check_Timeouts;
      procedure Check_Time_Wait;

   private
      Socket                  : Socket_Access := null;

      State                   : Socket_State_Kind := Closed;

      Local_Addr              : Ip_Addr := (0, 0, 0, 0);
      Local_Port              : Uint16  := 0;

      Remote_Addr             : Ip_Addr := (0, 0, 0, 0);
      Remote_Port             : Uint16  := 0;

      Local_MSS               : Uint16; --  Maximum segment size for receiving
      Remote_MSS              : Uint16; --  Maximum segment size for sending

      Init_Sequence_Num       : Uint32;
      Next_Sequence_Num       : Uint32;

      --  Send
      Send_Window             : Uint16;
      Ssthresh                : Uint32;
      Cwnd                    : Uint32;
      Send_Unacknowledged     : Uint32;
      Send_Next_Control       : Uint32;
      Sequence_Last_Update    : Uint32;
      Ask_Last_Update         : Uint32;

      --  Recive
      Init_Recive_Num         : Uint32;
      Receive_Window          : Uint16;
      Receive_Next            : Uint32;

      Send_Queue              : Net.Buffers.Buffer_List;
      Unack_Queue             : Net.Buffers.Buffer_List;
      Received_Queue          : Net.Buffers.Buffer_List;

      Retransmitting_Sequence : Uint32;
      Retransmitting_Ticks    : Uint32;

      RTT_Average             : Uint16;
      RTT_Stddev              : Uint16;
      RTO                     : Uint16;

      Retransmit_Ticks        : Int16;
      Retransmit_Count        : Uint8;

      Watchdog_Ticks          : Uint32;
      --  TCP ticks for watchdog timer (used for idle/keepalive, and
      --  2MSL TIME_WAIT).

      Persist_Ticks           : Int32;
      Persist_Backoff         : Int32;
      --  TCP ticks value for persist timer (-1 if not running, ticks count
      --  since last reset if running, and current backoff count (0 if not
      --  running).

      procedure Init;
      procedure Set_State (New_State : Socket_State_Kind);

      procedure Send_Control
        (Syn    : Boolean;
         Fin    : Boolean;
         Status : out Error_Code);
      --  Send a TCP segment with no payload, just control bits set according
      --  to Syn and Fin. Ack will be set as well unless in Syn_Sent state.

      procedure Send_Rst
        (Ack     : Boolean;
         Seq_Num : Uint32;
         Ack_Num : Uint32;
         Status  : out Error_Code);
      --  Sends RESET

      procedure Enqueue
        (Data   : Net.Buffers.Buffer_Type;
         Push   : Boolean;
         Syn    : Boolean;
         Fin    : Boolean;
         Ack    : Boolean;
         Status : out Error_Code);
      --  Request push onto the Send_Queue for later output by TCP_Output.
      --  Data designates a buffer to be used as payload data or TCP
      --  options, according to Options, with segments cut to be MSS bytes max
      --  each.

      procedure Process_Send_Queue
        (Ack_Now : Boolean;
         Status  : out Error_Code);
      --  Starts output from send queue. Check whether ACK have sent if
      --  Ack_Now = True.

      procedure Send_Packet
        (Packet : in out Buffer_Type;
         Status : out Error_Code);
      --  Send the packet

      procedure Push_Packet
        (Packet : in out Buffer_Type;
         Status : out Error_Code);
      --  Push the packet over IP

      procedure Process_Ack (Packet : Net.Buffers.Buffer_Type);
      --  Process received ack in the packet

      procedure Send_Window_Probe;

      procedure Retransmit_Timeout;

      procedure Call_Callback (Event : Tcp_Event);

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
     with Priority => Priority
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

   State_To_List : constant array (Socket_State_Kind) of
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
         Send_Next_Control       := 0;
         Sequence_Last_Update    := 0;
         Ask_Last_Update         := 0;
         Receive_Window          := 0;
         Next_Sequence_Num       := 0;
         Receive_Next            := 0;
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
         Release (Received_Queue);
      end Init;

      ---------------
      -- Get_State --
      ---------------

      function Get_State return Socket_State_Kind is
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
         Status : out Error_Code) is
      begin
         if Socket = null
           or else Socket = This
         then
            Status := EOK;
            Init;
            Socket     := This;
            Local_Addr := Ifnet.Ip;
            Local_Port := Port;
         else
            Status := ENOBUFS;
         end if;
      end Bind;

      -------------
      -- Connect --
      -------------

      procedure Connect
        (Addr   : Ip_Addr;
         Port   : Uint16;
         Status : out Error_Code) is
      begin
         Remote_Addr         := Addr;
         Remote_Port         := Port;

         Init_Sequence_Num   := Net.Utils.Random;
         Next_Sequence_Num   := Init_Sequence_Num;
         Send_Unacknowledged := Init_Sequence_Num - 1;
         Send_Next_Control   := Init_Sequence_Num;

         Receive_Window      := Uint16'Min
           (Default_TCP_Window,
            Uint16
              (Net.Buffers.Packets_Count / 2 / Uint32 (Max_Sockets_Count)) *
                Max_Packet_Size);
         Send_Window         := Initial_Send_Window;
         Cwnd                := Initial_Send_Window;

         Set_State (Syn_Sent);

         pragma Assert (Is_Empty (Send_Queue));

         Send_Control (Syn => True, Fin => False, Status => Status);

      exception
         when others =>
            Status := ENOBUFS;
      end Connect;

      ----------
      -- Send --
      ----------

      procedure Send
        (Data   : Net.Buffers.Buffer_Type;
         Push   : Boolean;
         Status : out Error_Code) is
      begin
         case State is
            when Established | Close_Wait | Syn_Sent | Syn_Received =>
               Enqueue
                 (Data   => Data,
                  Push   => Push,
                  Syn    => False,
                  Fin    => False,
                  Ack    => False,
                  Status => Status);
            when others =>
               Status := ENOBUFS;
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
         Has_More : out Boolean) is
      begin
         if Is_Empty (Received_Queue) then
            Has_More := False;
         else
            Peek (Received_Queue, Data);
            Receive_Window := Receive_Window +
              Get_Data_Size (Data, RAW_PACKET);
            Has_More := not Is_Empty (Received_Queue);
         end if;
      end Receive;

      ----------------------
      -- Get_Receive_Room --
      ----------------------

      function Get_Receive_Room return Uint16 is
      begin
         return Receive_Window;
      end Get_Receive_Room;

      -----------
      -- Close --
      -----------

      procedure Close (Status : out Error_Code) is

         ---------
         -- Fin --
         ---------

         procedure Fin (State : Socket_State_Kind);
         procedure Fin (State : Socket_State_Kind) is
         begin
            Send_Control (Syn => False, Fin => True, Status => Status);
            Set_State (State);
         end Fin;

      begin
         --  Except when the current PCB state is Closed already, we rely on
         --  Set_State to perform the necessary list operations.

         case State is
            when Closed =>
               null; -- Can't happen

            when Syn_Sent =>
               Set_State (Closed);
               Status := EOK;

            when Syn_Received | Established =>
               --  Transition to FIN_WAIT_1 after sending FIN
               Fin (Fin_Wait_1);

            when Close_Wait =>
               --  Transition to LAST_ACK after sending FIN
               Fin (Last_Ack);

            when others =>
               Status := EOK;
         end case;
      end Close;

      ----------
      -- Drop --
      ----------

      procedure Drop (Status : out Error_Code) is
      begin
         --  Send RST
         Send_Rst
           (Ack      => True,
            Seq_Num  => Send_Next_Control,
            Ack_Num  => Receive_Next,
            Status   => Status);

         Set_State (Closed);
      end Drop;

      ---------------
      -- Set_State --
      ---------------

      procedure Set_State (New_State : Socket_State_Kind)
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

            Call_Callback ((Kind => Tcp_Event_State, State => New_State));
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
         Status : out Error_Code)
      is
         Empty : Buffer_Type;
      begin
         Enqueue
           (Data   => Empty,
            Push   => False,
            Syn    => Syn,
            Fin    => Fin,
            Ack    => not Syn and then not Fin,
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
         Ack    : Boolean;
         Status : out Error_Code)

      is
         Num        : Uint32;
         Len        : Uint16 := 0;
         Queue      : Buffer_List;
         Packet     : Buffer_Type;
         Left       : Uint16 := 0;
         Pos        : Uint16 := 0;
         Tcp_Header : Net.Headers.TCP_Header_Access;

      begin
         Status := ENOBUFS;

         pragma Assert (not (Syn and Fin));

         if not Data.Is_Null then
            Left := Get_Data_Size (Data, RAW_PACKET);
         end if;

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
               Pos  := Pos  + Remote_MSS;
               Len  := Len  + Remote_MSS;
               Left := Left - Remote_MSS;

            elsif Left > 0 then
               Copy (Packet, Data, Pos, Pos + Left - 1);
               Len  := Len + Left;
               Left := 0;
            end if;

            --  Fill TCP header fields
            Tcp_Header          := Packet.TCP;
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

            if State = Syn_Sent
              and then Tcp_Header.Th_Flags = Th_Flags_Syn
            then
               --  The first SYN, add MSS Option
               Put_Uint8  (Packet, TCP_Option_MSS);
               Put_Uint8  (Packet, 4);
               Put_Uint16 (Packet, Max_Packet_Size);
               Tcp_Header.Th_Off := 96;
            end if;

            --  Use temporary queue to ensure that we have enought memory
            --  for all chunks
            Set_Length (Packet, Get_Data_Size (Packet, RAW_PACKET));
            Append (Queue, Packet);

            Num := Num + Uint32 (Len);
            exit when Left = 0;
         end loop;

         if Syn or else Fin then
            Num := Num + 1;
         end if;

         --  Push the temporary queue on the Send_Queue for later processing
         --  by Process_Send_Queue.
         if not Is_Empty (Queue) then
            Transfer (To => Send_Queue, From => Queue);
         end if;

         --  Update next sequence number for stream since we added all data
         --  in the queue
         Next_Sequence_Num := Num;

         Process_Send_Queue (Ack_Now => Ack, Status => Status);

      exception
         when others =>
            Release (Queue);
            Release (Packet);
      end Enqueue;

      ------------------------
      -- Process_Send_Queue --
      ------------------------

      procedure Process_Send_Queue
        (Ack_Now : Boolean;
         Status  : out Error_Code)
      is
         ACK_Sent   : Boolean := False;
         Window     : constant Uint32 := Uint32'Min
           (Cwnd, Uint32 (Send_Window));
         Packet     : Buffer_Type;
         Tcp_Header : TCP_Header_Access;
         Num        : Uint32;
         Size       : Uint32;

      begin
         while not Is_Empty (Send_Queue) loop
            --  We still have packets to send

            --  Get the first segment from Send_Queue
            Peek (Send_Queue, Packet);
            Tcp_Header := Packet.TCP;

            --  Get segment data
            Num  := Tcp_Header.Th_Seq;
            Size := Uint32 (TCP_Data_Length (Packet, Tcp_Header));

            --  Check that we will not cross the Remote_Window
            if Size > Send_Unacknowledged + Window then
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
            if Send_Next_Control < Num + Size then
               Send_Next_Control := Num + Size;
            end if;
         end loop;

         --  Send an empty ACK segment if needed
         if Ack_Now
           and then not ACK_Sent
         then
            declare
               Ack_Packet : Buffer_Type;
            begin
               Allocate (Ack_Packet);
               if not Ack_Packet.Is_Null then
                  Set_Type (Ack_Packet, TCP_PACKET);

                  Tcp_Header          := Ack_Packet.TCP;
                  Tcp_Header.Th_Seq   := Send_Next_Control;
                  Tcp_Header.Th_Ack   := 0;
                  Tcp_Header.Th_Off   := TCP_Header_Net_Octets;
                  Tcp_Header.Th_Flags := Th_Flags_Ack;

                  Push_Packet (Ack_Packet, Status);
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
         Local : Buffer_Type;

      begin
         Allocate (Local);
         if Is_Null (Local) then
            Insert (Send_Queue, Packet);
            Status := ENOBUFS;
            return;
         end if;

         Copy (From => Packet, To => Local);

         Push_Packet (Packet, Status);

         if Status in ENOBUFS .. ENETUNREACH then
            --  Did not send, return segment to the Send_Queue
            Insert (Send_Queue, Local);
         else
            --  Initialize retransmitting data
            if Retransmitting_Sequence = 0
              or else Retransmitting_Sequence < Local.TCP.Th_Seq
            then
               Retransmitting_Sequence := Local.TCP.Th_Seq;
               Retransmitting_Ticks    := Timeouts_Ticks_Count;
            end if;

            --  Start retransmit timer if not already running
            if Retransmit_Ticks < 0 then
               Retransmit_Ticks := 0;
            end if;

            --  Append segment to the Unack_Queue
            Append (Unack_Queue, Local);
         end if;

      exception
         when others =>
            if not Is_Null (Local) then
               Insert (Send_Queue, Local);
            end if;
      end Send_Packet;

      -----------------
      -- Push_Packet --
      -----------------

      procedure Push_Packet
        (Packet : in out Buffer_Type;
         Status : out Error_Code)
      is
         Tcp_Header    : TCP_Header_Access;
         Pseudo_Header : TCP_Pseudo_Header;

      begin
         Set_Length (Packet, Get_Data_Size (Packet, RAW_PACKET));

         Tcp_Header          := Packet.TCP;
         Tcp_Header.Th_Sport := Local_Port;
         Tcp_Header.Th_Dport := Remote_Port;

         --  Fill in the ACK number field and advertise our receiving
         --  window size
         if (Tcp_Header.Th_Flags and Th_Flags_Ack) > 0 then
            Tcp_Header.Th_Ack := Receive_Next;
         end if;
         Tcp_Header.Th_Win := Receive_Window;
         Tcp_Header.Th_Urp := 0;

         --  Convert header data to network order --
         To_Network (Tcp_Header);

         --  Create Pseudo_Header for checksum calculation --
         Pseudo_Header.Source_IP      := Local_Addr;
         Pseudo_Header.Destination_IP := Remote_Addr;
         Pseudo_Header.Zero           := 0;
         Pseudo_Header.Protocol       := Net.Protos.IPv4.P_TCP;
         Pseudo_Header.TCP_Length     := To_Network
           (Get_Data_Size (Packet, IP_PACKET));

         --  Compute checksum --
         Tcp_Header.Th_Sum := 0;
         Tcp_Header.Th_Sum := Net.Utils.TCP_Checksum (Pseudo_Header, Packet);

         Net.Protos.IPv4.Make_Header
           (Packet.IP,
            Local_Addr,
            Remote_Addr,
            Net.Protos.IPv4.P_TCP,
            Get_Data_Size (Packet, Net.Buffers.ETHER_PACKET));
         Net.Protos.IPv4.Send_Raw (Ifnet, Remote_Addr, Packet, Status);
      end Push_Packet;

      --------------
      -- Received --
      --------------

      procedure Received
        (Packet    : in out Net.Buffers.Buffer_Type;
         Length    : Uint16;
         Processed : out Boolean)
      is
         Packet_IP  : constant IP_Header_Access  := Packet.IP;
         Packet_TCP : constant TCP_Header_Access := Packet.TCP;
         Status     : Error_Code;

         procedure Setup_Flow_Control;
         --  Shared processing between passive and active open: once the
         --  remote MSS is known, set up the congestion window and other
         --  flow control parameters.

         procedure Teardown (Callback : Boolean);
         --  Tear down the current connection, notify user if Callback is True

         ------------------------
         -- Setup_Flow_Control --
         ------------------------

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

            function Get_Option return Uint8;
            procedure Check_Option_Length (Len : Uint8);

            ----------------
            -- Get_Option --
            ----------------

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
                           Option_Offset := Option_Offset +
                             Uint16 (Length) - 2;
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

         procedure Teardown (Callback : Boolean) is
         begin
            if Callback then
               Call_Callback ((Kind => Tcp_Event_Abort));
            end if;
            Set_State (Closed);
         end Teardown;

         Win_L, Win_R : Uint32;
         --  Left and right edges of receive window
         Data_Len     : Uint16;
         --  Length of non-duplicate data in segment

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

         if State = Syn_Sent then
            if (Packet_TCP.Th_Flags and Th_Flags_Ack) > 0 then
               --  Reject if ACK not in range
               if not (Init_Sequence_Num <= Packet_TCP.Th_Ack - 1
                       and then Packet_TCP.Th_Ack - 1 < Send_Next_Control)
               then
                  if (Packet_TCP.Th_Flags and Th_Flags_Rst) = 0 then
                     Send_Rst
                       (Ack     => False,
                        Seq_Num => Packet_TCP.Th_Ack,
                        Ack_Num => 0,
                        Status  => Status);
                  end if;
                  return;
               end if;
            end if;

            if (Packet_TCP.Th_Flags and Th_Flags_Rst) > 0 then
               if (Packet_TCP.Th_Flags and Th_Flags_Ack) > 0 then
                  --  Connection refused
                  Teardown (True);
               end if;

               return;
            end if;

            if (Packet_TCP.Th_Flags and Th_Flags_Syn) > 0 then
               Setup_Flow_Control;

               Init_Recive_Num := Packet_TCP.Th_Seq;
               Receive_Next    := Init_Recive_Num + 1;

               if (Packet_TCP.Th_Flags and Th_Flags_Ack) > 0 then
                  Process_Ack (Packet);
               end if;

               if Send_Unacknowledged > Init_Sequence_Num then
                  Send_Control
                    (Syn    => False,
                     Fin    => False,
                     Status => Status);
                  Set_State (Established);

               else
                  Set_State (Syn_Received);
                  Send_Control
                    (Syn    => True,
                     Fin    => False,
                     Status => Status);
               end if;
            end if;

         else
            --  Check sequence number
            Win_L := Receive_Next;
            Win_R := Receive_Next + Uint32 (Receive_Window);

            if not
              ((Receive_Window = 0
                and then Packet_TCP.Th_Seq = Receive_Next)
               or else
                 (Win_L <= Packet_TCP.Th_Seq
                  and then Packet_TCP.Th_Seq < Win_R)
               or else
                 (Win_L <= Packet_TCP.Th_Seq + Uint32 (Length) - 1
                  and then Packet_TCP.Th_Seq + Uint32 (Length) - 1 <
                      Win_R))
            then
               --  Segment is not acceptable: send ACK
               --  (unless RST is present).

               if (Packet_TCP.Th_Flags and Th_Flags_Rst) = 0 then
                  Send_Control
                    (Syn    => False,
                     Fin    => False,
                     Status => Status);
               end if;
               return;

            else
               --  Here if segment is acceptable

               --  Check RST bit
               if (Packet_TCP.Th_Flags and Th_Flags_Rst) > 0 then
                  Teardown (State in Established .. Close_Wait);
                  return;
               end if;
            end if;

            --  Check SYN bit
            if (Packet_TCP.Th_Flags and Th_Flags_Syn) > 0 then
               --  SYN is in the window: error, tear down connection
               Teardown (True);
               return;
            end if;

            --  Check ACK field
            if (Packet_TCP.Th_Flags and Th_Flags_Ack) = 0 then
               return;
            end if;

            if State = Syn_Received then
               if Send_Unacknowledged <= Packet_TCP.Th_Ack
                 and then Packet_TCP.Th_Ack < Send_Next_Control + 1
               then
                  Set_State (Established);
               else
                  Send_Rst
                    (Ack     => False,
                     Seq_Num => Packet_TCP.Th_Ack,
                     Ack_Num => 0,
                     Status  => Status);
                  Teardown (False);
                  return;
               end if;
            end if;

            case State is
               when Syn_Received =>
                  --  Can't happen, processed previously
                  null;

               when Established | Fin_Wait_1 | Fin_Wait_2 =>
                  Process_Ack (Packet);

                  if Packet_TCP.Th_Seq < Receive_Next then
                     --  Drop head of segment that was already received

                     Data_Len := Length -
                       Uint16 (Receive_Next - Packet_TCP.Th_Seq);

                  else
                     Data_Len := Length;
                  end if;

                  Receive_Next := Packet_TCP.Th_Seq + Uint32 (Data_Len);

                  if (Packet_TCP.Th_Flags and Th_Flags_Fin) > 0 then
                     --  Dec 1 if the packet has FIN
                     Data_Len := Data_Len - 1;
                  end if;

                  if Data_Len < Receive_Window then
                     Receive_Window := Receive_Window - Data_Len;

                  else
                     Receive_Window := 0;
                  end if;

                  if Data_Len > 0 then
                     --  Store raw data in the recive list
                     Packet.Delete_Headers (Packet.Get_Length - Data_Len);
                     Append (Received_Queue, Packet);
                     Call_Callback ((Kind => Tcp_Event_Recv));
                  end if;
                  Process_Send_Queue (Ack_Now => False, Status => Status);

               when others =>
                  --  Ignore urgent pointer and segment text
                  null;
            end case;

            --  Check FIN bit
            if (Packet_TCP.Th_Flags and Th_Flags_Fin) > 0 then
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
                     --  -> FIN, <-ACK, <-FIN so now we have to send ACK and
                     --  close the socket
                     Send_Control (False, False, Status);
                     Set_State (Closed);

                  when Close_Wait | Closing | Last_Ack =>
                     null;

                  when Time_Wait =>
                     --  Restart 2MSL timeout
                     Watchdog_Ticks := Timeouts_Ticks_Count;
               end case;
            end if;
         end if;
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
         Status     : Error_Code;

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

            pragma Assert (Packet_TCP.Th_Ack <= Send_Next_Control);

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
                 (Uint16 (Timeouts_Ticks_Count - Retransmitting_Ticks));
               Retransmitting_Ticks := 0;
            end if;

            --  Purge entirely acked segments
            while not Is_Empty (Unack_Queue) loop
               Peek (Unack_Queue, Prev);

               Prev_TCP := Prev.TCP;
               Length   := TCP_Data_Length (Prev, Prev_TCP);

               if Prev_TCP.Th_Seq + Uint32 (Length) > Packet_TCP.Th_Ack then
                  Insert (Unack_Queue, Prev);
                  exit;
               end if;

               --  Packet entirely acked: notify user and remove from queue.
               --  Note: For a segment carrying a FIN, we do not signal it sent
               --  if the ack covers all of the data but not the FIN flag.

               Call_Callback ((Kind => Tcp_Event_Sent));

               if (Prev_TCP.Th_Flags and Th_Flags_Fin) > 0 then
                  case State is
                     when Fin_Wait_1 =>
                        --  FIN sent, have ACK so we are in Fin_Wait_2
                        Set_State (Fin_Wait_2);

                        --  Start Fin_Wait_2 timeout
                        Watchdog_Ticks := Timeouts_Ticks_Count;

                     when Closing =>
                        Set_State (Time_Wait);

                        --  Start 2MSL timeout
                        Watchdog_Ticks := Timeouts_Ticks_Count;

                     when Last_Ack =>
                        Set_State (Closed);

                     when Time_Wait =>
                        --  Have FIN, send ACK
                        Send_Control
                          (Syn    => False,
                           Fin    => False,
                           Status => Status);

                        --  Restart 2MSL timeout
                        Watchdog_Ticks := Timeouts_Ticks_Count;

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
             and then Timeouts_Ticks_Count - Watchdog_Ticks > Fin_Wait_Timeout)
           or else
             (State = Syn_Received
              and then Timeouts_Ticks_Count - Watchdog_Ticks >
                Syn_Received_Timeout)
           or else
             (State = Last_Ack
              and then Timeouts_Ticks_Count - Watchdog_Ticks > Time_Wait_Timeout)
         then
            Remove := True;

         else
            --  Persist timer: send window probe
            if Persist_Backoff > 0 then
               Persist_Ticks := Persist_Ticks + 1;

               if Persist_Ticks >= Persist_Backoff then
                  Persist_Ticks := 0;

                  --  Double persist backoff up to Max_Persist_Backoff
                  Persist_Backoff := Int32'Min
                    (Maximum_Persist_Backoff, Persist_Backoff * 2);

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
                     --  Syn_Sent: no backoff, Maximum_SYN_Retransmits limit
                     if Retransmit_Count > Maximum_SYN_Retransmits then
                        Remove := True;
                     end if;

                  else
                     --  All other cases: exponential backoff,
                     --  Maximum_Retransmits limit
                     if Retransmit_Count > Maximum_Retransmits then
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
            Call_Callback ((Kind => Tcp_Event_Abort));
            Set_State (Closed);
         end if;
      end Check_Timeouts;

      ---------------------
      -- Check_Time_Wait --
      ---------------------

      procedure Check_Time_Wait is
      begin
         if Timeouts_Ticks_Count - Watchdog_Ticks > Time_Wait_Timeout then
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
            Duplicate_First (Unack_Queue, Packet);

         elsif not Is_Empty (Send_Queue) then
            Duplicate_First (Send_Queue, Packet);
         end if;

         if Is_Null (Packet) then
            return;
         end if;

         Packet_TCP := Packet.TCP;
         Length     := TCP_Data_Length (Packet, Packet_TCP);

         Probe_Fin := (Packet_TCP.Th_Flags and Th_Flags_Fin) > 0
           and then Length = 1;

         Allocate (Probe);
         if not Is_Null (Probe) then
            Set_Type (Probe, TCP_PACKET);

            Probe_TCP        := Probe.TCP;
            Probe_TCP.Th_Seq := Packet_TCP.Th_Seq;
            Probe_TCP.Th_Ack := 0;
            Probe_TCP.Th_Off := TCP_Header_Net_Octets;
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

            Push_Packet (Probe, Status);
         end if;

      exception
         when others =>
            Release (Probe);
      end Send_Window_Probe;

      ------------------------
      -- Retransmit_Timeout --
      ------------------------

      procedure Retransmit_Timeout
      is
         Status : Error_Code;
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
         Process_Send_Queue (Ack_Now => False, Status => Status);
      end Retransmit_Timeout;

      --------------
      -- Send_Rst --
      --------------

      procedure Send_Rst
        (Ack     : Boolean;
         Seq_Num : Uint32;
         Ack_Num : Uint32;
         Status  : out Error_Code)
      is
         Packet     : Buffer_Type;
         TCP_Header : TCP_Header_Access;

      begin
         Status := ENOBUFS;

         Allocate (Packet);
         if Is_Null (Packet) then
            return;
         end if;

         Set_Type (Packet, TCP_PACKET);
         TCP_Header := Packet.TCP;

         TCP_Header.Th_Dport := Remote_Port;
         TCP_Header.Th_Sport := Local_Port;
         TCP_Header.Th_Seq   := Seq_Num;
         TCP_Header.Th_Ack   := Ack_Num;
         TCP_Header.Th_Off   := TCP_Header_Net_Octets;
         if Ack then
            TCP_Header.Th_Flags := Th_Flags_Ack or Th_Flags_Rst;
         else
            TCP_Header.Th_Flags := Th_Flags_Rst;
         end if;
         TCP_Header.Th_Win := 0;
         TCP_Header.Th_Sum := 0;
         TCP_Header.Th_Urp := 0;

         Set_Length (Packet, Get_Data_Size (Packet, RAW_PACKET));

         Net.Protos.IPv4.Make_Header
           (Packet.IP,
            Local_Addr,
            Remote_Addr,
            Net.Protos.IPv4.P_TCP,
            Get_Data_Size (Packet, Net.Buffers.ETHER_PACKET));
         Net.Protos.IPv4.Send_Raw (Ifnet, Remote_Addr, Packet, Status);

      exception
         when others =>
            Release (Packet);
      end Send_Rst;

      -------------------
      -- Call_Callback --
      -------------------

      procedure Call_Callback (Event : Tcp_Event) is
      begin
         if Socket /= null
           and then Socket.Callback /= null
         then
            Socket.Callback (Socket, Event);
         end if;
      end Call_Callback;

   end State_Protected_Object;

   ----------
   -- Bind --
   ----------

   procedure Bind
     (This   : in out Socket;
      Port   : Uint16;
      Status : out Error_Code) is
   begin
      Status := ENOBUFS;

      if This.State_No = 0 then
         for Index in 1 .. Max_Sockets_Count loop
            States (Index).Bind (This.Self, Port, Status);
            if Status = EOK then
               This.State_No := Index;
               exit;
            end if;
         end loop;
      else
         States (This.State_No).Bind (This.Self, Port, Status);
      end if;
   end Bind;

   -------------
   -- Connect --
   -------------

   procedure Connect
     (This   : in out Socket;
      Addr   : Ip_Addr;
      Port   : Uint16;
      Status : out Error_Code) is
   begin
      States (This.State_No).Connect (Addr, Port, Status);
   end Connect;

   --------------
   -- Received --
   --------------

   procedure Received
     (This      : Socket_Access;
      Packet    : in out Net.Buffers.Buffer_Type;
      Length    : Uint16;
      Processed : out Boolean) is
   begin
      States (This.State_No).Received (Packet, Length, Processed);
   end Received;

   --------------------
   -- Check_Timeouts --
   --------------------

   procedure Check_Timeouts (This : Socket_Access) is
   begin
      States (This.State_No).Check_Timeouts;
   end Check_Timeouts;

   ---------------------
   -- Check_Time_Wait --
   ---------------------

   procedure Check_Time_Wait (This : Socket_Access) is
   begin
      States (This.State_No).Check_Time_Wait;
   end Check_Time_Wait;

   ---------------
   -- Get_State --
   ---------------

   function Get_State (This : Socket) return Socket_State_Kind is
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
      Status : out Error_Code) is
   begin
      if Is_Null (Data) or else Get_Data_Size (Data, RAW_PACKET) = 0 then
         Status := ENOBUFS;
      else
         States (This.State_No).Send (Data, Push, Status);
      end if;
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
      States (This.State_No).Receive (Data, Has_More);
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
      Status : out Error_Code) is
   begin
      if This.State_No /= 0 then
         States (This.State_No).Close (Status);
      end if;
   end Close;

   ----------
   -- Drop --
   ----------

   procedure Drop
     (This   : in out Socket;
      Status : out Error_Code) is
   begin
      States (This.State_No).Drop (Status);
   end Drop;

   ------------------
   -- Set_Callback --
   ------------------

   procedure Set_Callback
     (This     : in out Socket;
      Callback : Callback_Procedure) is
   begin
      This.Callback := Callback;
   end Set_Callback;

   --------------
   -- Received --
   --------------

   procedure Received
     (Ifnet  : in out Net.Interfaces.Ifnet_Type'Class;
      Packet : in out Net.Buffers.Buffer_Type)
   is
      pragma Unreferenced (Ifnet);

      Data_Length   : Uint16;
      Packet_IP     : constant IP_Header_Access  := Packet.IP;
      Packet_TCP    : constant TCP_Header_Access := Packet.TCP;
      Pseudo_Header : TCP_Pseudo_Header;
      Data_Offset   : Uint16;
      Processed     : Boolean := False;

      Ack              : Boolean;
      Seq_Num, Ack_Num : Uint32;
      Status           : Error_Code;

   begin
      Net.Protos.IPv4.To_Host (Packet_IP);

      Data_Length := Packet_IP.Ip_Len - IP_Header_Length (Packet_IP);

      --  Verify TCP checksum
      if Packet_TCP.Th_Sum /= 0 then
         Pseudo_Header.Source_IP      := Packet_IP.Ip_Src;
         Pseudo_Header.Destination_IP := Packet_IP.Ip_Dst;
         Pseudo_Header.Zero           := 0;
         Pseudo_Header.Protocol       := Net.Protos.IPv4.P_TCP;
         Pseudo_Header.TCP_Length     := To_Network (Data_Length);

         if not Net.Utils.Check_TCP_Checksum (Pseudo_Header, Packet) then
            --  Not valid checksum, do not process the packet
            return;
         end if;
      end if;

      --  Convert to host's byte order --
      To_Host (Packet_TCP);

      Data_Offset := TCP_Header_Length (Packet_TCP);

      Data_Length := Data_Length - Data_Offset +
        (if (Packet_TCP.Th_Flags and Th_Flags_Syn) > 0 then 1 else 0) +
        (if (Packet_TCP.Th_Flags and Th_Flags_Fin) > 0 then 1 else 0);

      --  Get copy of active socets
      Reestr.Get_List_Copy (Active);

      for Idx in 1 .. Processing_Sockets.Last loop
         Received
           (This      => Processing_Sockets.List (Idx),
            Packet    => Packet,
            Length    => Data_Length,
            Processed => Processed);
         exit when Processed;
      end loop;

      if not Processed then
         if (Packet_TCP.Th_Flags and Th_Flags_Rst) > 0 then
            --  Discard incoming RST without associated socket
            null;

         else
            --  Calculate logical TCP segment length, including the data payload,
            --  as well as the SYN and FIN flags.

            if (Packet_TCP.Th_Flags and Th_Flags_Ack) = 0 then
               Seq_Num := 0;
               Ack_Num := Packet_TCP.Th_Seq + Uint32 (Data_Length);
               Ack     := True;
            else
               Seq_Num := Packet_TCP.Th_Ack;
               Ack_Num := 0;
               Ack     := False;
            end if;

            Send_Rst_Flag
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

   -------------------
   -- Send_Rst_Flag --
   -------------------

   procedure Send_Rst_Flag
     (Src_IP   : Ip_Addr;
      Src_Port : Uint16;
      Dst_IP   : Ip_Addr;
      Dst_Port : Uint16;
      Ack      : Boolean;
      Seq_Num  : Uint32;
      Ack_Num  : Uint32;
      Status   : out Error_Code)
   is
      Packet     : Buffer_Type;
      TCP_Header : TCP_Header_Access;

   begin
      Status := ENOBUFS;

      Allocate (Packet);
      if Is_Null (Packet) then
         return;
      end if;

      Set_Type (Packet, TCP_PACKET);
      TCP_Header := Packet.TCP;

      TCP_Header.Th_Dport := Dst_Port;
      TCP_Header.Th_Sport := Src_Port;
      TCP_Header.Th_Seq   := Seq_Num;
      TCP_Header.Th_Ack   := Ack_Num;
      TCP_Header.Th_Off   := TCP_Header_Net_Octets;
      if Ack then
         TCP_Header.Th_Flags := Th_Flags_Ack or Th_Flags_Rst;
      else
         TCP_Header.Th_Flags := Th_Flags_Rst;
      end if;
      TCP_Header.Th_Win := 0;
      TCP_Header.Th_Sum := 0;
      TCP_Header.Th_Urp := 0;

      Set_Length (Packet, Get_Data_Size (Packet, RAW_PACKET));

      Net.Protos.IPv4.Make_Header
        (Packet.IP,
         Src_IP,
         Dst_IP,
         Net.Protos.IPv4.P_TCP,
         Get_Data_Size (Packet, Net.Buffers.RAW_PACKET) - 14);
      Net.Protos.IPv4.Send_Raw (Ifnet, Dst_IP, Packet, Status);

   exception
      when others =>
         Release (Packet);
   end Send_Rst_Flag;

   --------------------
   -- Check_Timeouts --
   --------------------

   procedure Check_Timeouts is
   begin
      Timeouts_Ticks_Count := Timeouts_Ticks_Count + 1;

      Reestr.Get_List_Copy (Active);

      for Pos in 1 .. Processing_Sockets.Last loop
         Check_Timeouts (Processing_Sockets.List (Pos));
      end loop;

      --  Check Time_Wait list
      Reestr.Get_List_Copy (Time_Wait);
      for Pos in 1 .. Processing_Sockets.Last loop
         Check_Time_Wait (Processing_Sockets.List (Pos));
      end loop;
   end Check_Timeouts;

   ---------------------
   -- TCP_Data_Length --
   ---------------------

   function TCP_Data_Length
     (Packet : Net.Buffers.Buffer_Type;
      Header : Net.Headers.TCP_Header_Access)
      return Uint16 is
   begin
      return Get_Data_Size (Packet, IP_PACKET) -
        TCP_Header_Length (Header) +
        (if (Header.Th_Flags and Th_Flags_Syn) > 0 then 1 else 0) +
        (if (Header.Th_Flags and Th_Flags_Fin) > 0 then 1 else 0);
   end TCP_Data_Length;

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
