pragma Profile (Ravenscar);

with Ada.Real_Time; use Ada.Real_Time;
with Ada.Text_IO;
with Ada.Command_Line;

with Net;          use Net;
with Net.Buffers;
with Net.Protos.Arp;
with Tap_TCP;

procedure TCP_Client is
   use Tap_TCP.Sockets;

   Timeout_Delay : constant Ada.Real_Time.Time_Span :=
     Ada.Real_Time.Microseconds (1000);
   T             : Ada.Real_Time.Time;

   Status   : Net.Error_Code;
   Data     : Net.Buffers.Buffer_Type; --  Raw data
   Has_More : Boolean;

   type Stage_Kind is (Connect, Send, Reveive, Closing, Close);
   Stage : Stage_Kind := Connect;

begin
   Ada.Text_IO.Put_Line ("Boot");

   Tap_TCP.Initialize;

   Tap_TCP.Tap.Ip := (192, 168, 68, 117);
   Tap_TCP.Tap.Create (Tap => "tap0");
   delay until Ada.Real_Time.Clock + Ada.Real_Time.Seconds (2);

   Bind (Tap_TCP.Socket, 9095, Status);
   pragma Assert (Status not in ENOBUFS .. ENETUNREACH);

   Tap_TCP.LAN_Receiver.Start;

   --  $>sudo ip tuntap add mode tap tap0
   --  $>sudo ip link set dev tap0 up
   --  $>sudo ip address add 192.168.68.116/24 dev tap0
   --  $>netcat -4 -v -l -s 192.168.68.116 -p 9090

   Connect (Tap_TCP.Socket, (192, 168, 68, 116), 9090, Status);
   pragma Assert (Status not in ENOBUFS .. ENETUNREACH);

   T := Ada.Real_Time.Clock + Timeout_Delay;

   Main_Loop : loop
      case Stage is
         when Connect =>
            case Get_State (Tap_TCP.Socket) is
               when Syn_Sent .. Syn_Received =>
                  --  Still connecting
                  null;

               when Established =>
                  --  Connected
                  Ada.Text_IO.Put_Line ("Connected");
                  if Ada.Command_Line.Argument_Count = 0 then
                     Stage := Send;
                  else
                     Stage := Reveive;
                  end if;

               when Closed =>
                  exit Main_Loop;

               when others =>
                  --  Something wrong, waiting when the socket will be closed
                  null;
            end case;

         when Send =>
            pragma Assert (Get_State (Tap_TCP.Socket) = Established);

            Net.Buffers.Allocate (Data);
            Data.Put_String ("Hello");
            Send (Tap_TCP.Socket, Data, False, Status);
            Net.Buffers.Release (Data);
            pragma Assert (Status not in ENOBUFS .. ENETUNREACH);

            --  restart timer after send
            T := Ada.Real_Time.Clock + Timeout_Delay;

            Ada.Text_IO.Put_Line ("Send");
            Stage := Closing;

         when Reveive =>
            pragma Assert (Get_State (Tap_TCP.Socket) = Established);

            Receive (Tap_TCP.Socket, Data, Has_More);
            if not Data.Is_Null then
               Ada.Text_IO.Put_Line ("Reveived");
               declare
                  S : String (1 .. Integer (Data.Get_Length));
               begin
                  Data.Get_String (S);
                  pragma Assert (S = "Hello");
               end;
               Net.Buffers.Release (Data);
               Stage := Closing;
            end if;

         when Closing =>
            Ada.Text_IO.Put_Line ("Closing");
            Close (Tap_TCP.Socket, Status);
            pragma Assert (Status not in ENOBUFS .. ENETUNREACH);

            --  restart timer after send FIN+ACK
            T := Ada.Real_Time.Clock + Timeout_Delay;

            Stage := Close;

         when Close =>
            exit Main_Loop when Get_State (Tap_TCP.Socket) = Closed;
      end case;

      if T < Ada.Real_Time.Clock then
         T := T + Timeout_Delay;

         Net.Protos.Arp.Timeout (Tap_TCP.Tap);
         Tap_TCP.Sockets.Check_Timeouts;
      end if;
   end loop Main_Loop;
   Ada.Text_IO.Put_Line ("Closed");
end TCP_Client;
