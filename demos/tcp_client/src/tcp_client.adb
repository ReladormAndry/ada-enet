pragma Profile (Ravenscar);

with Ada.Real_Time; use Ada.Real_Time;
with Ada.Text_IO;
with Ada.Streams;
with Ada.Command_Line;
with GNAT.Random_Numbers;

with Net.Buffers;
with Net.Protos.Arp;
with Net.Utils;

with Tap_TCP;

procedure TCP_Client is
   use Tap_TCP.Sockets;

   Socket        : Tap_TCP.Sockets.Socket;
   Status        : Status_Kind;
   Event         : Tcp_Event_Kind;

   Buffer_Memory : Ada.Streams.Stream_Element_Array (1 .. 1_024_000);
   Random        : GNAT.Random_Numbers.Generator;

   function Get_Random return Net.Uint32;

   ----------------
   -- Get_Random --
   ----------------

   function Get_Random return Net.Uint32 is
   begin
      return GNAT.Random_Numbers.Random (Random);
   end Get_Random;

begin
   Ada.Text_IO.Put_Line ("Boot");

   Net.Buffers.Add_Region
     (Addr => Buffer_Memory'Address,
      Size => Buffer_Memory'Length);

   GNAT.Random_Numbers.Reset (Random);
   Net.Utils.Set_Random_Function (Get_Random'Unrestricted_Access);

   Initialize;

   Tap_TCP.INet.Ip := (192, 168, 68, 117);
   declare
      Argument : constant String :=
        (if Ada.Command_Line.Argument_Count = 0 then "tap0"
         else Ada.Command_Line.Argument (1));
   begin
      Tap_TCP.INet.Create (Tap => Argument);
      delay until Ada.Real_Time.Clock + Ada.Real_Time.Seconds (2);
   end;

   Watchdog.Start;

   Bind (Socket, 9095, Tap_TCP.Callback'Access, Status);
   pragma Assert (Status = Ok);

   Net.Protos.Arp.Timeout (Tap_TCP.INet);

   --  $>sudo ip tuntap add mode tap tap0
   --  $>sudo ip link set dev tap0 up
   --  $>sudo ip address add 192.168.68.116/24 dev tap0
   Connect (Socket, (192, 168, 68, 116), 9090, Status);
   pragma Assert (Status = Ok);

   --  Wait until connection has been established
   while Get_State (Socket) in Closed .. Syn_Received loop
      Ada.Text_IO.Put_Line (Get_State (Socket)'Img);
      Tap_TCP.Watchdog.Wait (Event);
      Ada.Text_IO.Put_Line (Event'Img);
      pragma Assert (Event = Tcp_Event_State);
   end loop;
   pragma Assert (Get_State (Socket) = Established);

   Ada.Text_IO.Put_Line ("Connected");

   Close (Socket, Status);
   pragma Assert (Status = Ok);

   --  Wait until connection has been closed
   while Get_State (Socket) /= Closed loop
      Ada.Text_IO.Put_Line (Get_State (Socket)'Img);
      Tap_TCP.Watchdog.Wait (Event);
      Ada.Text_IO.Put_Line (Event'Img);
      pragma Assert (Event = Tcp_Event_State);
   end loop;
   pragma Assert (Get_State (Socket) = Closed);
   Ada.Text_IO.Put_Line ("Closed");
end TCP_Client;
