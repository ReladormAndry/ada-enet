pragma Profile (Ravenscar);

with Ada.Real_Time;

with Net.Interfaces.Tap;
with Net.Sockets.Tcp;

package Tap_TCP is

   INet : aliased Net.Interfaces.Tap.Tap_Ifnet;

   -- Sockets --

   package Sockets is new Net.Sockets.Tcp
     (Ifnet                    => Net.Interfaces.Ifnet_Type'Class (INet),
      Max_Sockets_Count        => 1,
      Use_IRQ                  => False,
      Read_Delay               => Ada.Real_Time.Milliseconds (10),
      Max_Read_Time            => Ada.Real_Time.Milliseconds (4),
      Check_TCP_Status_Time    => Ada.Real_Time.Milliseconds (500),
      Check_Incoming_Checksums => False,
      Send_Outcoming_Checksums => False);

   use Sockets;

   procedure Callback
     (This  : Socket_Access;
      Event : Tcp_Event_Kind);

   -- Watchdog --

   protected Watchdog is

      entry Wait (Event : out Tcp_Event_Kind);
      procedure Release (Event : Tcp_Event_Kind);

   private
      Last     : Tcp_Event_Kind := Tcp_Event_None;
      Released : Boolean := False;
   end Watchdog;

end Tap_TCP;
