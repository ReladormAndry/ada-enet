pragma Profile (Ravenscar);

with Net.Interfaces.Tap;
with Net.Sockets.Tcp;
with Net.Generic_Receiver;

package Tap_TCP is

   Tap : aliased Net.Interfaces.Tap.Tap_Ifnet;

   -- Sockets --

   package Sockets is new Net.Sockets.Tcp
     (Ifnet             => Net.Interfaces.Ifnet_Type'Class (Tap),
      Max_Sockets_Count => 1);

   package LAN_Receiver is new Net.Generic_Receiver
     (Net.Interfaces.Ifnet_Type'Class (Tap));

   Socket : Sockets.Socket;

   procedure Initialize;

end Tap_TCP;
