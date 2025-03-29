
with Ada.Streams;         use Ada.Streams;
with GNAT.Random_Numbers;

with Net.Buffers;
with Net.Protos.Dispatchers;
with Net.Protos.IPv4;
with Net.Utils;

package body Tap_TCP is

   Buffer_Memory : Ada.Streams.Stream_Element_Array
     (1 .. 2_048 * Stream_Element_Offset (Net.Buffers.NET_ALLOC_SIZE));
   Random        : GNAT.Random_Numbers.Generator;

   function Get_Random return Net.Uint32;

   ----------------
   -- Get_Random --
   ----------------

   function Get_Random return Net.Uint32 is
   begin
      return GNAT.Random_Numbers.Random (Random);
   end Get_Random;

   Dummy : Net.Protos.Receive_Handler;

   ----------------
   -- Initialize --
   ----------------

   procedure Initialize is
   begin
      Net.Buffers.Add_Region
        (Addr => Buffer_Memory'Address,
         Size => Buffer_Memory'Length);

      GNAT.Random_Numbers.Reset (Random);
      Net.Utils.Set_Random_Function (Get_Random'Unrestricted_Access);

      Net.Protos.Dispatchers.Set_Handler
        (Net.Protos.IPv4.P_TCP, Sockets.Received'Access, Dummy);
   end Initialize;

end Tap_TCP;
