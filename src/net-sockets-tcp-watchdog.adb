
with Ada.Real_Time; use Ada.Real_Time;
with Ada.Synchronous_Task_Control;

separate (Net.Sockets.Tcp)
package body Watchdog is

   ETHERTYPE_ARP : constant Net.Uint16 :=
     Net.Headers.To_Network (Net.Protos.ETHERTYPE_ARP);

   ETHERTYPE_IP : constant Net.Uint16 :=
     Net.Headers.To_Network (Net.Protos.ETHERTYPE_IP);

   Ready : Ada.Synchronous_Task_Control.Suspension_Object;

   procedure Received (Until_Time : Ada.Real_Time.Time);

   --------------
   -- Receiver --
   --------------

   protected Receiver
     with Priority => Priority
   is
      procedure On_IRQ;
      --  Called externally when Ifnet set IRQ that some data has arrived.
   end Receiver;

   ----------------
   -- Controller --
   ----------------

   --  The task that waits for packets in Ifnet.
   task Controller with
     Priority => Priority;

   ------------
   -- On_IRQ --
   ------------

   procedure On_IRQ is
   begin
      Receiver.On_IRQ;
   end On_IRQ;

   -----------
   -- Start --
   -----------

   procedure Start is
   begin
      Ada.Synchronous_Task_Control.Set_True (Ready);
   end Start;

   --------------
   -- Receiver --
   --------------

   protected body Receiver is

      ------------
      -- On_IRQ --
      ------------

      procedure On_IRQ is
      begin
         Received (Ada.Real_Time.Clock + Max_Read_Time);
      end On_IRQ;
   end Receiver;

   ----------------
   -- Controller --
   ----------------

   task body Controller is
      Now       : Ada.Real_Time.Time;
      Prev_Pass : Ada.Real_Time.Time;

   begin
      --  Wait until the Ethernet driver is ready.
      Ada.Synchronous_Task_Control.Suspend_Until_True (Ready);

      Prev_Pass := Ada.Real_Time.Clock;
      loop
         begin
            Now := Ada.Real_Time.Clock;

            if not Use_IRQ then
               Received (Now + Max_Read_Time);
            end if;

            if Now - Prev_Pass > Check_TCP_Status_Time then
               Prev_Pass := Prev_Pass + Check_TCP_Status_Time;

               Check_Statuses;
            end if;

            delay until Now + Read_Delay;
         exception
            when others =>
               null;
         end;
      end loop;
   end Controller;

   --------------
   -- Received --
   --------------

   procedure Received (Until_Time : Ada.Real_Time.Time) is
      Packet : Net.Buffers.Buffer_Type;
      Ether  : Net.Headers.Ether_Header_Access;

   begin
      loop
         if Net.Buffers.Is_Null (Packet) then
            Net.Buffers.Allocate (Packet);
         end if;

         Ifnet.Receive (Packet);
         exit when Packet.Get_Length = 0;

         if Net.Protos.IPv4.Is_Valid_ETHER_Packet (Packet) then
            --  We have valid ETHER header
            Ether := Packet.Ethernet;
            if Ether.Ether_Type = ETHERTYPE_ARP then
               Net.Protos.Arp.Receive (Ifnet, Packet);

            elsif Ether.Ether_Type = ETHERTYPE_IP then
               Net.Protos.IPv4.To_Host (Packet.IP);

               if Net.Protos.IPv4.Is_Valid_IP_Packet
                 (Packet, Check_Incoming_Checksums)
               then
                  --  We have valid IP header
                  if Packet.IP.Ip_P = Net.Protos.IPv4.P_TCP then
                     Net.Sockets.Tcp.Received (Packet);

                  else
                     Net.Protos.Dispatchers.Receive (Ifnet, Packet);
                  end if;
               end if;
            end if;
         end if;

         exit when Ada.Real_Time.Clock > Until_Time;
      end loop;

      Net.Buffers.Release (Packet);
   exception
      when others =>
         Net.Buffers.Release (Packet);
   end Received;

end Watchdog;
