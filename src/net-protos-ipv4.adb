-----------------------------------------------------------------------
--  net-protos-Ipv4 -- IPv4 Network protocol
--  Copyright (C) 2016-2024 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--
--  Licensed under the Apache License, Version 2.0 (the "License");
--  you may not use this file except in compliance with the License.
--  You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0
--
--  Unless required by applicable law or agreed to in writing, software
--  distributed under the License is distributed on an "AS IS" BASIS,
--  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
--  See the License for the specific language governing permissions and
--  limitations under the License.
-----------------------------------------------------------------------

with Ada.Unchecked_Conversion;
with Net.Protos.Arp;
with Net.Utils;

package body Net.Protos.IPv4 is

   use type Net.Protos.Arp.Arp_Status;

   Packet_Id : Uint16 := 1;

   function To_Address is new Ada.Unchecked_Conversion
     (Net.Headers.IP_Header_Access, System.Address);

   --  ------------------------------
   --  Send the raw IPv4 packet to the interface.  The destination Ethernet address is
   --  resolved from the ARP table and the packet Ethernet header updated.  The packet
   --  is send immediately when the destination Ethernet address is known, otherwise
   --  it is queued and sent when the ARP resolution is successful.
   --  ------------------------------
   procedure Send_Raw (Ifnet     : in out Net.Interfaces.Ifnet_Type'Class;
                       Target_Ip : in Ip_Addr;
                       Packet    : in out Net.Buffers.Buffer_Type;
                       Status    : out Error_Code) is
      Ether  : constant Net.Headers.Ether_Header_Access := Packet.Ethernet;
      Arp_Status : Net.Protos.Arp.Arp_Status;
   begin
      Ether.Ether_Shost := Ifnet.Mac;
      Ether.Ether_Type  := Net.Headers.To_Network (Net.Protos.ETHERTYPE_IP);
      if Ifnet.Is_Broadcast (Target_Ip) then
         Ether.Ether_Dhost := Broadcast_Mac;
         Arp_Status := Net.Protos.Arp.ARP_FOUND;
      elsif Ifnet.Is_Local_Network (Target_Ip) then
         Net.Protos.Arp.Resolve (Ifnet, Target_Ip, Ether.Ether_Dhost, Packet, Arp_Status);
      elsif Ifnet.Gateway /= (0, 0, 0, 0) then
         Net.Protos.Arp.Resolve (Ifnet, Ifnet.Gateway, Ether.Ether_Dhost, Packet, Arp_Status);
      else
         Arp_Status := Net.Protos.Arp.ARP_UNREACHABLE;
      end if;
      case Arp_Status is
         when Net.Protos.Arp.ARP_FOUND =>
            Ifnet.Send (Packet);
            Status := EOK;

         when Net.Protos.Arp.ARP_PENDING | Net.Protos.Arp.ARP_NEEDED =>
            Status := EINPROGRESS;

         when Net.Protos.Arp.ARP_UNREACHABLE | Net.Protos.Arp.ARP_QUEUE_FULL =>
            Net.Buffers.Release (Packet);
            Status := ENETUNREACH;

      end case;
   end Send_Raw;

   --  ------------------------------
   --  Make an IP packet identifier.
   --  ------------------------------
   procedure Make_Ident (Ip : in Net.Headers.IP_Header_Access) is
   begin
      Ip.Ip_Id  := Net.Headers.To_Network (Packet_Id);
      Packet_Id := Packet_Id + 1;
   end Make_Ident;

   --  ------------------------------
   --  Make the IPv4 header for the source and destination IP addresses and protocol.
   --  ------------------------------
   procedure Make_Header (Ip     : in Net.Headers.IP_Header_Access;
                          Src    : in Ip_Addr;
                          Dst    : in Ip_Addr;
                          Proto  : in Uint8;
                          Length : in Uint16) is
   begin
      Ip.Ip_Ihl := 16#45#;
      Ip.Ip_Tos := 0;
      Ip.Ip_Off := Net.Headers.To_Network (16#4000#);
      Ip.Ip_Ttl := 64;
      Ip.Ip_Sum := 0;
      Ip.Ip_Src := Src;
      Ip.Ip_Dst := Dst;
      Ip.Ip_P   := Proto;
      Ip.Ip_Len := Net.Headers.To_Network (Length);
      Make_Ident (Ip);
   end Make_Header;

   procedure Send (Ifnet     : in out Net.Interfaces.Ifnet_Type'Class;
                   Target_Ip : in Ip_Addr;
                   Packet    : in out Net.Buffers.Buffer_Type;
                   Status    : out Error_Code) is
      Ip     : constant Net.Headers.IP_Header_Access := Packet.IP;
   begin
      Make_Header (Ip, Ifnet.Ip, Target_Ip, P_UDP, Packet.Get_Length);
      Ip.Ip_Ihl := 4;
      Ip.Ip_Tos := 0;
      Ip.Ip_Id  := 2;
      Ip.Ip_Off := 0;
      Ip.Ip_Ttl := 255;
      Ip.Ip_Sum := 0;
      Ip.Ip_Src := Ifnet.Ip;
      Ip.Ip_Dst := Target_Ip;
      Ip.Ip_P   := 4;
      --  Ip.Ip_Len := Net.Headers.To_Network (Packet.Get_Length);
      --  if Ifnet.Is_Local_Address (Target_Ip) then

      Send_Raw (Ifnet, Target_Ip, Packet, Status);
   end Send;

   ---------------------------
   -- Is_Valid_ETHER_Packet --
   ---------------------------

   function Is_Valid_ETHER_Packet
     (Packet : Net.Buffers.Buffer_Type)
      return Boolean is
   begin
      return Packet.Get_Length >= 14;
   end Is_Valid_ETHER_Packet;

   -------------
   -- To_Host --
   -------------

   procedure To_Host (IP : Net.Headers.IP_Header_Access) is
   begin
      IP.Ip_Len := Net.Headers.To_Host (IP.Ip_Len);
      IP.Ip_Id  := Net.Headers.To_Host (IP.Ip_Id);
      IP.Ip_Off := Net.Headers.To_Host (IP.Ip_Off);
      IP.Ip_Sum := Net.Headers.To_Host (IP.Ip_Sum);
   end To_Host;

   ------------------------
   -- Is_Valid_IP_Packet --
   ------------------------

   function Is_Valid_IP_Packet
     (Packet    : Net.Buffers.Buffer_Type;
      Check_Sum : Boolean := True)
      return Boolean
   is
      Ip : constant Net.Headers.IP_Header_Access := Packet.IP;
   begin
      if Packet.Get_Length < 34
        or else Packet.Get_Length < Ip.Ip_Len
        or else (Standard.Interfaces.Shift_Right (Ip.Ip_Ihl, 4)) /= 4 --  Ver
      then
         return False;
      end if;

      if Check_Sum then
         return Ip.Ip_Sum = 0
           or else Net.Utils.Check_Checksum
             (To_Address (Ip), Uint16 (Ip.Ip_Ihl and 16#0F#) * 4);
      else
         return True;
      end if;
   end Is_Valid_IP_Packet;

end Net.Protos.IPv4;
