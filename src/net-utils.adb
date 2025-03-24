-----------------------------------------------------------------------
--  net-utils -- Network utilities
--  Copyright (C) 2016 Stephane Carrez
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
with Interfaces;
with System;

package body Net.Utils is

   function Hex (Value : in Uint8) return String;
   function Image (Value : in Uint8) return String;

   Hex_String : constant String := "0123456789ABCDEF";

   --  Get a 32-bit random number.
   function Default_Random return Uint32 is separate;

   function To_Address is new Ada.Unchecked_Conversion
     (Net.Headers.TCP_Header_Access, System.Address);

   function Hex (Value : in Uint8) return String is
      use Interfaces;

      Result : String (1 .. 2);
   begin
      Result (1) := Hex_String (Positive (Shift_Right (Value, 4) + 1));
      Result (2) := Hex_String (Positive ((Value and 16#0f#) + 1));
      return Result;
   end Hex;

   function Image (Value : in Uint8) return String is
      Result : constant String := Value'Image;
   begin
      return Result (Result'First + 1 .. Result'Last);
   end Image;

   --  ------------------------------
   --  Convert the IPv4 address to a dot string representation.
   --  ------------------------------
   function To_String (Ip : in Ip_Addr) return String is
   begin
      return Image (Ip (Ip'First)) & "."
        & Image (Ip (Ip'First + 1)) & "."
        & Image (Ip (Ip'First + 2)) & "."
        & Image (Ip (Ip'First + 3));
   end To_String;

   --  ------------------------------
   --  Convert the Ethernet address to a string representation.
   --  ------------------------------
   function To_String (Mac : in Ether_Addr) return String is
   begin
      return Hex (Mac (Mac'First)) & ":"
        & Hex (Mac (Mac'First + 1)) & ":"
        & Hex (Mac (Mac'First + 2)) & ":"
        & Hex (Mac (Mac'First + 3)) & ":"
        & Hex (Mac (Mac'First + 4)) & ":"
        & Hex (Mac (Mac'First + 5));
   end To_String;

   procedure Set_Random_Function (Value : Custom_Random_Function) is
   begin
      Random_Function := Value;
   end Set_Random_Function;

   ------------------
   -- TCP_Checksum --
   ------------------

   function TCP_Checksum
     (Pseudo_Header : Net.Headers.TCP_Pseudo_Header;
      Buf           : Net.Buffers.Buffer_Type)
      return Uint16 is
   begin
      return Calculate_Checksum
        (To_Address (Buf.TCP),
         Net.Buffers.Get_Data_Size (Buf, Net.Buffers.IP_PACKET),
         Checksum (Pseudo_Header));
   end TCP_Checksum;

   --------------
   -- Checksum --
   --------------

   function Checksum (Header : Net.Headers.TCP_Pseudo_Header) return Uint32 is
      Data : array (1 .. 6) of Uint16 with Import, Address => Header'Address;
      Result : Uint32 := 0;
   begin
      for I in Data'Range loop
         Result := Result + Uint32 (Data (I));
      end loop;
      return Result;
   end Checksum;

   ------------------------
   -- Check_TCP_Checksum --
   ------------------------

   function Check_TCP_Checksum
     (Pseudo_Header : Net.Headers.TCP_Pseudo_Header;
      Buf           : Net.Buffers.Buffer_Type)
      return Boolean is
   begin
      return TCP_Checksum (Pseudo_Header, Buf) = 0;
   end Check_TCP_Checksum;

   --------------------
   -- Check_Checksum --
   --------------------

   function Check_Checksum
     (Address : System.Address;
      Lenght  : Uint16)
      return Boolean is
   begin
      return Calculate_Checksum (Address, Lenght, 0) = 0;
   end Check_Checksum;

   ------------------------
   -- Calculate_Checksum --
   ------------------------

   function Calculate_Checksum
     (Address : System.Address;
      Lenght  : Uint16;
      From    : Uint32)
      return Uint16
   is
      Result  : Uint32 := From;
      Data_16 : array (1 .. Lenght / 2) of Uint16 with Import,
        Address => Calculate_Checksum.Address;
      Data_8 : array (1 .. Lenght) of Uint8 with Import,
        Address => Calculate_Checksum.Address;

   begin
      for I in Data_16'Range loop
         Result := Result + Uint32 (Data_16 (I));
      end loop;

      if Data_16'Last * 2 < Data_8'Last then
         Result := Result + Uint32 (Data_8 (Data_8'Last));
      end if;

      while Result > 16#FFFF# loop
         Result := (Result and 16#FFFF#) + Interfaces.Shift_Right (Result, 16);
      end loop;

      return not Uint16 (Result);
   end Calculate_Checksum;

end Net.Utils;
