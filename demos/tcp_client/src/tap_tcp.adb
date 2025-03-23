
package body Tap_TCP is

   --------------
   -- Callback --
   --------------

   procedure Callback
     (This  : Socket_Access;
      Event : Tcp_Event_Kind)
   is
      pragma Unreferenced (This);
   begin
      Watchdog.Release (Event);
   end Callback;

   --------------
   -- Watchdog --
   --------------

   protected body Watchdog is

      entry Wait (Event : out Tcp_Event_Kind)
        when Released is
      begin
         Event    := Last;
         Last     := Tcp_Event_None;
         Released := False;
      end Wait;

      -------------
      -- Release --
      -------------

      procedure Release (Event : Tcp_Event_Kind) is
      begin
         Last     := Event;
         Released := True;
      end Release;
   end Watchdog;

end Tap_TCP;
