@real_plc
Feature: Recover from normal S7CommPlus connection lifecycle events

  @smoke
  Scenario: Reconnect after a clean disconnect
    Given the client uses the configured S7CommPlus security mode
    And I connected to and disconnected from the PLC
    When I reconnect with the same configuration
    Then a known read succeeds

  @smoke
  Scenario: Repeated operations do not corrupt the session
    Given the client uses the configured S7CommPlus security mode
    And I am connected to the PLC
    When I read the canonical fixture repeatedly
    Then every read succeeds with the expected value
    And disconnect completes cleanly

  @smoke @pending
  Scenario: Rebuild the session with reconnect()
    Given the client uses the configured S7CommPlus security mode
    And the client supports reconnect
    And I am connected to the PLC
    When I rebuild the session with reconnect()
    Then the client reports that it is connected
    And a known read succeeds
