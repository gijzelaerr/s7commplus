@real_plc @alarm
Feature: Read the PLC alarm state

  @smoke
  Scenario: Read the active alarm snapshot
    Given the client uses the configured S7CommPlus security mode
    And I am connected to the PLC
    When I read the active alarms
    Then the snapshot is a list of alarms and its size is recorded

  @smoke
  Scenario: Create and delete an alarm subscription
    Given the client uses the configured S7CommPlus security mode
    And I am connected to the PLC
    When I subscribe to alarms
    Then the alarm subscription is deleted cleanly
    And a known read succeeds
