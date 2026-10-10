@real_plc @subscription
Feature: Subscribe to data changes

  @smoke
  Scenario: Receive the initial value of a subscribed member
    Given the client uses the configured S7CommPlus security mode
    And I am connected to the PLC
    And I know the access sequence of the read-only member int2
    When I subscribe to that member
    Then a notification carries its current value
    And the subscription is deleted cleanly

  @write
  Scenario: Receive a change to a scratch member
    Given the client uses the configured S7CommPlus security mode
    And writing has been explicitly enabled
    And I have a dedicated non-optimized scratch DB
    And the original bytes for INT have been saved
    And I know the access sequence of the scratch member int1
    And I am subscribed to that member
    When I write a valid INT value
    Then a notification carries the written value
    And the subscription is deleted cleanly
    And the original bytes are restored and verified
