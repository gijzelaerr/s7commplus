@real_plc
Feature: Connect to and identify a real S7CommPlus PLC

  Background:
    Given I am using a dedicated non-safety-critical test PLC
    And the test configuration contains no secrets in reportable fields

  @smoke
  Scenario: Establish and close an S7CommPlus session
    Given the client uses the configured S7CommPlus security mode
    When I connect to the configured PLC
    Then the client reports that it is connected
    And the negotiated protocol version and TLS mode are recorded
    When I disconnect
    Then the client reports that it is disconnected

  @smoke @cpu_state
  Scenario: Report the CPU operating state
    Given the client uses the configured S7CommPlus security mode
    And I am connected to the PLC
    When I read the CPU operating state
    Then the state is RUN, STOP or UNKNOWN and is recorded
    And the state matches the expected state when one is configured
