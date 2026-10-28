@real_plc
Feature: Change the CPU operating state (disruptive, unverified)

  This feature drives the RUN/STOP request whose wire layout is still
  unverified (issue #8). The run itself is the evidence: it records the
  request bytes, response bytes and ReturnValues so a capture is not needed.
  It halts the CPU, so it is gated behind @administrative (--allow-admin) and
  must only ever target a dedicated, non-production, non-safety-critical PLC.

  Background:
    Given I am using a dedicated non-safety-critical test PLC

  @administrative @pending @cpu_state
  Scenario: Stop and restart the CPU and record the exchange
    Given the client uses the configured S7CommPlus security mode
    And the client supports operating state control
    And I am connected to the PLC
    And I record the starting CPU operating state
    When I request the STOP operating state and poll until the CPU stops
    Then the CPU operating state is STOP and the exchange is recorded
    When I request the RUN operating state and poll until the CPU runs
    Then the CPU operating state is RUN and the exchange is recorded
