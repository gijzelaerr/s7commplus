@real_plc @symbolic
Feature: Find and read the fixture data block by name

  @smoke
  Scenario: List the data blocks
    Given the client uses the configured S7CommPlus security mode
    And I am connected to the PLC
    When I list the data blocks
    Then the read-only fixture DB and the scratch DB are listed

  @smoke
  Scenario: Browse the fixture data block
    Given the client uses the configured S7CommPlus security mode
    And I am connected to the PLC
    When I browse the PLC symbols
    Then every member of the read-only fixture DB is listed with its type
    And the browsed byte offsets match the documented layout

  @smoke
  Scenario: Read the fixture members by name
    Given the client uses the configured S7CommPlus security mode
    And the non-optimized read-only DB has the documented canonical layout
    When I read every fixture member by name
    Then every member read by name matches the byte-offset read
