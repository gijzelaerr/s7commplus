@real_plc @write
Feature: Write safely to a non-optimized scratch data block over S7CommPlus

  Scenario Outline: Round-trip a value and restore the PLC
    Given the client uses the configured S7CommPlus security mode
    And writing has been explicitly enabled
    And I have a dedicated non-optimized scratch DB
    And the original bytes for <type> have been saved
    When I write a valid <type> value
    Then reading the address returns the written value
    And the original bytes are restored and verified

    Examples: S7CommPlus values
      | type  |
      | INT   |
      | REAL  |
      | BYTE  |
      | WORD  |
      | DWORD |
      | DINT  |
      | CHAR  |
      | BOOL  |

  @symbolic
  Scenario Outline: Round-trip a value by name and restore the PLC
    Given the client uses the configured S7CommPlus security mode
    And writing has been explicitly enabled
    And I have a dedicated non-optimized scratch DB
    And the original bytes for <type> have been saved
    When I write a valid <type> value by name
    Then reading the member by name returns the written value
    And the original bytes are restored and verified

    Examples: S7CommPlus named values
      | type  |
      | INT   |
      | REAL  |
      | BYTE  |
      | WORD  |
      | DWORD |
      | DINT  |
      | CHAR  |
      | BOOL  |
