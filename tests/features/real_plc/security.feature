@real_plc
Feature: Protect the session with TLS and a password

  @smoke @tls
  Scenario: The session is encrypted when TLS is requested
    Given TLS has been requested for this run
    And the client uses the configured S7CommPlus security mode
    When I connect to the configured PLC
    Then the session reports TLS as active

  @smoke @tls
  Scenario: A PLC certificate from an untrusted CA is refused
    Given TLS has been requested for this run
    And the client uses the configured S7CommPlus security mode
    When I connect while trusting only a freshly generated CA
    Then the connection is refused
    And the client reports that it is disconnected

  @smoke @password
  Scenario: Legitimate with the configured password
    Given a test password is configured
    And the client uses the configured S7CommPlus security mode
    When I connect with the configured password
    Then the client reports that it is connected
    And the protection level is recorded
    And a known read succeeds

  @administrative @password
  Scenario: A wrong password is refused
    Given a test password is configured
    And the client uses the configured S7CommPlus security mode
    When I connect with a wrong password
    Then the connection is refused as an authentication failure

  @smoke @pending @tls
  Scenario: Pin the PLC certificate
    Given TLS has been requested for this run
    And the client uses the configured S7CommPlus security mode
    And the client supports certificate pinning
    And I have recorded the PLC certificate fingerprint
    When I connect pinning that fingerprint
    Then the client reports that it is connected
    When I disconnect
    And I connect pinning a different fingerprint
    Then the connection is refused
