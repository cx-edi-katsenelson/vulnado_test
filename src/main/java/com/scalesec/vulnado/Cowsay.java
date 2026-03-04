package com.scalesec.vulnado;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.regex.Pattern;

public class Cowsay {
  // Pattern to validate safe input - only allow alphanumeric characters, spaces, and basic punctuation
  private static final Pattern SAFE_INPUT_PATTERN = Pattern.compile("^[a-zA-Z0-9\\s.,!?'-]+$");
  private static final int MAX_INPUT_LENGTH = 500;

  /**
   * Executes the cowsay command with the provided input.
   * Uses array-based exec() to prevent command injection attacks.
   *
   * @param input The text to be displayed by cowsay
   * @return The cowsay output or an error message
   */
  public String run(String input) {
    try {
      // Validate input to prevent command injection
      if (input == null || input.isEmpty()) {
        return "Error: Input cannot be empty";
      }

      if (input.length() > MAX_INPUT_LENGTH) {
        return "Error: Input exceeds maximum length of " + MAX_INPUT_LENGTH + " characters";
      }

      // Check for potentially dangerous characters
      if (!SAFE_INPUT_PATTERN.matcher(input).matches()) {
        return "Error: Input contains invalid characters. Only alphanumeric characters, spaces, and basic punctuation are allowed.";
      }

      // Use array-based exec() to prevent command injection
      // This ensures the command and arguments are properly separated
      String[] cmd = {"cowsay", input};
      Process process = Runtime.getRuntime().exec(cmd);

      BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
      StringBuilder output = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        output.append(line).append("\n");
      }

      int exitCode = process.waitFor();
      if (exitCode != 0) {
        return "Error: Command execution failed with exit code " + exitCode;
      }

      return output.toString();
    } catch (Exception e) {
      return "Error: " + e.getMessage();
    }
  }
}
