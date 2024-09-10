# frozen_string_literal: true

# rubocop:disable Style/RedundantReturn

# rubocop:disable Style/HashSyntax

# rubocop:disable Style/StringConcatenation

require 'winrm'
# Additional functions to run commands and puppet apply over WinRM instead of ssh
# Version: 2016-05-03-001
# Reference: https://github.tooling.kpn.org/kpn-puppet-forge/puppet-kpn-module-skeleton/blob/master/skeleton/spec/spec_helper_acceptance.rb.erb

def winrm_command(host, command, opts = {})
  # Get parameters
  # rubocop:disable Style/ConditionalAssignment

  user = host[:ssh][:user]
  pass = host[:ssh][:password]
  hostname = host.to_s
  endpoint = "http://#{hostname}:5985/wsman"
  acceptable_exit_codes = nil
  if opts.key?(:acceptable_exit_codes) && !opts[:acceptable_exit_codes].nil?
    acceptable_exit_codes = opts[:acceptable_exit_codes]
  else
    acceptable_exit_codes = opts[:acceptable_exit_codes] = [0]
  end

  # rubocop:enable Style/ConditionalAssignment

  run_as_cmd = false
  run_as_cmd = true if opts.key?(:run_as_cmd) && !opts[:acceptable_exit_codes].nil?

  # Setup winrm
  opts = {
    user: user,
    password: pass,
    endpoint: endpoint,
    operation_timeout: 300,
  }
  winrm = WinRM::Connection.new(opts)

  # Debugging
  host.logger.debug "Running command '#{command}' via winrm"
  # Execute command via winrm
  if run_as_cmd
    winrm.shell(:cmd) do |shell|
      @result = shell.run(command) do |stdout, stderr|
        host.logger.debug stdout
        host.logger.debug stderr
      end
    end
  else
    winrm.shell(:powershell) do |shell|
      @result = shell.run(command) do |stdout, stderr|
        host.logger.debug stdout
        host.logger.debug stderr
      end
    end
  end

  # Debugging
  host.logger.debug "winrm - stdout  :#{stdout}"
  host.logger.debug "winrm - stderr  :#{stderr}"
  host.logger.debug "winrm - exitcode:#{@result.exitcode}"

  # rubocop:disable Style/LineEndConcatenation

  # rubocop:disable Style/NegatedIf

  if !acceptable_exit_codes.include?(@result.exitcode)
    raise StandardError, "Command '#{command}' failed with unacceptable exit code:#{@result.exitcode} on host '#{hostname}'\n" +
                         "Stdout:#{@result.stdout}\n" +
                         "Stderr:#{@result.stderr}\n"
  end

  # rubocop:enable Style/LineEndConcatenation

  # rubocop:enable Style/NegatedIf

  # Return flat hash with stdout, stderr and the exitcode
  return { :stdout => @result.stdout,
           :stderr => @result.stderr,
           :exitcode => @result.exitcode }
end

def apply_manifest_on_winrm(host, manifest, opts = {})
  if [opts[:catch_changes], opts[:catch_failures], opts[:expect_failures], opts[:expect_changes]].compact.length > 1
    raise StandardError, 'only one of :catch_changes, :catch_failures, :expect_failures and :expect_changes should be set'
  end

  acceptedexitcodes = [0]

  acceptedexitcodes = [0] if opts[:catch_changes]

  acceptedexitcodes = [0, 2] if opts[:catch_failures]

  acceptedexitcodes = [1, 4, 6] if opts[:expect_failures]

  acceptedexitcodes = [2] if opts[:expect_changes]

  file_path = host.tmpfile('apply_manifest.pp')
  create_remote_file(host, file_path, manifest + "\n")

  winrm_command(host, 'puppet apply --detailed-exitcodes ' + file_path + '; exit $lastexitcode',
                { acceptable_exit_codes: acceptedexitcodes })
end

# rubocop:enable Style/RedundantReturn

# rubocop:enable Style/HashSyntax

# rubocop:enable Style/StringConcatenation
