# frozen_string_literal: true

require 'beaker-rspec'
require 'beaker/puppet_install_helper'
require 'beaker-rspec/helpers/serverspec'
require_relative 'spec_helper_acceptance_winrm.rb'
require_relative 'spec_helper_acceptance_methods.rb'

UNSUPPORTED_PLATFORMS = [].freeze

unless (ENV['RS_PROVISION'] == 'no') || (ENV['BEAKER_provision'] == 'no')
  # Install Puppet Enterprise Agent
  run_puppet_install_helper

  # Clone module dependencies here...
  clone_dependent_modules
end

RSpec.configure do |c|
  # Project root
  proj_root = File.expand_path(File.join(File.dirname(__FILE__), '..'))

  # Readable test descriptions
  c.formatter = :documentation

  # Configure all nodes in nodeset
  c.before :suite do
    # Copy modules to SUT (System Under Test)
    install_dependent_modules
    puppet_module_install(source: proj_root, module_name: 'local_security_policy')
  end
end
