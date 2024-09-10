# frozen_string_literal: true

require 'spec_helper'
require 'puppet_x/lsp/security_policy'

describe 'SecurityPolicy', if: RUBY_PLATFORM =~ %r{cygwin|mswin|mingw|bccwin|wince|emx} do
  subject(:security_policy) { SecurityPolicy }

  before :each do
    allow(Puppet::Util).to receive(:which).with('wmic').and_return('c:\\tools\\wmic')
    allow(Puppet::Util).to receive(:which).with('secedit').and_return('c:\\tools\\secedit')
    ENV['windir'] = 'C:\Windows'
    infout = StringIO.new
    sdbout = StringIO.new
    allow(Tempfile).to receive(:new).with('infimport').and_return(infout)
    allow(Tempfile).to receive(:new).with('sdbimport').and_return(sdbout)
    allow(File).to receive(:file?).with(secdata).and_return(true)
    allow(File).to receive(:file?).with(%r{facter}).and_return(true)
    allow(SecurityPolicy).to receive(:temp_file).and_return(secdata)
  end

  let(:secdata) do
    File.join(fixtures, 'unit', 'secedit.inf')
  end

  it 'returns sid when user is not found' do
    expect(security_policy.user_to_sid('*S-11-5-80-0')).to eq('*S-11-5-80-0')
  end

#  it 'returns sid' do
#    expect(security_policy.user_to_sid('Network Configuration Operators')).to eq('*S-1-5-32-556')
#    # expect(security_policy.user_to_sid('NT_SERVICE\\ALL_SERVICES')).to eq('*S-1-5-80-0')
#  end

  it 'returns user when sid is not found' do
    expect(security_policy.user_to_sid('N_SERVICE\\ALL_SERVICES')).to eq('N_SERVICE\\ALL_SERVICES')
  end

  describe 'audit event' do
    let(:resource) do
      Puppet::Type.type(:local_security_policy).new(
        name: 'Audit account logon events',
        ensure: 'present',
        policy_setting: 'AuditAccountLogon',
        policy_type: 'Event Audit',
        policy_value: 'Success,Failure',
      )
    end

    it 'converts a audit right' do
      defined_policy = SecurityPolicy.find_mapping_from_policy_desc(resource[:name])
      defined_policy.merge!(resource.to_hash)
      hash = SecurityPolicy.convert_policy_hash(defined_policy)
      expect(hash[:policy_value]).to eq(3)
    end
  end
end
