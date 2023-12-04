# frozen_string_literal: true

require 'spec_helper'
require 'puppet_x/lsp/security_policy'

describe 'SecurityPolicy' do
  subject(:securitypolicy) { SecurityPolicy }

  before :each do
    # Set windir environment variable
    ENV['windir'] = 'C:\Windows'
    infout = StringIO.new
    sdbout = StringIO.new
    allow(Tempfile).to receive(:new).with('infimport').and_return(infout)
    allow(Tempfile).to receive(:new).with('sdbimport').and_return(sdbout)
    allow(File).to receive(:file?).with(secdata).and_return(true)
    # the below mock seems to be required or rspec complains
    allow(File).to receive(:file?).with(%r{facter}).and_return(true)
    allow(security_policy).to receive('user_to_sid').with('*S-11-5-80-0').and_return('*S-11-5-80-0')
    allow(security_policy).to receive('sid_to_user').with('S-1-5-32-556').and_return('Network Configuration Operators')
    allow(security_policy).to receive('sid_to_user').with('*S-1-5-80-0').and_return('NT_SERVICE\\ALL_SERVICES')
    allow(security_policy).to receive('user_to_sid').with('Network Configuration Operators').and_return('*S-1-5-32-556')
    allow(security_policy).to receive('user_to_sid').with('NT_SERVICE\\ALL_SERVICES').and_return('*S-1-5-80-0')
    allow(security_policy).to receive('user_to_sid').with('N_SERVICE\\ALL_SERVICES').and_return('N_SERVICE\\ALL_SERVICES')
  end

  let(:secdata) do
    File.join(fixtures_path, 'unit', 'secedit.inf')
  end

  let(:security_policy) do
    SecurityPolicy.new
  end

  it 'returns user' do
    expect(security_policy.sid_to_user('S-1-5-32-556')).to eq('Network Configuration Operators')
    expect(security_policy.sid_to_user('*S-1-5-80-0')).to eq('NT_SERVICE\\ALL_SERVICES')
  end

  it 'returns sid when user is not found' do
    expect(security_policy.user_to_sid('*S-11-5-80-0')).to eq('*S-11-5-80-0')
  end

  it 'returns sid' do
    expect(security_policy.user_to_sid('Network Configuration Operators')).to eq('*S-1-5-32-556')
    expect(security_policy.user_to_sid('NT_SERVICE\\ALL_SERVICES')).to eq('*S-1-5-80-0')
  end

  it 'returns user when sid is not found' do
    expect(security_policy.user_to_sid('N_SERVICE\\ALL_SERVICES')).to eq('N_SERVICE\\ALL_SERVICES')
  end

  # describe 'privilege right' do
  #   let(:resource) {
  #     Puppet::Type.type(:local_security_policy).new(
  #         :name =>  'Access this computer from the network',
  #         :ensure         => 'present',
  #         :policy_setting => 'SeNetworkLogonRight',
  #         :policy_type    => 'Privilege Rights',
  #         :policy_value   => 'AUTHENTICATED_USERS,BUILTIN_ADMINISTRATORS'
  #     )
  #   }
  #   it 'should convert a privilege right to sids' do
  #     hash = security_policy.convert_policy_value(resource, resource[:policy_value])
  #     expect(hash[:policy_value]).to eq('*S-1-5-11,*S-1-5-32-544')
  #   end

  # end
  #
  # describe 'audit event' do
  #   let(:resource) {
  #     Puppet::Type.type(:local_security_policy).new(
  #         :name => 'Audit account logon events',
  #         :ensure         => 'present',
  #         :policy_setting => "AuditAccountLogon",
  #         :policy_type    => "Event Audit",
  #         :policy_value   => 'Success,Failure',
  #     )
  #   }
  #   it 'should convert a audit right' do
  #     defined_policy = SecurityPolicy.find_mapping_from_policy_desc(resource[:name])
  #     defined_policy.merge!(resource.to_hash)
  #     expect(provider.convert_audit(defined_policy)).to eq(3)
  #   end
  #
  #   it 'should convert a audit right' do
  #     defined_policy = SecurityPolicy.find_mapping_from_policy_desc(resource[:name])
  #     defined_policy.merge!(resource.to_hash)
  #     hash = provider.convert_policy_hash(defined_policy)
  #     expect(hash[:policy_value]).to eq(3)
  #   end
  # end
end
