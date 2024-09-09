# frozen_string_literal: false

require 'spec_helper'
provider_class = Puppet::Type.type(:local_security_policy).provider(:policy)

# rubocop:disable RSpec/MultipleMemoizedHelpers
describe provider_class, if: RUBY_PLATFORM =~ %r{cygwin|mswin|mingw|bccwin|wince|emx} do
  subject { provider_class }

  before :each do
    infout = StringIO.new
    sdbout = StringIO.new
    allow(Puppet::Util).to receive(:which).with('wmic').and_return('c:\\tools\\wmic')
    allow(Puppet::Util).to receive(:which).with('secedit').and_return('c:\\tools\\secedit')
    allow(provider_class).to receive(:read_policy_settings).and_return(inf_data)
    allow(Tempfile).to receive(:new).with('infimport').and_return(infout)
    allow(Tempfile).to receive(:new).with('sdbimport').and_return(sdbout)
    allow(File).to receive(:file?).and_return(true)
    allow(SecurityPolicy).to receive(:temp_file).and_return(secdata)
    allow(provider_class).to receive(:secedit).with(['/configure', '/db', 'sdbout', '/cfg', 'infout', '/quiet'])
    allow(provider_class).to receive(:secedit).with(['/export', '/cfg', secdata, '/quiet'])
    allow(SecurityPolicy).to receive(:wmic).with(['useraccount', 'get', 'name,sid', '/format:csv']).and_return(userdata)
    allow(SecurityPolicy).to receive(:wmic).with(['group', 'get', 'name,sid', '/format:csv']).and_return(groupdata)
  end

  let(:security_policy) do
    SecurityPolicy.new
  end

  let(:inf_data) do
    regexp = "\xEF\xBB\xBF"
    regexp.force_encoding 'utf-8'
    inffile_content = File.read(secdata).encode('utf-8', universal_newline: true).gsub(regexp, '')
    PuppetX::IniFile.new(content: inffile_content)
  end
  let(:secdata) do
    File.join(fixtures, 'unit', 'secedit.inf')
  end

  let(:groupdata) do
    file = File.join(fixtures, 'unit', 'group.txt')
    regexp = "\xEF\xBB\xBF"
    regexp.force_encoding 'utf-8'
    File.open(file, 'r') { |f| f.read.encode('utf-8', universal_newline: true).gsub(regexp, '') }
  end

  let(:userdata) do
    file = File.join(fixtures, 'unit', 'useraccount.txt')
    regexp = "\xEF\xBB\xBF"
    regexp.force_encoding 'utf-8'
    File.open(file, 'r') { |f| f.read.encode('utf-8', universal_newline: true).gsub(regexp, '') }
  end

  let(:facts) { { is_virtual: 'false', operatingsystem: 'windows' } }

  let(:resource) do
    Puppet::Type.type(:local_security_policy).new(
      name: 'Network access: Let Everyone permissions apply to anonymous users',
      ensure: 'present',
      policy_setting: 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
      policy_type: 'Registry Values',
      policy_value: 'disabled',
    )
  end
  let(:provider) do
    provider_class.new(resource)
  end

  it 'creates instances without error' do
    instances = provider_class.instances
    expect(instances.class).to eq(Array)
    expect(instances.count).to be >= 114
  end

  # if you get this error, your are missing a entry in the lsp_mapping under puppet_x/security_policy
  # either its a type, case, or missing entry
  it 'lsp_mapping should contain all the entries in secdata file' do
    inffile = provider_class.read_policy_settings
    missing_policies = {}

    inffile.sections.each do |section|
      next if section == 'Unicode'
      next if section == 'Version'

      inffile[section].each do |name, value|
        SecurityPolicy.find_mapping_from_policy_name(name)
      rescue KeyError => e
        puts e.message
        if value && (section == 'Registry Values')
          reg_type = value.split(',').first
          missing_policies[name] = { name: name, policy_type: section, reg_type: reg_type }
        else
          missing_policies[name] = { name: name, policy_type: section }
        end
      end
    end
    expect(missing_policies.count).to eq(0), 'Missing policy, check the lsp mapping'
  end

  it 'ensure instances works' do
    instances = Puppet::Type.type(:local_security_policy).instances
    expect(instances.count).to be > 1
  end

  describe 'write output' do
    let(:resource) do
      Puppet::Type.type(:local_security_policy).new(
        name: 'Recovery console: Allow automatic administrative logon',
        ensure: 'present',
        policy_setting: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel',
        policy_type: 'Registry Values',
        policy_value: 'disabled',
      )
    end

    it 'writes out the file correctly' do
      provider.create
    end
  end

  describe 'resource is removed' do
    let(:resource) do
      Puppet::Type.type(:local_security_policy).new(
        name: 'Network access: Let Everyone permissions apply to anonymous users',
        ensure: 'absent',
        policy_setting: 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
        policy_type: 'Registry Values',
        policy_value: 'disabled',
      )
    end

    it 'exists? should be false' do
      expect(provider.exists?).to eq(false)
      expect(provider).to receive(:destroy).exactly(0).times
    end
  end

  describe 'resource is present' do
    let(:secdata) do
      File.join(fixtures, 'unit', 'short_secedit.inf')
    end
    let(:resource) do
      Puppet::Type.type(:local_security_policy).new(
        name: 'Recovery console: Allow automatic administrative logon',
        ensure: 'present',
        policy_setting: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel',
        policy_type: 'Registry Values',
        policy_value: 'disabled',
      )
    end

    it 'exists? should be true' do
      expect(provider).to receive(:create).exactly(0).times
    end
  end

  describe 'resource is absent' do
    let(:resource) do
      Puppet::Type.type(:local_security_policy).new(
        name: 'Recovery console: Allow automatic administrative logon',
        ensure: 'present',
        policy_setting: '1MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel',
        policy_type: 'Registry Values',
        policy_value: 'enabled',
      )
    end

    it 'exists? should be false' do
      expect(provider.exists?).to eq(false)
      allow(provider).to receive(:create).once
    end
  end

  it 'is an instance of Puppet::Type::Local_security_policy::ProviderPolicy' do
    expect(provider).to be_an_instance_of Puppet::Type::Local_security_policy::ProviderPolicy
  end
end
# rubocop:enable RSpec/MultipleMemoizedHelpers
