# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'local_security_policy', unless: UNSUPPORTED_PLATFORMS.include?(fact('osfamily')) do
  ENV['no_proxy'] = default
  # test basic resources and idempotency
  context 'when all local windows securit settings ' do
    pp = <<-LSP
    local_security_policy{ 'Audit account logon events':
      ensure       => 'present',
      policy_value => 'Success,Failure',
    }
    local_security_policy{ 'Audit account management':
      ensure       => 'present',
      policy_value => 'Success,Failure',
    }
    local_security_policy{ 'Audit directory service access':
      ensure       => 'present',
      policy_value => 'Success,Failure',
    }
    local_security_policy{ 'Audit logon events':
      ensure       => 'present',
      policy_value => 'Success,Failure',
    }
    local_security_policy{ 'Audit object access':
      ensure       => 'present',
      policy_value => 'Success,Failure',
    }
    local_security_policy{ 'Audit policy change':
      ensure       => 'present',
      policy_value => 'Success,Failure',
    }
    local_security_policy{ 'Audit privilege use':
      ensure       => 'present',
      policy_value => 'Success,Failure',
    }
    local_security_policy{ 'Audit process tracking':
      ensure       => 'present',
      policy_value => 'Success,Failure',
    }
    local_security_policy{ 'Audit system events':
      ensure       => 'present',
      policy_value => 'Success,Failure',
    }
    LSP

    it 'WinRM should be enabled also on Windows Server 2008' do
      r = command('winrm qc -force').stdout
      default.logger.notify r
      sleep(5)
    end

    it 'work idempotently with no errors' do
      # Run it twice and test for idempotency
      # apply_manifest_on_winrm(default,pp, :expect_failures => true)
      default.logger.notify 'This can take a while, so grab a coffee'
      apply_manifest_on_winrm(default, pp, catch_failures: true)
      apply_manifest_on_winrm(default, pp, catch_changes: true)
    end

    describe 'check if settings are applied' do
      it 'Export current Security Policy' do
        winrm_command(default, 'SecEdit /export /cfg c:\cfg.txt')
      end
      # rubocop:disable Style/RegexpLiteral

      it 'Check AuditAccountLogon' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "AuditAccountLogon = 3"')[:stdout].delete("\n")
        expect(r).to match(/AuditAccountLogon = 3/)
      end

      it 'Check AuditAccountManage' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "AuditAccountManage = 3"')[:stdout].delete("\n")
        expect(r).to match(/AuditAccountManage = 3/)
      end

      it 'Check AuditDSAccess' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "AuditDSAccess = 3"')[:stdout].delete("\n")
        expect(r).to match(/AuditDSAccess = 3/)
      end

      it 'Check AuditLogonEvents' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "AuditLogonEvents = 3"')[:stdout].delete("\n")
        expect(r).to match(/AuditLogonEvents = 3/)
      end

      it 'Check AuditObjectAccess' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "AuditObjectAccess = 3"')[:stdout].delete("\n")
        expect(r).to match(/AuditObjectAccess = 3/)
      end

      it 'Check AuditPolicyChange' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "AuditPolicyChange = 3"')[:stdout].delete("\n")
        expect(r).to match(/AuditPolicyChange = 3/)
      end

      it 'Check AuditPrivilegeUse' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "AuditPrivilegeUse = 3"')[:stdout].delete("\n")
        expect(r).to match(/AuditPrivilegeUse = 3/)
      end

      it 'Check AuditProcessTracking' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "AuditProcessTracking = 3"')[:stdout].delete("\n")
        expect(r).to match(/AuditProcessTracking = 3/)
      end

      it 'Check AuditSystemEvents' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "AuditSystemEvents = 3"')[:stdout].delete("\n")
        expect(r).to match(/AuditSystemEvents = 3/)
      end
      # rubocop:enable Style/RegexpLiteral
    end
  end
end
