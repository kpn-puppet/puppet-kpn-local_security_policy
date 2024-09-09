# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'local_security_policy', unless: UNSUPPORTED_PLATFORMS.include?(fact('osfamily')) do
  ENV['no_proxy'] = default
  # test basic resources and idempotency
  context 'with all local windows securit settings ' do
    pp = <<-PP
    local_security_policy{ 'Audit account logon events':
      ensure       => 'absent',
    }
    local_security_policy{ 'Audit account management':
      ensure       => 'absent',
    }
    local_security_policy{ 'Audit directory service access':
      ensure       => 'absent',
    }
    local_security_policy{ 'Audit logon events':
      ensure       => 'absent',
    }
    local_security_policy{ 'Audit object access':
      ensure       => 'absent',
    }
    local_security_policy{ 'Audit policy change':
      ensure       => 'absent',
    }
    local_security_policy{ 'Audit privilege use':
      ensure       => 'absent',
    }
    local_security_policy{ 'Audit process tracking':
      ensure       => 'absent',
    }
    local_security_policy{ 'Audit system events':
      ensure       => 'absent',
    }
    PP

    it 'WinRM should be enabled also on Windows Server 2008' do
      r = command('winrm qc -force').stdout
      default.logger.notify r
      sleep(5)
    end

    it 'works idempotently with no errors' do
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

      it 'Check AuditAccountLogon' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "AuditAccountLogon = 0"')[:stdout].delete("\n")
        expect(r).to match(%r{AuditAccountLogon = 0})
      end

      it 'Check AuditAccountManage' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "AuditAccountManage = 0"')[:stdout].delete("\n")
        expect(r).to match(%r{AuditAccountManage = 0})
      end

      it 'Check AuditDSAccess' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "AuditDSAccess = 0"')[:stdout].delete("\n")
        expect(r).to match(%r{AuditDSAccess = 0})
      end

      it 'Check AuditLogonEvents' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "AuditLogonEvents = 0"')[:stdout].delete("\n")
        expect(r).to match(%r{AuditLogonEvents = 0})
      end

      it 'Check AuditObjectAccess' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "AuditObjectAccess = 0"')[:stdout].delete("\n")
        expect(r).to match(%r{AuditObjectAccess = 0})
      end

      it 'Check AuditPolicyChange' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "AuditPolicyChange = 0"')[:stdout].delete("\n")
        expect(r).to match(%r{AuditPolicyChange = 0})
      end

      it 'Check AuditPrivilegeUse' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "AuditPrivilegeUse = 0"')[:stdout].delete("\n")
        expect(r).to match(%r{AuditPrivilegeUse = 0})
      end

      it 'Check AuditProcessTracking' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "AuditProcessTracking = 0"')[:stdout].delete("\n")
        expect(r).to match(%r{AuditProcessTracking = 0})
      end

      it 'Check AuditSystemEvents' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "AuditSystemEvents = 0"')[:stdout].delete("\n")
        expect(r).to match(%r{AuditSystemEvents = 0})
      end
    end
  end
end
