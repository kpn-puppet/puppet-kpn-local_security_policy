# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'local_security_policy', unless: UNSUPPORTED_PLATFORMS.include?(fact('osfamily')) do
  ENV['no_proxy'] = default
  # test basic resources and idempotency
  context 'when all local windows securit settings ' do
    pp = <<-LSP
    local_security_policy { 'Account lockout threshold':
      ensure       => 'present',
      policy_value => '10',
    } -> local_security_policy { 'Reset account lockout counter after':
      ensure       => 'present',
      policy_value => '15',
    } -> local_security_policy { 'Account lockout duration':
      ensure       => 'present',
      policy_value => '15',
    }
    local_security_policy { 'Enforce password history':
      ensure       => 'present',
      policy_value => '24',
    }
    local_security_policy { 'Maximum password age':
      ensure       => 'present',
      policy_value => '60',
    }
    local_security_policy { 'Minimum password age':
      ensure       => 'present',
      policy_value => '1',
    }
    local_security_policy { 'Minimum password length':
      ensure       => 'present',
      policy_value => '14',
    }
    local_security_policy { 'Password must meet complexity requirements':
      ensure       => 'present',
      policy_value => 'enabled',
    }
    local_security_policy { 'Store passwords using reversible encryption':
      ensure       => 'present',
      policy_value => 'disabled',
    }
    local_security_policy { 'Accounts: Administrator account status':
      ensure       => 'present',
      policy_value => 'enabled',
    }
    local_security_policy { 'Accounts: Guest account status':
      ensure       => 'present',
      policy_value => 'disabled',
    }
    local_security_policy { 'Accounts: Limit local account use of blank passwords to console logon only':
      ensure       => 'present',
      policy_value => 'enabled',
    }
    # Disabled this policy, because the Administrator user is used by beaker.
    #local_security_policy { 'Accounts: Rename administrator account':
    #  ensure       => 'present',
    #  policy_value => 'hosting',
    #}
    local_security_policy { 'Accounts: Rename guest account':
      ensure       => 'present',
      policy_value => 'tseug',
    }
    local_security_policy { 'Audit: Audit the access of global system objects':
        ensure       => 'present',
        policy_value => 'disabled',
      }
    local_security_policy { 'Audit: Audit the use of Backup and Restore privilege':
      ensure       => 'present',
      policy_value => 'enabled',
    }
    local_security_policy { 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings':
      ensure       => 'present',
      policy_value => 'enabled',
    }
    local_security_policy { 'Audit: Shut down system immediately if unable to log security audits':
      ensure       => 'present',
      policy_value => 'disabled',
    }
    local_security_policy{ 'Devices: Allow undock without having to log on':
      ensure       => 'present',
      policy_value => 'disabled',
    }
    local_security_policy{ 'Devices: Allowed to format and eject removable media':
      ensure       => 'present',
      policy_value => 'Administrators',
    }
    local_security_policy{ 'Devices: Prevent users from installing printer drivers':
      ensure       => 'present',
      policy_value => 'enabled',
    }
    local_security_policy{ 'Devices: Restrict CD-ROM access to locally logged-on user only':
      ensure       => 'present',
      policy_value => 'enabled',
    }
    local_security_policy{ 'Devices: Restrict floppy access to locally logged-on user only':
      ensure       => 'present',
      policy_value => 'enabled',
    }
    local_security_policy{ 'Domain member: Digitally encrypt or sign secure channel data (always)':
      ensure       => 'present',
      policy_value => 'enabled',
    }
    local_security_policy{ 'Domain member: Digitally encrypt secure channel data (when possible)':
      ensure       => 'present',
      policy_value => 'enabled',
    }
    local_security_policy{ 'Domain member: Digitally sign secure channel data (when possible)':
      ensure       => 'present',
      policy_value => 'enabled',
    }
    local_security_policy{ 'Domain member: Disable machine account password changes':
      ensure       => 'present',
      policy_value => 'disabled',
    }
    local_security_policy{ 'Domain member: Maximum machine account password age':
      ensure       => 'present',
      policy_value => '30',
    }
    local_security_policy{ 'Domain member: Require strong (Windows 2000 or later) session key':
      ensure       => 'present',
      policy_value => 'enabled',
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

      it 'Check MinimumPasswordAge' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "MinimumPasswordAge = 1"')[:stdout].delete("\n")
        expect(r).to match(/MinimumPasswordAge = 1/)
      end

      it 'Check MaximumPasswordAge ' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "MaximumPasswordAge = 60"')[:stdout].delete("\n")
        expect(r).to match(/MaximumPasswordAge = 60/)
      end

      it 'Check MinimumPasswordLength' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "MinimumPasswordLength = 14"')[:stdout].delete("\n")
        expect(r).to match(/MinimumPasswordLength = 14/)
      end

      it 'Check PasswordComplexity ' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "PasswordComplexity = 1"')[:stdout].delete("\n")
        expect(r).to match(/PasswordComplexity = 1/)
      end

      it 'Check PasswordHistorySize  ' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "PasswordHistorySize = 24"')[:stdout].delete("\n")
        expect(r).to match(/PasswordHistorySize = 24/)
      end

      it 'Check NewGuestName ' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "NewGuestName = "')[:stdout].delete("\n")
        expect(r).to match(/NewGuestName = \"tseug\"/)
      end

      it 'Check EnableGuestAccount' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "EnableGuestAccount = 0"')[:stdout].delete("\n")
        expect(r).to match(/EnableGuestAccount = 0/)
      end

      it 'Check ClearTextPassword' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "ClearTextPassword = 0"')[:stdout].delete("\n")
        expect(r).to match(/ClearTextPassword = 0/)
      end

      it 'Check LockoutBadCount' do
        r = winrm_command(default, 'Select-String -Path C:\cfg.txt "LockoutBadCount = 10"')[:stdout].delete("\n")
        expect(r).to match(/LockoutBadCount = 10/)
      end
      # rubocop:enable Style/RegexpLiteral
    end
  end
end
