2020-07-28 Release 3.1.2
- Rubocop ruby 2.4-strict fixes.

2018-06-12 Release 3.1.1
- fix: absent didn't work for registry policies.

2018-06-11 Release 3.1.0
- 'Privilege Rights' now supports merging of values (issue #2)
 - 'set:' will set the policy_value
 - 'merge:' will merge the policy_value
   - '+' adds a value when using 'merge'
   - '-' removes a value when using 'merge'

2018-03-22 Release 3.0.2
- 'Privilege Rights' policies now support domain accounts/groups
- made the 'Privilege Rights' policies idempotent
- the previous versions of local_security_policy used a translation tabel to convert the user names to
  SID's. Release 3.0.0 will translate the Windows user names directly to SID's.
- check your code for the correct user names. Example: BUILTIN_ADMINISTRATORS should be Administrators
- code checked with rubocop

2017-12-19 Release 2.0.1
- unknown (domain) policies already set on the system are ignored
- trying to set an unknown/invalid policy using puppet will still result in an error

2017-10-24 Release 2.0.0
- Allows a policy to be set to 'absent'.

2017-10-18 Release 1.1.2
- Fix bug in 'Allow log on locally'

2017-10-10 Release 1.1.1
- Fix settings in 'Accounts: Block Microsoft accounts'

2017-10-10 Release 1.1.0
- Fix idempotency issue for 'Microsoft network server: Server SPN target name validation level'
- Adds 6 policy settings:
  - 'Accounts: Block Microsoft accounts'
  - 'Network access: Restrict clients allowed to make remote calls to SAM'
  - 'Network security: Allow Local System to use computer identity for NTLM'
  - 'Network security: Allow LocalSystem NULL session fallback'
  - 'Network Security: Allow PKU2U authentication requests to this computer to use online identities'
  - 'Network security: Configure encryption types allowed for Kerberos'

2017-09-04 Release 1.0.7
- Fix idemportenty issue for Event Audit

2017-03-14 Release 1.0.6
- Updated acceptance tests for Windows 2016

2016-03-29 Release 1.0.5
- release for the fixed metadata

2016-03-29 Release 1.0.4
- Fixed metadata
- Updated static (Gemfile, Rakefile, .gitignore, .rspec) files.

2015-12-29 Release 1.0.3
- Fix issue with wmic bug when regional settings aren't en-US as in http://stackoverflow.com/questions/9673057/wmic-error-invalid-xsl-format-in-windows7

2015-12-17 Release 1.0.2
- Added gem to Gemfile

2015-11-9 Release 1.0.1
- Fixed path in type as workaround for Puppet bugs #14073 and #7788

2015-11-05 Release 1.0.0
- Initial release
