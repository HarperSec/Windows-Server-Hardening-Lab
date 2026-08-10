
# Windows Server Lab Environment

## Purpose

Before applying security hardening configurations, the Windows Server environment was reviewed to document the system, network, domain, and installed server roles.

Establishing the lab environment provides context for the security controls implemented later in the project and confirms that the server is functioning as an Active Directory Domain Controller within the `harper.local` domain.

## Environment

| Component               | Configuration                    |
| ----------------------- | -------------------------------- |
| Operating System        | Windows Server 2025              |
| Domain                  | `harper.local`                   |
| Server Name             | `HARPER-7476`                    |
| Directory Service       | Active Directory Domain Services |
| Domain Role             | Domain Controller                |
| Administration Tool     | Windows PowerShell               |
| Domain Functional Level | Windows Server 2025              |

---

## Reviewing the Server Identity

The server hostname and operating system information were reviewed before beginning the hardening process.

The following commands were used:

```powershell
hostname
```

```powershell
systeminfo
```

The `hostname` command identifies the Windows Server computer, while `systeminfo` provides detailed operating system and system configuration information.

This information was used to confirm that the correct Windows Server system was being used for the hardening lab.

![Server Identity and System Information](../screenshots/screenshots/01-01-Server-System-Information)

---

## Reviewing the Network Configuration

The server's network configuration was reviewed using the following command:

```powershell
ipconfig /all
```

This command displays detailed network adapter information including the IPv4 address, subnet configuration, default gateway, DNS configuration, and network adapter information.

Reviewing the network configuration is important before hardening a Domain Controller because Active Directory Domain Services relies heavily on properly configured networking and DNS.

![Server Network Configuration](../screenshots/02-network-configuration.png)

---

## Verifying Domain Membership

The following PowerShell command was used to verify the server's Active Directory domain configuration:

```powershell
Get-CimInstance Win32_ComputerSystem |
Select-Object Name, Domain, PartOfDomain
```

The command confirms the computer name, domain name, and whether the system is joined to an Active Directory domain.

The server was confirmed as part of the:

```text
harper.local
```

domain.

![Active Directory Domain Configuration](../screenshots/03-domain-configuration.png)

---

## Reviewing Installed Server Roles and Features

The installed Windows Server roles and features were reviewed before security changes were made.

The following command was used:

```powershell
Get-WindowsFeature |
Where-Object {$_.InstallState -eq "Installed"}
```

This command displays the Windows Server roles and features currently installed on the system.

Reviewing installed roles is an important part of server hardening because unnecessary roles and features can increase the system's attack surface.

The results also confirmed the services required for the existing Active Directory lab environment.

![Installed Windows Server Roles](../screenshots/04-installed-server-roles.png)

---

## Verification

The environment review confirmed that:

* Windows Server 2025 is running successfully.
* The server identity and operating system information can be retrieved.
* Network configuration is available and operational.
* The server belongs to the `harper.local` Active Directory domain.
* Active Directory Domain Services is present in the environment.
* Installed Windows Server roles and features can be identified for later security review.

The environment was successfully documented and was ready for the initial security baseline assessment.
