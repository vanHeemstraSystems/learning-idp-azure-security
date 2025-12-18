# Learning IDP: Azure Security

This repository focuses on mastering Azure security services using Python and Azure SDK to build, manage, and automate security infrastructure for Internal Development Platform (IDP) development.

- [References](./REFERENCES.md)

## 🎯 Learning Objectives

By working through this repository, you will:

1. Master Azure Active Directory (AAD) and identity management
1. Implement Azure Key Vault for secrets management
1. Configure Network Security and Azure Firewall
1. Work with Azure Security Center and Microsoft Defender
1. Implement Role-Based Access Control (RBAC)
1. Configure compliance and governance policies
1. Build secure CI/CD pipelines and DevSecOps practices

## 📚 Prerequisites

- Python 3.11 or higher
- Azure subscription with security admin access
- Azure CLI installed and configured
- Completed [learning-idp-python-azure-sdk](https://github.com/vanHeemstraSystems/learning-idp-python-azure-sdk)
- Basic understanding of security concepts
- Git and GitHub account

## 🗂️ Directory Structure

```
learning-idp-azure-security/
├── README.md                          # This file
├── REFERENCES.md                      # Links to resources and related repos
├── pyproject.toml                     # Python project configuration
├── requirements.txt                   # Python dependencies
├── requirements-dev.txt               # Development dependencies
├── .python-version                    # Python version for pyenv
├── .gitignore                         # Git ignore patterns
├── .env.example                       # Environment variables template
│
├── docs/
│   ├── concepts/
│   │   ├── 01-security-overview.md
│   │   ├── 02-identity-access-management.md
│   │   ├── 03-network-security.md
│   │   ├── 04-data-protection.md
│   │   ├── 05-threat-protection.md
│   │   └── 06-compliance-governance.md
│   ├── guides/
│   │   ├── getting-started.md
│   │   ├── key-vault-setup.md
│   │   ├── rbac-configuration.md
│   │   ├── security-monitoring.md
│   │   └── devsecops-practices.md
│   └── examples/
│       ├── managed-identities.md
│       ├── key-vault-integration.md
│       ├── azure-firewall-config.md
│       ├── security-policies.md
│       └── threat-detection.md
│
├── src/
│   ├── __init__.py
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── authentication.py          # Azure authentication
│   │   ├── config.py                  # Configuration management
│   │   ├── exceptions.py              # Custom exceptions
│   │   └── logging_config.py          # Logging setup
│   │
│   ├── identity/
│   │   ├── __init__.py
│   │   ├── aad_manager.py             # Azure AD operations
│   │   ├── user_manager.py            # User management
│   │   ├── group_manager.py           # Group management
│   │   ├── service_principal.py       # Service principal operations
│   │   └── managed_identity.py        # Managed identity operations
│   │
│   ├── key_vault/
│   │   ├── __init__.py
│   │   ├── vault_manager.py           # Key Vault CRUD
│   │   ├── secret_manager.py          # Secret operations
│   │   ├── key_manager.py             # Key operations
│   │   ├── certificate_manager.py     # Certificate operations
│   │   └── access_policy.py           # Access policy management
│   │
│   ├── rbac/
│   │   ├── __init__.py
│   │   ├── role_manager.py            # Role operations
│   │   ├── role_assignment.py         # Role assignment
│   │   ├── custom_roles.py            # Custom role definition
│   │   └── permissions.py             # Permission management
│   │
│   ├── network_security/
│   │   ├── __init__.py
│   │   ├── nsg_manager.py             # NSG operations
│   │   ├── firewall_manager.py        # Azure Firewall
│   │   ├── waf_manager.py             # Web Application Firewall
│   │   ├── ddos_protection.py         # DDoS protection
│   │   └── private_endpoints.py       # Private endpoint security
│   │
│   ├── data_protection/
│   │   ├── __init__.py
│   │   ├── encryption.py              # Encryption operations
│   │   ├── backup_manager.py          # Backup operations
│   │   ├── disaster_recovery.py       # DR configuration
│   │   └── data_classification.py     # Data classification
│   │
│   ├── threat_protection/
│   │   ├── __init__.py
│   │   ├── security_center.py         # Security Center operations
│   │   ├── defender.py                # Microsoft Defender
│   │   ├── sentinel.py                # Azure Sentinel
│   │   ├── threat_detection.py        # Threat detection
│   │   └── incident_response.py       # Incident response
│   │
│   ├── compliance/
│   │   ├── __init__.py
│   │   ├── policy_manager.py          # Azure Policy
│   │   ├── blueprint_manager.py       # Azure Blueprints
│   │   ├── compliance_scan.py         # Compliance scanning
│   │   └── audit_logs.py              # Audit logging
│   │
│   ├── devsecops/
│   │   ├── __init__.py
│   │   ├── security_scan.py           # Security scanning
│   │   ├── vulnerability_mgmt.py      # Vulnerability management
│   │   ├── secrets_scanning.py        # Secrets detection
│   │   └── sast_integration.py        # SAST integration
│   │
│   └── monitoring/
│       ├── __init__.py
│       ├── security_alerts.py         # Security alerts
│       ├── activity_logs.py           # Activity log analysis
│       ├── metrics.py                 # Security metrics
│       └── reporting.py               # Security reporting
│
├── examples/
│   ├── 01_identity_management/
│   │   ├── 01_create_service_principal.py
│   │   ├── 02_managed_identity.py
│   │   ├── 03_user_management.py
│   │   ├── 04_group_management.py
│   │   └── 05_conditional_access.py
│   │
│   ├── 02_key_vault/
│   │   ├── 01_create_key_vault.py
│   │   ├── 02_manage_secrets.py
│   │   ├── 03_manage_keys.py
│   │   ├── 04_manage_certificates.py
│   │   ├── 05_access_policies.py
│   │   └── 06_key_rotation.py
│   │
│   ├── 03_rbac/
│   │   ├── 01_list_roles.py
│   │   ├── 02_assign_roles.py
│   │   ├── 03_custom_roles.py
│   │   ├── 04_role_permissions.py
│   │   └── 05_least_privilege.py
│   │
│   ├── 04_network_security/
│   │   ├── 01_configure_nsg.py
│   │   ├── 02_azure_firewall.py
│   │   ├── 03_waf_configuration.py
│   │   ├── 04_ddos_protection.py
│   │   └── 05_network_isolation.py
│   │
│   ├── 05_data_protection/
│   │   ├── 01_storage_encryption.py
│   │   ├── 02_disk_encryption.py
│   │   ├── 03_backup_configuration.py
│   │   ├── 04_disaster_recovery.py
│   │   └── 05_data_classification.py
│   │
│   ├── 06_threat_protection/
│   │   ├── 01_security_center_setup.py
│   │   ├── 02_defender_for_cloud.py
│   │   ├── 03_sentinel_integration.py
│   │   ├── 04_threat_detection.py
│   │   └── 05_incident_response.py
│   │
│   ├── 07_compliance/
│   │   ├── 01_azure_policy.py
│   │   ├── 02_compliance_scanning.py
│   │   ├── 03_audit_logs.py
│   │   ├── 04_blueprints.py
│   │   └── 05_regulatory_compliance.py
│   │
│   └── 08_devsecops/
│       ├── 01_security_scanning.py
│       ├── 02_vulnerability_assessment.py
│       ├── 03_secrets_detection.py
│       ├── 04_sast_integration.py
│       └── 05_secure_pipeline.py
│
├── templates/
│   ├── policies/
│   │   ├── allowed_locations.json     # Location policy
│   │   ├── required_tags.json         # Tag policy
│   │   └── allowed_vm_sizes.json      # VM size policy
│   ├── roles/
│   │   ├── custom_reader.json         # Custom reader role
│   │   ├── security_admin.json        # Security admin role
│   │   └── network_contributor.json   # Network role
│   ├── security_center/
│   │   ├── security_contacts.json     # Security contacts
│   │   ├── pricing_tier.json          # Pricing configuration
│   │   └── auto_provisioning.json     # Auto provisioning
│   └── scripts/
│       ├── security_audit.sh          # Security audit script
│       ├── rotate_secrets.py          # Secret rotation
│       └── compliance_check.py        # Compliance checker
│
├── notebooks/
│   ├── 01_identity_basics.ipynb
│   ├── 02_key_vault_operations.ipynb
│   ├── 03_rbac_management.ipynb
│   ├── 04_threat_detection.ipynb
│   └── 05_security_monitoring.ipynb
│
├── scripts/
│   ├── setup_security_environment.sh  # Setup script
│   ├── security_hardening.sh          # Hardening script
│   ├── vulnerability_scan.py          # Vulnerability scanner
│   └── compliance_report.py           # Compliance reporting
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── unit/
│   │   ├── test_key_vault_manager.py
│   │   ├── test_rbac_manager.py
│   │   ├── test_security_center.py
│   │   └── test_policy_manager.py
│   └── integration/
│       ├── test_identity_lifecycle.py
│       ├── test_key_vault_operations.py
│       ├── test_network_security.py
│       └── test_threat_detection.py
│
└── .github/
    └── workflows/
        ├── security-scan.yml          # Security scanning
        ├── vulnerability-check.yml    # Vulnerability check
        └── compliance-test.yml        # Compliance testing
```

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/vanHeemstraSystems/learning-idp-azure-security.git
cd learning-idp-azure-security
```

### 2. Set Up Python Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/MacOS:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 3. Configure Azure Authentication

```bash
# Login to Azure
az login

# Set subscription
az account set --subscription "your-subscription-id"

# Create service principal with security permissions
az ad sp create-for-rbac \
    --name "idp-security-sp" \
    --role "Security Admin" \
    --scopes /subscriptions/{subscription-id}

# Configure environment variables
cp .env.example .env
# Edit .env with your credentials
```

### 4. Run Your First Example

```bash
# Create a Key Vault
python examples/02_key_vault/01_create_key_vault.py

# Store and retrieve a secret
python examples/02_key_vault/02_manage_secrets.py

# Create a service principal
python examples/01_identity_management/01_create_service_principal.py
```

## 📖 Learning Path

Follow this recommended sequence:

### Week 1: Identity & Access Management

**Day 1-2: Azure Active Directory**

1. Read `docs/concepts/02-identity-access-management.md`
1. Complete examples in `examples/01_identity_management/`
1. Practice service principal and managed identity creation

**Day 3-5: Key Vault**

1. Study `docs/guides/key-vault-setup.md`
1. Work through all examples in `examples/02_key_vault/`
1. Implement secret rotation and access policies

**Day 6-7: RBAC**

1. Read `docs/guides/rbac-configuration.md`
1. Complete examples in `examples/03_rbac/`
1. Practice least privilege access

### Week 2: Network & Data Security

**Day 1-3: Network Security**

1. Read `docs/concepts/03-network-security.md`
1. Work through `examples/04_network_security/`
1. Configure NSGs, Firewall, and WAF

**Day 4-7: Data Protection**

1. Study encryption methods
1. Complete examples in `examples/05_data_protection/`
1. Implement backup and disaster recovery

### Week 3: Threat Protection & Monitoring

**Day 1-3: Security Center & Defender**

1. Read `docs/concepts/05-threat-protection.md`
1. Complete examples in `examples/06_threat_protection/`
1. Configure threat detection

**Day 4-7: Compliance & Governance**

1. Study `docs/concepts/06-compliance-governance.md`
1. Work through `examples/07_compliance/`
1. Implement Azure Policy and compliance scanning

### Week 4: DevSecOps & Production

**Day 1-4: DevSecOps**

1. Read `docs/guides/devsecops-practices.md`
1. Complete examples in `examples/08_devsecops/`
1. Integrate security scanning in CI/CD

**Day 5-7: Security Operations**

1. Implement security monitoring
1. Configure alerting and incident response
1. Perform security audits

## 🔑 Key Azure SDK Packages

### Security Services

```python
# Identity Management
azure-identity>=1.15.0              # Authentication
azure-mgmt-authorization>=4.0.0     # RBAC management
azure-graphrbac>=0.61.1             # Azure AD Graph API (deprecated, use Microsoft Graph)

# Key Vault
azure-keyvault-secrets>=4.7.0       # Secret management
azure-keyvault-keys>=4.9.0          # Key management
azure-keyvault-certificates>=4.7.0  # Certificate management
azure-mgmt-keyvault>=10.2.0         # Key Vault management

# Security & Compliance
azure-mgmt-security>=5.0.0          # Security Center
azure-mgmt-policyinsights>=1.1.0    # Policy insights

# Network Security
azure-mgmt-network>=25.0.0          # Network security groups, firewall
```

## 💡 Common Operations Examples

### Create and Use Key Vault

```python
from azure.identity import DefaultAzureCredential
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.keyvault.models import (
    VaultCreateOrUpdateParameters,
    VaultProperties,
    Sku,
    SkuName,
    AccessPolicyEntry,
    Permissions,
    SecretPermissions,
    KeyPermissions
)
from azure.keyvault.secrets import SecretClient

credential = DefaultAzureCredential()
kv_mgmt_client = KeyVaultManagementClient(credential, subscription_id)

# Get current user/service principal object ID
# You'll need this for access policies
object_id = "your-object-id"  # From Azure AD

# Create Key Vault
vault_params = VaultCreateOrUpdateParameters(
    location='westeurope',
    properties=VaultProperties(
        tenant_id=tenant_id,
        sku=Sku(name=SkuName.STANDARD, family='A'),
        access_policies=[
            AccessPolicyEntry(
                tenant_id=tenant_id,
                object_id=object_id,
                permissions=Permissions(
                    secrets=[
                        SecretPermissions.GET,
                        SecretPermissions.LIST,
                        SecretPermissions.SET,
                        SecretPermissions.DELETE
                    ],
                    keys=[
                        KeyPermissions.GET,
                        KeyPermissions.LIST,
                        KeyPermissions.CREATE
                    ]
                )
            )
        ],
        enabled_for_deployment=True,
        enabled_for_disk_encryption=True,
        enabled_for_template_deployment=True,
        enable_soft_delete=True,
        soft_delete_retention_in_days=90,
        enable_purge_protection=True
    )
)

vault = kv_mgmt_client.vaults.begin_create_or_update(
    'my-rg',
    'my-keyvault',
    vault_params
).result()

print(f"Created Key Vault: {vault.name}")
print(f"Vault URI: {vault.properties.vault_uri}")

# Store secret
secret_client = SecretClient(
    vault_url=vault.properties.vault_uri,
    credential=credential
)

secret_client.set_secret("database-password", "SuperSecretP@ssw0rd!")
print("Secret stored")

# Retrieve secret
secret = secret_client.get_secret("database-password")
print(f"Retrieved secret: {secret.value}")
```

### Configure RBAC with Custom Role

```python
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.authorization.models import (
    RoleDefinition,
    Permission,
    RoleAssignment,
    RoleAssignmentCreateParameters
)
import uuid

credential = DefaultAzureCredential()
auth_client = AuthorizationManagementClient(credential, subscription_id)

# Create custom role
role_name = "Custom Storage Reader"
role_definition = RoleDefinition(
    role_name=role_name,
    description="Can read storage accounts and list keys",
    type="CustomRole",
    permissions=[
        Permission(
            actions=[
                "Microsoft.Storage/storageAccounts/read",
                "Microsoft.Storage/storageAccounts/listKeys/action"
            ],
            not_actions=[],
            data_actions=[],
            not_data_actions=[]
        )
    ],
    assignable_scopes=[
        f"/subscriptions/{subscription_id}"
    ]
)

custom_role = auth_client.role_definitions.create_or_update(
    scope=f"/subscriptions/{subscription_id}",
    role_definition_id=str(uuid.uuid4()),
    role_definition=role_definition
)
print(f"Created custom role: {custom_role.role_name}")

# Assign role to service principal
role_assignment_params = RoleAssignmentCreateParameters(
    role_definition_id=custom_role.id,
    principal_id=service_principal_object_id,
    principal_type="ServicePrincipal"
)

assignment = auth_client.role_assignments.create(
    scope=f"/subscriptions/{subscription_id}/resourceGroups/my-rg",
    role_assignment_name=str(uuid.uuid4()),
    parameters=role_assignment_params
)
print(f"Role assigned: {assignment.id}")
```

### Configure Network Security Group

```python
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient

credential = DefaultAzureCredential()
network_client = NetworkManagementClient(credential, subscription_id)

# Create NSG with security rules
nsg_params = {
    'location': 'westeurope',
    'security_rules': [
        {
            'name': 'Allow-HTTPS',
            'protocol': 'Tcp',
            'source_port_range': '*',
            'destination_port_range': '443',
            'source_address_prefix': '*',
            'destination_address_prefix': '*',
            'access': 'Allow',
            'priority': 100,
            'direction': 'Inbound',
            'description': 'Allow HTTPS traffic'
        },
        {
            'name': 'Deny-RDP',
            'protocol': 'Tcp',
            'source_port_range': '*',
            'destination_port_range': '3389',
            'source_address_prefix': '*',
            'destination_address_prefix': '*',
            'access': 'Deny',
            'priority': 200,
            'direction': 'Inbound',
            'description': 'Deny RDP access'
        },
        {
            'name': 'Deny-SSH-Internet',
            'protocol': 'Tcp',
            'source_port_range': '*',
            'destination_port_range': '22',
            'source_address_prefix': 'Internet',
            'destination_address_prefix': '*',
            'access': 'Deny',
            'priority': 210,
            'direction': 'Inbound',
            'description': 'Deny SSH from Internet'
        }
    ]
}

nsg = network_client.network_security_groups.begin_create_or_update(
    'my-rg',
    'secure-nsg',
    nsg_params
).result()

print(f"Created NSG: {nsg.name}")
print(f"Security rules: {len(nsg.security_rules)}")
```

### Configure Azure Policy

```python
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource.policy import PolicyClient
from azure.mgmt.resource.policy.models import (
    PolicyDefinition,
    PolicyAssignment
)

credential = DefaultAzureCredential()
policy_client = PolicyClient(credential, subscription_id)

# Create custom policy definition
policy_rule = {
    "if": {
        "allOf": [
            {
                "field": "type",
                "equals": "Microsoft.Storage/storageAccounts"
            },
            {
                "field": "Microsoft.Storage/storageAccounts/enableHttpsTrafficOnly",
                "equals": "false"
            }
        ]
    },
    "then": {
        "effect": "deny"
    }
}

policy_definition = PolicyDefinition(
    policy_type="Custom",
    mode="All",
    display_name="Require HTTPS for Storage Accounts",
    description="Denies storage account creation without HTTPS",
    policy_rule=policy_rule,
    metadata={
        "category": "Storage"
    }
)

custom_policy = policy_client.policy_definitions.create_or_update(
    policy_definition_name="require-https-storage",
    parameters=policy_definition
)
print(f"Created policy: {custom_policy.display_name}")

# Assign policy
policy_assignment = PolicyAssignment(
    display_name="Enforce HTTPS Storage",
    policy_definition_id=custom_policy.id,
    scope=f"/subscriptions/{subscription_id}",
    enforcement_mode="Default"
)

assignment = policy_client.policy_assignments.create(
    scope=f"/subscriptions/{subscription_id}",
    policy_assignment_name="enforce-https-storage",
    parameters=policy_assignment
)
print(f"Policy assigned: {assignment.display_name}")
```

### Enable Security Center and Defender

```python
from azure.identity import DefaultAzureCredential
from azure.mgmt.security import SecurityCenter
from azure.mgmt.security.models import (
    Pricing,
    PricingTier,
    SecurityContact,
    AutoProvisioningSetting,
    AutoProvision
)

credential = DefaultAzureCredential()
security_client = SecurityCenter(credential, subscription_id, '')

# Enable Defender for Cloud (Standard tier)
for resource_type in ['VirtualMachines', 'SqlServers', 'AppServices', 
                      'StorageAccounts', 'KeyVaults', 'Containers']:
    pricing = Pricing(pricing_tier=PricingTier.STANDARD)
    security_client.pricings.update(
        pricing_name=resource_type,
        pricing=pricing
    )
    print(f"Enabled Defender for {resource_type}")

# Configure security contact
security_contact = SecurityContact(
    email='security@example.com',
    phone='+31-123-456789',
    alert_notifications='On',
    alerts_to_admins='On'
)

security_client.security_contacts.create(
    security_contact_name='default',
    security_contact=security_contact
)
print("Security contact configured")

# Enable auto-provisioning of monitoring agent
auto_provisioning = AutoProvisioningSetting(
    auto_provision=AutoProvision.ON
)

security_client.auto_provisioning_settings.create(
    auto_provisioning_setting_name='default',
    setting=auto_provisioning
)
print("Auto-provisioning enabled")
```

## 🎯 Best Practices

### 1. Use Managed Identities

```python
# Instead of storing credentials, use managed identities
from azure.identity import ManagedIdentityCredential

# System-assigned managed identity
credential = ManagedIdentityCredential()

# User-assigned managed identity
credential = ManagedIdentityCredential(client_id="your-client-id")
```

### 2. Implement Least Privilege

```python
# Grant minimum required permissions
permissions = Permissions(
    secrets=[SecretPermissions.GET],  # Only read access
    keys=[KeyPermissions.GET],
    # Don't grant SET, DELETE unless necessary
)
```

### 3. Enable Encryption Everywhere

```python
# Storage account with encryption
storage_params = StorageAccountCreateParameters(
    # ... other params
    encryption=Encryption(
        services=EncryptionServices(
            blob=EncryptionService(enabled=True, key_type='Account'),
            file=EncryptionService(enabled=True, key_type='Account')
        ),
        key_source='Microsoft.Storage'  # Or 'Microsoft.Keyvault' for CMK
    ),
    enable_https_traffic_only=True
)
```

### 4. Implement Secret Rotation

```python
from datetime import datetime, timedelta

def rotate_secret(secret_client, secret_name):
    """Rotate secret and keep old version for transition"""
    # Get current secret
    current_secret = secret_client.get_secret(secret_name)
    
    # Generate new secret value
    new_secret_value = generate_secure_password()
    
    # Set new secret (creates new version)
    secret_client.set_secret(secret_name, new_secret_value)
    
    # Schedule old secret deletion after transition period
    # Old version remains accessible for 30 days
    print(f"Secret rotated. Old version: {current_secret.properties.version}")
```

## 🔧 Development Tools

### Security Scanning Tools

```bash
# Install security tools
pip install bandit  # Python security linter
pip install safety  # Dependency vulnerability scanner
pip install detect-secrets  # Secret detection

# Run security scans
bandit -r src/
safety check
detect-secrets scan
```

### Azure Security Tools

```bash
# Azure Security Scanner
az security assessment list

# Check compliance
az policy state list

# View security alerts
az security alert list
```

## 📊 Security Architecture Patterns

### Zero Trust Architecture

```
┌─────────────────────────────────────┐
│   Identity & Access Management      │
│   - Azure AD                         │
│   - Conditional Access               │
│   - MFA                              │
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│   Network Security                   │
│   - Network Segmentation             │
│   - Private Endpoints                │
│   - Azure Firewall                   │
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│   Data Protection                    │
│   - Encryption at Rest               │
│   - Encryption in Transit            │
│   - Key Vault                        │
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│   Threat Protection                  │
│   - Defender for Cloud               │
│   - Sentinel                         │
│   - Security Center                  │
└─────────────────────────────────────┘
```

### Defense in Depth

```
Layer 7: Data
  - Encryption, Classification, DLP
Layer 6: Application
  - WAF, API Security, Input Validation
Layer 5: Compute
  - VM Security, Container Security
Layer 4: Network
  - NSGs, Firewall, DDoS Protection
Layer 3: Perimeter
  - VPN, ExpressRoute, Private Link
Layer 2: Identity
  - AAD, MFA, Conditional Access
Layer 1: Physical
  - Azure Datacenter Security
```

## 🔗 Related Repositories

- [learning-internal-development-platform](https://github.com/vanHeemstraSystems/learning-internal-development-platform) - Main overview
- [learning-idp-python-azure-sdk](https://github.com/vanHeemstraSystems/learning-idp-python-azure-sdk) - Azure SDK fundamentals
- [learning-idp-azure-networking](https://github.com/vanHeemstraSystems/learning-idp-azure-networking) - Network security
- [learning-idp-azure-storage](https://github.com/vanHeemstraSystems/learning-idp-azure-storage) - Storage security
- [learning-idp-cicd-pipelines](https://github.com/vanHeemstraSystems/learning-idp-cicd-pipelines) - Secure pipelines

## 🤝 Contributing

This is a personal learning repository, but suggestions and improvements are welcome!

1. Fork the repository
1. Create a feature branch
1. Make your changes with tests
1. Ensure all tests pass
1. Submit a pull request

## 📄 License

This project is for educational purposes. See LICENSE file for details.

## 📧 Contact

Willem van Heemstra

- GitHub: [@vanHeemstraSystems](https://github.com/vanHeemstraSystems)
- LinkedIn: [Willem van Heemstra](https://www.linkedin.com/in/willemvanheemstra/)

-----

*Last updated: December 18, 2025*
*Part of the learning-internal-development-platform series*
