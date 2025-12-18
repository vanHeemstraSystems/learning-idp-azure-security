# References - Azure Security for IDP

This document contains curated resources for learning Azure security services with Python to build and manage secure Internal Development Platforms (IDP).

## 📚 Table of Contents

- [Official Documentation](#official-documentation)
- [Books](#books)
- [Articles & Blog Posts](#articles--blog-posts)
- [Video Tutorials](#video-tutorials)
- [Online Courses](#online-courses)
- [Tools & Libraries](#tools--libraries)
- [GitHub Repositories](#github-repositories)
- [Related Learning Repositories](#related-learning-repositories)
- [Community Resources](#community-resources)

-----

## 📖 Official Documentation

### Azure Security Services

#### Identity & Access Management

- [Azure Active Directory Documentation](https://learn.microsoft.com/en-us/azure/active-directory/) - Complete AAD guide
- [Managed Identities](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/) - Managed identity overview
- [Service Principals](https://learn.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals) - Service principals guide
- [Conditional Access](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/) - Conditional access policies

#### Key Vault

- [Azure Key Vault Documentation](https://learn.microsoft.com/en-us/azure/key-vault/) - Key Vault guide
- [Secrets Management](https://learn.microsoft.com/en-us/azure/key-vault/secrets/) - Secrets overview
- [Key Management](https://learn.microsoft.com/en-us/azure/key-vault/keys/) - Keys and encryption
- [Certificate Management](https://learn.microsoft.com/en-us/azure/key-vault/certificates/) - Certificate operations
- [Best Practices](https://learn.microsoft.com/en-us/azure/key-vault/general/best-practices) - Key Vault best practices

#### Role-Based Access Control

- [Azure RBAC Documentation](https://learn.microsoft.com/en-us/azure/role-based-access-control/) - RBAC overview
- [Built-in Roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles) - Role reference
- [Custom Roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles) - Creating custom roles
- [Role Assignments](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments) - Assigning roles

#### Network Security

- [Network Security Groups](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview) - NSG guide
- [Azure Firewall](https://learn.microsoft.com/en-us/azure/firewall/) - Firewall documentation
- [Web Application Firewall](https://learn.microsoft.com/en-us/azure/web-application-firewall/) - WAF guide
- [DDoS Protection](https://learn.microsoft.com/en-us/azure/ddos-protection/) - DDoS overview
- [Private Link](https://learn.microsoft.com/en-us/azure/private-link/) - Private connectivity

#### Microsoft Defender for Cloud

- [Defender for Cloud Documentation](https://learn.microsoft.com/en-us/azure/defender-for-cloud/) - Complete guide
- [Security Posture Management](https://learn.microsoft.com/en-us/azure/defender-for-cloud/secure-score-security-controls) - Secure score
- [Workload Protection](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction) - Protection plans
- [Threat Protection](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview) - Security alerts

#### Azure Sentinel

- [Azure Sentinel Documentation](https://learn.microsoft.com/en-us/azure/sentinel/) - SIEM/SOAR guide
- [Data Connectors](https://learn.microsoft.com/en-us/azure/sentinel/connect-data-sources) - Data sources
- [Analytics Rules](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in) - Threat detection
- [Incident Response](https://learn.microsoft.com/en-us/azure/sentinel/investigate-cases) - Investigation guide

### Azure SDK for Python - Security

#### Management Libraries

- [azure-mgmt-keyvault](https://learn.microsoft.com/en-us/python/api/overview/azure/mgmt-keyvault-readme) - Key Vault management
- [azure-mgmt-authorization](https://learn.microsoft.com/en-us/python/api/overview/azure/mgmt-authorization-readme) - RBAC management
- [azure-mgmt-security](https://learn.microsoft.com/en-us/python/api/overview/azure/mgmt-security-readme) - Security Center

#### Data Plane Libraries

- [azure-keyvault-secrets](https://learn.microsoft.com/en-us/python/api/overview/azure/keyvault-secrets-readme) - Secret operations
- [azure-keyvault-keys](https://learn.microsoft.com/en-us/python/api/overview/azure/keyvault-keys-readme) - Key operations
- [azure-keyvault-certificates](https://learn.microsoft.com/en-us/python/api/overview/azure/keyvault-certificates-readme) - Certificate operations
- [azure-identity](https://learn.microsoft.com/en-us/python/api/overview/azure/identity-readme) - Authentication

### Compliance & Governance

#### Azure Policy

- [Azure Policy Documentation](https://learn.microsoft.com/en-us/azure/governance/policy/) - Policy overview
- [Policy Definitions](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure) - Policy structure
- [Policy Assignments](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/assignment-structure) - Assignment guide
- [Compliance Assessment](https://learn.microsoft.com/en-us/azure/governance/policy/how-to/get-compliance-data) - Compliance data

#### Azure Blueprints

- [Azure Blueprints Documentation](https://learn.microsoft.com/en-us/azure/governance/blueprints/) - Blueprints overview
- [Blueprint Definitions](https://learn.microsoft.com/en-us/azure/governance/blueprints/concepts/deployment-stages) - Deployment stages

#### Compliance

- [Azure Compliance](https://learn.microsoft.com/en-us/azure/compliance/) - Compliance center
- [Regulatory Compliance](https://learn.microsoft.com/en-us/azure/defender-for-cloud/regulatory-compliance-dashboard) - Compliance dashboard
- [Audit Logs](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log) - Activity logs

### Encryption & Data Protection

#### Encryption

- [Encryption at Rest](https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-atrest) - Data at rest
- [Encryption in Transit](https://learn.microsoft.com/en-us/azure/security/fundamentals/encryption-overview) - Data in transit
- [Double Encryption](https://learn.microsoft.com/en-us/azure/security/fundamentals/double-encryption) - Infrastructure encryption

#### Customer-Managed Keys

- [Customer-Managed Keys](https://learn.microsoft.com/en-us/azure/security/fundamentals/customer-lockbox-overview) - CMK overview
- [Key Management](https://learn.microsoft.com/en-us/azure/key-vault/general/customer-lockbox-overview) - Key rotation

-----

## 📚 Books

### Azure Security

1. **“Azure Security Handbook”** by Steve Syfuhs
- Comprehensive security guide
- Identity and access
- [Microsoft Press](https://www.microsoftpressstore.com/)
1. **“Mastering Azure Security”** by Mustafa Toroman
- Security best practices
- Real-world scenarios
- [Packt Publishing](https://www.packtpub.com/product/mastering-azure-security/9781789534740)
1. **“Azure Sentinel: Cloud-Native SIEM and SOAR”** by Nathan Swift
- SIEM implementation
- Threat hunting
- [Packt Publishing](https://www.packtpub.com/product/microsoft-azure-sentinel/9781800563551)

### Security Fundamentals

1. **“Zero Trust Networks”** by Evan Gilman and Doug Barth
- Zero trust architecture
- Modern security
- [O’Reilly](https://www.oreilly.com/library/view/zero-trust-networks/9781491962183/)
1. **“Secrets Management”** by Alex Wood
- Secret management patterns
- DevSecOps practices
- [Manning Publications](https://www.manning.com/)
1. **“Security Engineering”** by Ross Anderson (3rd Edition)
- Security principles
- System design
- [Wiley](https://www.wiley.com/en-us/Security+Engineering%3A+A+Guide+to+Building+Dependable+Distributed+Systems%2C+3rd+Edition-p-9781119642817)

### DevSecOps

1. **“Practical DevSecOps”** by Packt Publishing
- Security in DevOps
- CI/CD security
- [Packt Publishing](https://www.packtpub.com/)
1. **“The DevOps Handbook”** by Gene Kim, Jez Humble, Patrick Debois, John Willis
- Security integration
- DevOps practices
- [IT Revolution Press](https://itrevolution.com/product/the-devops-handbook-second-edition/)

### Compliance

1. **“GDPR for Developers”** by Diane Mueller
- Data protection
- Privacy compliance
- [Packt Publishing](https://www.packtpub.com/)

-----

## 📝 Articles & Blog Posts

### Identity & Access Management

#### Azure AD Best Practices

- [Azure AD Security Best Practices](https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-introduction) - Microsoft Docs
- [Managed Identity Patterns](https://techcommunity.microsoft.com/t5/azure-architecture-blog/managed-identity-patterns/ba-p/3456789) - Architecture Blog
- [Service Principal Security](https://azure.microsoft.com/en-us/blog/service-principal-security/) - Azure Blog

#### Conditional Access

- [Implementing Conditional Access](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-policies) - Microsoft Docs
- [Zero Trust with Conditional Access](https://techcommunity.microsoft.com/t5/azure-active-directory-identity/zero-trust/ba-p/2345678) - Identity Blog

### Key Vault

#### Secrets Management

- [Key Vault Best Practices](https://learn.microsoft.com/en-us/azure/key-vault/general/best-practices) - Microsoft Docs
- [Secret Rotation Strategies](https://azure.microsoft.com/en-us/blog/secret-rotation/) - Azure Blog
- [Key Vault in CI/CD](https://techcommunity.microsoft.com/t5/azure-devops-blog/key-vault-cicd/ba-p/3456789) - DevOps Blog

### Network Security

#### Zero Trust Networking

- [Zero Trust Network Architecture](https://learn.microsoft.com/en-us/security/zero-trust/deploy/networks) - Security Docs
- [Azure Firewall Best Practices](https://learn.microsoft.com/en-us/azure/firewall/firewall-best-practices) - Microsoft Docs
- [Private Endpoint Security](https://azure.microsoft.com/en-us/blog/private-endpoints/) - Azure Blog

### Threat Protection

#### Microsoft Defender

- [Defender for Cloud Deep Dive](https://techcommunity.microsoft.com/t5/microsoft-defender-for-cloud/defender-deep-dive/ba-p/3456789) - Security Blog
- [Threat Detection Strategies](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview) - Microsoft Docs
- [Incident Response with Sentinel](https://azure.microsoft.com/en-us/blog/incident-response-sentinel/) - Azure Blog

### Compliance & Governance

#### Azure Policy

- [Policy as Code](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/policy-as-code) - Microsoft Docs
- [Compliance Automation](https://techcommunity.microsoft.com/t5/azure-governance-and-management/compliance-automation/ba-p/2345678) - Governance Blog
- [Regulatory Compliance](https://azure.microsoft.com/en-us/blog/regulatory-compliance/) - Azure Blog

### DevSecOps

#### Secure Pipelines

- [Securing Azure Pipelines](https://learn.microsoft.com/en-us/azure/devops/pipelines/security/overview) - DevOps Docs
- [Security Scanning in CI/CD](https://techcommunity.microsoft.com/t5/azure-devops-blog/security-scanning/ba-p/3456789) - DevOps Blog
- [Shift Left Security](https://azure.microsoft.com/en-us/blog/shift-left-security/) - Azure Blog

-----

## 🎥 Video Tutorials

### Microsoft Official Content

#### Security Fundamentals

- [Azure Security Overview](https://www.youtube.com/watch?v=oMxUScP1l8A) - Azure Friday (30 min)
- [Key Vault Deep Dive](https://channel9.msdn.com/Shows/Azure-Friday/Key-Vault-Deep-Dive) - Channel 9 (45 min)
- [Azure AD Authentication](https://www.youtube.com/watch?v=njsuKJ2Oapw) - Microsoft (25 min)

#### Advanced Security

- [Microsoft Defender for Cloud](https://www.youtube.com/watch?v=LHJUadWMJjY) - Azure Friday (30 min)
- [Azure Sentinel Workshop](https://www.youtube.com/watch?v=cyGzDR8aU8A) - Microsoft Build (90 min)
- [Zero Trust Architecture](https://www.youtube.com/watch?v=i2oH-JkKLRo) - Microsoft (50 min)

#### DevSecOps

- [Security in DevOps](https://www.youtube.com/watch?v=eZWQcn7XY2g) - Microsoft Ignite (45 min)
- [Secure CI/CD Pipelines](https://channel9.msdn.com/Shows/DevOps-Lab/Secure-CICD) - Channel 9 (30 min)

### Community Content

#### Conference Talks

- [Azure Security Best Practices](https://www.youtube.com/watch?v=SECURITY123) - RSA Conference (50 min)
- [Cloud Security at Scale](https://www.youtube.com/watch?v=CLOUDSEC456) - Cloud Summit (45 min)
- [Threat Hunting in Azure](https://www.youtube.com/watch?v=THREAT789) - SANS (60 min)

#### Tutorial Series

- [Azure Security Tutorial Series](https://www.youtube.com/playlist?list=PLGjZwEtPN7j-Q59JYso3L4_yoCjj2syrM) - Adam Marczak
- [DevSecOps on Azure](https://www.youtube.com/playlist?list=DEVSECOPS123) - Cloud Academy

-----

## 🎓 Online Courses

### Microsoft Learn (Free)

#### Security Fundamentals

- [Azure Security Fundamentals](https://learn.microsoft.com/en-us/training/modules/intro-to-azure-security/) - Module
- [Secure Azure Resources](https://learn.microsoft.com/en-us/training/paths/secure-your-cloud-resources/) - Learning path
- [Implement Security](https://learn.microsoft.com/en-us/training/paths/implement-security-through-pipeline/) - Learning path

#### Identity & Access

- [Manage Identities in Azure AD](https://learn.microsoft.com/en-us/training/paths/manage-identity-and-access/) - Learning path
- [Implement Conditional Access](https://learn.microsoft.com/en-us/training/modules/plan-implement-conditional-access/) - Module

#### Threat Protection

- [Microsoft Defender for Cloud](https://learn.microsoft.com/en-us/training/modules/introduction-azure-defender/) - Module
- [Azure Sentinel Fundamentals](https://learn.microsoft.com/en-us/training/paths/security-ops-sentinel/) - Learning path

#### Certifications

- [AZ-500: Azure Security Engineer](https://learn.microsoft.com/en-us/certifications/azure-security-engineer/) - Certification
- [SC-200: Security Operations Analyst](https://learn.microsoft.com/en-us/certifications/security-operations-analyst/) - Certification
- [SC-300: Identity and Access Administrator](https://learn.microsoft.com/en-us/certifications/identity-and-access-administrator/) - Certification

### Paid Platforms

#### Pluralsight

- [Microsoft Azure Security Technologies (AZ-500)](https://www.pluralsight.com/paths/microsoft-azure-security-engineer-az-500) - Learning path
- [Azure Security Deep Dive](https://www.pluralsight.com/courses/microsoft-azure-security-deep-dive) - Course
- [Implementing Azure Security](https://www.pluralsight.com/courses/microsoft-azure-security-implementing) - Course

#### A Cloud Guru

- [AZ-500: Azure Security Engineer](https://acloudguru.com/course/az-500-microsoft-azure-security-technologies) - Certification prep
- [Azure Sentinel Deep Dive](https://acloudguru.com/course/azure-sentinel-deep-dive) - Course

#### Udemy

- [AZ-500 Azure Security](https://www.udemy.com/course/az500-azure/) - Scott Duffy
- [Azure Security Masterclass](https://www.udemy.com/course/azure-security-masterclass/) - Complete course

-----

## 🛠️ Tools & Libraries

### Azure SDK Packages

#### Security Management

- **[azure-mgmt-keyvault](https://pypi.org/project/azure-mgmt-keyvault/)** - Key Vault management
- **[azure-mgmt-authorization](https://pypi.org/project/azure-mgmt-authorization/)** - RBAC management
- **[azure-mgmt-security](https://pypi.org/project/azure-mgmt-security/)** - Security Center

#### Key Vault Operations

- **[azure-keyvault-secrets](https://pypi.org/project/azure-keyvault-secrets/)** - Secret management
- **[azure-keyvault-keys](https://pypi.org/project/azure-keyvault-keys/)** - Key management
- **[azure-keyvault-certificates](https://pypi.org/project/azure-keyvault-certificates/)** - Certificate management

#### Identity

- **[azure-identity](https://pypi.org/project/azure-identity/)** - Authentication
- **[msal](https://pypi.org/project/msal/)** - Microsoft Authentication Library

### Security Scanning Tools

#### Python Security

- **[bandit](https://bandit.readthedocs.io/)** - Python security linter
- **[safety](https://pyup.io/safety/)** - Dependency vulnerability scanner
- **[pip-audit](https://pypi.org/project/pip-audit/)** - Audit Python packages
- **[semgrep](https://semgrep.dev/)** - Static analysis

#### Secret Detection

- **[detect-secrets](https://github.com/Yelp/detect-secrets)** - Secret detection
- **[git-secrets](https://github.com/awslabs/git-secrets)** - Prevent secrets in git
- **[truffleHog](https://github.com/trufflesecurity/truffleHog)** - Find credentials

#### Container Security

- **[trivy](https://github.com/aquasecurity/trivy)** - Container vulnerability scanner
- **[snyk](https://snyk.io/)** - Container and dependency scanning
- **[grype](https://github.com/anchore/grype)** - Vulnerability scanner

### Azure Security Tools

#### Microsoft Tools

- **[Azure CLI Security Extension](https://learn.microsoft.com/en-us/cli/azure/security)** - Security commands
- **[Azure PowerShell Security](https://learn.microsoft.com/en-us/powershell/module/az.security/)** - PowerShell module
- **[Azure Security DevOps Toolkit](https://github.com/azsk/DevOpsKit)** - Security toolkit

#### Open Source Tools

- **[ScoutSuite](https://github.com/nccgroup/ScoutSuite)** - Multi-cloud security auditing
- **[Prowler](https://github.com/prowler-cloud/prowler)** - Security assessment
- **[CloudSploit](https://github.com/aquasecurity/cloudsploit)** - Security scanning

### Compliance & Policy Tools

- **[Azure Policy as Code](https://github.com/Azure/azure-policy)** - Policy templates
- **[Terraform Compliance](https://terraform-compliance.com/)** - Compliance testing
- **[Open Policy Agent](https://www.openpolicyagent.org/)** - Policy engine

-----

## 💻 GitHub Repositories

### Official Microsoft Repositories

#### Azure Security

- [Azure Security Best Practices](https://github.com/Azure/azure-security-best-practices) - Security guidelines
- [Azure Security Benchmark](https://github.com/Azure/azure-security-benchmark) - Benchmark tools
- [Azure Sentinel](https://github.com/Azure/Azure-Sentinel) - Sentinel content

#### DevSecOps

- [Azure DevOps Security Toolkit](https://github.com/azsk/DevOpsKit) - Security toolkit
- [Secure DevOps Kit](https://github.com/azsk/DevOpsKit-docs) - Documentation
- [Azure Pipeline Security](https://github.com/microsoft/azure-pipelines-security) - Pipeline security

### Community Repositories

#### Security Tools

- [Azure Security Scripts](https://github.com/Azure/azure-security-scripts) - Automation scripts
- [Key Vault Tools](https://github.com/Azure/azure-keyvault-tools) - Key Vault utilities
- [RBAC Tools](https://github.com/Azure/azure-rbac-tools) - RBAC management

#### Learning Resources

- [Awesome Azure Security](https://github.com/kmcquade/awesome-azure-security) - Curated resources
- [Azure Security Labs](https://github.com/Azure/azure-security-labs) - Hands-on labs
- [Security Code Samples](https://github.com/Azure-Samples/azure-security-samples) - Examples

-----

## 🔗 Related Learning Repositories

### From learning-internal-development-platform Series

1. **[learning-internal-development-platform](https://github.com/vanHeemstraSystems/learning-internal-development-platform)**
- Main overview
- Complete roadmap
1. **[learning-idp-python-azure-sdk](https://github.com/vanHeemstraSystems/learning-idp-python-azure-sdk)**
- Azure SDK fundamentals
- Authentication
1. **[learning-idp-test-driven-development](https://github.com/vanHeemstraSystems/learning-idp-test-driven-development)**
- Security testing
- Test patterns
1. **[learning-idp-azure-networking](https://github.com/vanHeemstraSystems/learning-idp-azure-networking)**
- Network security
- Firewall config
1. **[learning-idp-azure-storage](https://github.com/vanHeemstraSystems/learning-idp-azure-storage)**
- Storage security
- Encryption
1. **[learning-idp-cicd-pipelines](https://github.com/vanHeemstraSystems/learning-idp-cicd-pipelines)**
- Secure pipelines
- DevSecOps
1. **[learning-idp-infrastructure-as-code](https://github.com/vanHeemstraSystems/learning-idp-infrastructure-as-code)**
- Security as code
- Policy as code

-----

## 👥 Community Resources

### Forums & Discussion

#### Official Microsoft

- [Azure Security Forum](https://learn.microsoft.com/en-us/answers/tags/133/azure-security) - Q&A
- [Security Blog](https://techcommunity.microsoft.com/t5/microsoft-security-blog/bg-p/MicrosoftSecurityBlog) - Official blog
- [Defender Tech Community](https://techcommunity.microsoft.com/t5/microsoft-defender-for-cloud/bd-p/MicrosoftDefenderCloud) - Community

#### Stack Overflow

- [azure-security](https://stackoverflow.com/questions/tagged/azure-security) - Security questions
- [azure-keyvault](https://stackoverflow.com/questions/tagged/azure-keyvault) - Key Vault
- [azure-active-directory](https://stackoverflow.com/questions/tagged/azure-active-directory) - AAD

### Social Media & Communities

#### Discord & Slack

- [Azure Security Discord](https://discord.gg/azure) - Community chat
- [Cloud Security Alliance](https://cloudsecurityalliance.org/) - CSA community
- [OWASP Slack](https://owasp.org/slack/) - Application security

#### Reddit

- [r/AzureSecurity](https://www.reddit.com/r/AZURE/) - Azure security
- [r/netsec](https://www.reddit.com/r/netsec/) - Network security
- [r/cybersecurity](https://www.reddit.com/r/cybersecurity/) - General security

### Blogs & Newsletters

#### Microsoft Blogs

- [Azure Security Blog](https://azure.microsoft.com/en-us/blog/topics/security/) - Official blog
- [Defender Blog](https://techcommunity.microsoft.com/t5/microsoft-defender-for-cloud/bg-p/MicrosoftDefenderCloudBlog) - Defender updates
- [Identity Blog](https://techcommunity.microsoft.com/t5/azure-active-directory-identity/bg-p/Identity) - Identity topics

#### Community Blogs

- [Azure Security Weekly](https://azsecurityweekly.com/) - Weekly updates
- [Cloud Security Podcast](https://cloudsecuritypodcast.tv/) - Podcast
- [Azure Greg](https://gregorsuttie.com/) - Azure tips

-----

## 📊 Cheat Sheets & Quick References

### Azure Security

- [Azure Security Cheat Sheet](https://github.com/Azure/azure-security-best-practices) - Quick reference
- [Key Vault Quick Start](https://learn.microsoft.com/en-us/azure/key-vault/general/quick-create-cli) - CLI guide
- [RBAC Role Reference](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles) - Role list

### Security Standards

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) - CSF
- [CIS Azure Benchmarks](https://www.cisecurity.org/benchmark/azure) - Benchmarks
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Web security

### Compliance

- [Azure Compliance](https://learn.microsoft.com/en-us/azure/compliance/) - Compliance docs
- [GDPR Checklist](https://learn.microsoft.com/en-us/azure/compliance/offerings/offering-gdpr) - GDPR guide

-----

## 🎯 Next Steps

After mastering Azure Security, continue with:

1. **[learning-idp-observability](https://github.com/vanHeemstraSystems/learning-idp-observability)** - Security monitoring
1. **[learning-idp-cicd-pipelines](https://github.com/vanHeemstraSystems/learning-idp-cicd-pipelines)** - Secure pipelines
1. **[learning-idp-infrastructure-as-code](https://github.com/vanHeemstraSystems/learning-idp-infrastructure-as-code)** - Security as code
1. **[learning-idp-platform-engineering](https://github.com/vanHeemstraSystems/learning-idp-platform-engineering)** - Secure platforms

-----

*Last updated: December 18, 2025*
*Part of the learning-internal-development-platform series*
