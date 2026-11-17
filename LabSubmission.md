## Q1 (explore). Tests as security controls

A delivery pipeline is an automated path code that takes from initial commit to production; however, it is essential to protect the pipeline to prevent malicious actors from using the pipeline to steal credentials or ship malicious code. The core practice is enabling least-privilege access. (Peterson, 2026).

To avoid bad changes in production, running the tests in the test stage in the delivery pipeline invokes automated tests. Unit tests are executed to validate individual components of the application i.e., denied access via  SSH port 22. At the same time, integration tests run to verify how different parts of the app work together including the MFA requirement. 

However, with this approach it has limitations that cannot catch including; 

1.	Insufficient access control A test may confirm that the launch script does not explicitly open port 22, but it cannot guarantee that port 22 is not exposed through another security group, network ACL, firewall rule, or externally managed configuration. For example, another infrastructure component could unintentionally expose SSH even when the launch script remains unchanged. This happened to LastPass in 2022 when attackers gained access to portions of their source code and proprietary technical information in their development environment. (Palmer, 2023).

2.	Secret Leaks Sometimes developers inadvertently commit code containing secrets like API keys, passwords, or cryptographic keys. Attackers can exploit these exposed secrets and gain unauthorized access to critical systems and services. (National Security Agency(NSA), 2023). This happened in 2017 to Uber, when their GitHub repository was accidentally exposed. The repository contained access credentials. Attackers discovered and exploited these credentials to gain unauthorized access to Uber’s AWS account, compromising the personal data of nearly 60 million users (Sharwood, 2018).

Tools such as AWS IAM Access Analyzer, CloudFormation (cfn) guard, and Open Policy Agent (OPA) provide broader, rule-based validation, enforcing security and compliance requirements across infrastructure configurations. On the other hand, secret scanning in create_repo.sh refuses to commit anything that looks like an access key or private key; however, it cannot guarantee that all secrets or credential exposure paths are identified.

## Q2. Why does Nimbus-RequireMFA use BoolIfExists rather than Bool?

Nimbus-RequireMFA uses BoolIfExists rather than Bool to ensure that the MFA condition is evaluated safely, including when the aws:MultiFactorAuthPresent context key is missing from the request.
In AWS IAM policies:  Bool evaluates the condition only when the specified context key exists and has a matching Boolean value, while BoolIfExists also evaluates the condition when the key is absent. For a Deny statement, an absent key satisfies the BoolIfExists condition. (AWS). Therefore, helps prevent requests from bypassing the MFA requirement.

## Q3. In TechTeam-DevScoped, why is a Deny still useful when no Allow grants IAM access?
A Deny statement in TechTeam-DevScoped is still useful because it provides an explicit security boundary, even when no Allow statement grants IAM permissions.
AWS IAM follows the principle of implicit deny: if no applicable Allow statement grants permission, the request is denied by default.

## Q4 (explore). Group membership as an escalation path.

The most valuable group for an attacker to join would be SecurityTeam. It provides IAM read and audit permissions and allows policy authoring under policy/nimbus/. If an attacker compromises the onboarding service and adds a newly created user to this group, the attacker could potentially manipulate IAM policies within that permitted namespace, creating opportunities for privilege escalation depending on the permissions available to attach or use those policies.

Comparing the protective controls:

- Permissions boundary; limits the maximum permissions a user can receive. For example, the onboarding service could attach a boundary to every newly created user that permits only approved onboarding and basic access. Even if an attacker adds the user to SecurityTeam, the user's effective permissions remain restricted by that boundary (AWS).

- Condition on the group; the onboarding role currently has the ability to add users to groups under the /nimbus/ path. I would restrict it so that it can only add users to the approved onboarding group. For example, the relevant IAM permission could be restricted by using the iam:GroupName condition key. (AWS)

- Service Control Policy (SCP); a SCP provides organization-level permission guardrails across AWS accounts. For example, a SCP could explicitly deny sensitive IAM administrative actions, preventing an attacker from performing prohibited operations even if an IAM policy grants them. (AWS)

Therefore, I would choose the group condition as the primary control because it closes the vulnerability at its source.

## Q5. Name three places the admin password could have ended up if you had not used Secrets Manager. Why is each one worse?

If Secrets Manager had not been used, the admin password could have ended up in these places;

- Hardcoded in the creation script; the password could have been written directly into the script that creates the buckets and configures the web login. Why worse: Other users or processes with sufficient access could retrieve it. Files might also be backed up, shared, or accidentally committed to source control.

- CloudWatch log groups; the password could accidentally have been printed into deployment or application logs. Why worse: Multiple administrators or developers might have permission to read the logs. The password could also remain in retained log records long after deployment.

- Local configuration file or terminal history; the password could have been saved in a local file or entered directly into a terminal command. Why worse: Other users or processes with sufficient access could retrieve it. Files might also be backed up, shared, or accidentally committed to source control.

AWS Secrets Manager keeps the password separate from the application code and infrastructure configuration. Access can be controlled through IAM, and secret retrieval can be audited through CloudTrail (AWSSecrets Manager). You can read it again later with aws secretsmanager get-secret-value --secret-id nimbus/web-login.

## Q6. What does the TLS only bucket policy stop that Block Public Access does not?

The TLS-only bucket policy prevents S3 data from being accessed over an unencrypted connection (HTTP), whereas S3 Block Public Access prevents public exposure of bucket data.

## Q7 (explore). Customer managed keys.

A customer managed key does not necessarily make the encryption algorithm stronger. Its main advantage is giving the customer greater control over who can administer, use, disable, rotate, and audit the encryption key. A customer managed key provides control over operations such as: Disabling or scheduling deletion of the key, Configuring key rotation, Managing grants, Reviewing key usage through CloudTrail (AWSCustomer ManagedKeys).

A key policy is a resource policy for an AWS KMS key. Key policies are the primary way to control access to KMS keys. Every KMS key must have exactly one key policy. The statements in the key policy determine who has permission to use the KMS key and how they can use it. You can also use IAM policies and grants to control access to the KMS key, but every KMS key must have a key policy.

Therefore, a key policy would ensure No AWS principal, including the account root user or key creator, has any permissions to a KMS key unless they are explicitly allowed, and never denied, in a key policy, IAM policy, or grant. (AWSKey Policies).

Moving to customer managed KMS introduces costs such as; Monthly key charges for maintaining customer managed keys, API requests encrypt, decrypt, and data-key generation operations can incur request charges, Key rotation may have pricing implications depending on the key type and configuration, and monitoring CloudTrail events and security monitoring can increase logging costs (AWSKMS Pricing).

Customer managed keys provide more control, but that control introduces operational risks;

Accidental key deletion; an administrator could schedule a key for deletion. Once the deletion process is completed, encrypted data that depends on that key may become permanently unrecoverable. Incorrect key policy; a poorly configured policy could prevent legitimate application roles from using the key or even lock administrators out of key management (AWSKMS Security).

## Q8. For each of the three simulator results, name the Principal, Action, Resource and Request context, and say which statement decided it.
1.	Test: Can onboarding attach AdministratorAccess? Expected: implicitDeny

            Principal: nimbus-onboarding-svc IAM role
            
            Action: iam:AttachUserPolicy
            
            Resource: arn:aws:iam:: 092454132131:user/nimbus/alice
            
            Request context:
            
            iam:PolicyARN = arn:aws:iam:aws:policy/AdministratorAccess
            
            The request attempts to attach the AWS-managed AdministratorAccess policy to Alice
            
            Which statement decided it? implicitDeny.

2.	Test: Can onboarding attach Nimbus-RequireMFA? Expected: allowed 

            Principal: nimbus-onboarding-svc IAM role.
            
            Action: iam:AttachUserPolicy
            
            Resource: arn:aws:iam::ACCT:user/nimbus/alice
            
            Request context:
            
            iam:PolicyARN = arn:aws:iam:: 092454132131:policy/nimbus/Nimbus-RequireMFA
            
            The request attempts to attach the approved MFA guard policy to Alice.
            
            Which statement decided it?  Allow.

3.	Test: Can onboarding modify your lab user? Expected: implicitDeny
            Principal: nimbus-onboarding-svc IAM role.
  	
            Action: iam:CreateLoginProfile
  	
            Resource: arn:aws:iam:: 092454132131:user/lab-user
  	
            Request context:
  	
            - The request attempts to create a login profile for an existing lab user outside the intended onboarding scope.
  	
            Which statement decided it? implicitDeny.

## Q9 (Explore). Four containers, one host

The EC2 instance uses the Instance Metadata Service (IMDS), which provides information and temporary credentials associated with the instance profile (AWSIMDS). The IMDSv2 response hop limit controls the IP TTL (IPv4) or hop limit (IPv6) of metadata responses, this is important because container networking may introduce an additional network hop between the container and the host metadata service. A hop limit of 2 does not automatically guarantee that every container can access IMDS. Network configuration, metadata endpoint settings, host firewall rules, and container isolation also matter (AWSHop Limit).

If all four containers can access the same instance role, compromising one container could expose credentials with permissions intended for other services (MacCárthaigh, 2019).
Comparing redesign options on isolation, cost and operational effort.

| Design | Isolation | Cost	| Operational effort |
|---|---|---|---|
| one instance per service | Stronger than sharing one instance because compromising one instance does not automatically expose the instance role of another| High Four instances require additional compute, storage, and potentially networking resources | Moderate to high administrators must maintain multiple operating systems patching schedules, monitoring configurations, and deployments | 
| Container task roles on Amazon ECS | Strong IAM permissions are separated at task level rather than shared across the EC2 instance | Moderate to low incremental cost multiple tasks can share the same EC2 infrastructure, avoiding the need for a separate instance per service | Moderate. Requires ECS task definitions, task roles service configuration and proper metadata endpoint restrictions | 
| Pod-level identity on Kubernetes | Strong, provided service accounts, pod permissions, and node metadata access are configured correctly | Low to moderate incremental infrastructure cost because multiple pods can share worker nodes However EKS cluster and control-plane costs must be considered | High compared with a straightforward EC2 deployment Requires Kubernetes expertise service-account management IAM integration and careful workload security configuration |

## Q10. Which  events does the lab alert on, and why alert on them instead of only storing them?

- Risky IAM changes; IAM changes can give an attacker additional privileges or weaken existing security restrictions. An early notification allows security administrators to investigate suspicious changes before they are exploited.

- Console sign-in without MFA, a successful console login without MFA could indicate; an account has been configured without the required MFA protection, an attacker has obtained valid credentials, and an existing MFA enforcement control has been bypassed or misconfigured. Alerting allows administrators to investigate potentially compromised accounts and take corrective action.

## Q11 (Explore). Blind spots in detection.

Two attacker actions against IAM that these rules would miss include but not limited to:

- Credential Theft and Token Hijacking; Attackers target valid user or machine credentials to impersonate legitimate identities and bypass standard perimeter defenses. (FBI)
- Privilege Escalation via Policy Misconfigurations; An attacker could create a new access key for an existing IAM user and use it to access AWS resources programmatically. This is particularly dangerous because the attacker could maintain access even if the legitimate user is unaware of the compromise.
The following event pattern detects attempts to create a login profile for an existing IAM user:

            *{
  
            "source":["aws.iam"],"detail-type":["AWS API Call via CloudTrail"],
  
            "detail":{
  
            "eventSource":["iam.amazonaws.com"],
  
             	"eventName": ["CreateAccessKey"]
  
            }
  
            }*
  
Alert fatigue occurs when security teams receive too many alerts, including false positives and low-priority notifications. When analysts are overwhelmed with notifications, they may overlook genuine malicious activities or become desensitized to repeated warnings.

Amazon GuardDuty takes a broader threat-detection approach than manually configured EventBridge rules. Rather than relying only on predefined API event names, GuardDuty continuously analyzes supported AWS data sources, including CloudTrail management events, VPC Flow Logs, and DNS logs. It uses threat intelligence, anomaly detection, and machine learning to identify potentially malicious activity (AWS GuardDuty).

## Q12. Why is there no SSH and no key pair, and how do you debug the server without them?
There is no SSH access or key pair because the lab is designed to demonstrate a more secure AWS server-management approach using AWS Systems Manager (SSM) Session Manager instead of traditional SSH access. SSH typically requires opening port 22 and managing private keys. This introduces additional security risks, such as exposed SSH ports, stolen private keys, and unauthorized remote access (AWSessiion Manager).

## Q13. If the web container were compromised, what does egress filtering stop and what does it not stop?
Egress filtering restricts the outbound network connections that a compromised web container can establish. The default allow-all outbound rule is removed, and only ports 443 (HTTPS) and 80 (HTTP) are permitted.

## Q14 (explore). Certificates and trust on first use
Manually comparing the fingerprint of a self-signed certificate protects against a Man-in-the-Middle (MITM) attack. A self-signed certificate is not automatically trusted by browsers because it has not been issued by a trusted Certificate Authority (CA). Therefore, manually comparing its fingerprint against a fingerprint obtained through a trusted, independent channel helps verify that the certificate belongs to the intended server. If the fingerprints match, there is stronger evidence that the administrator is connecting to the correct server (SSLTrust).

AWS Certificate Manager behind a load balancer: ACM can provision a publicly trusted TLS certificate and attach it to an Application Load Balancer (ALB). The load balancer terminates HTTPS connections and presents the certificate to clients. ACM also handles renewal for eligible certificates, reducing manual certificate management (AWSRepost).

Public Certificate Authority: Organizations can obtain certificates from trusted CAs such as DigiCert or Let's Encrypt. Browsers already trust their root certificates, so users generally do not need to verify fingerprints manually. The browser validates the certificate chain, hostname, validity period, and other certificate requirements (Digicert).

An ACM public certificate is itself backed by a publicly trusted CA, so it benefits from the same browser trust model (AWSCert Manager).

HTTP Strict Transport Security (HSTS) is a security mechanism that instructs browsers to communicate with a website using HTTPS only (Mozilla org).

Certificate Transparency (CT) provides publicly auditable logs of issued TLS certificates. It helps detect situations where a CA mistakenly or maliciously issues a certificate for a domain without the legitimate owner's authorization (Certificate Transparency).

## Q15. Which of the six checks proved encryption in transit, which proved a smaller attack surface, and which proved protection against password guessing?

- Encryption in Transit; Check 1 – HTTPS works, plain HTTP does not, Check 2 – Security headers.
- Smaller attack surface; Check 3 – SSH and the old port are closed, Check 5 – Security group rules and VPC endpoints.
- Protection against password guessing; Check 4 – Login lockout after repeated failed attempts

## Q16. Why does the same user and action get denied without MFA and allowed with it? Quote the condition key?

The same user and action are denied without MFA and allowed with MFA because the IAM policy requires multi-factor authentication (MFA) for the requested operation.

The condition key is:
"Condition": {
        	"BoolIfExists": {
          		"aws:MultiFactorAuthPresent": "false"
}
}
##Q17. Who created mallory and how did you find out? Why does the audit trail in S3 not show it?

## Q18 (explore). Replacing IAM users with single sign on.

Adopting AWS IAM Identity Center with an external Identity Provider (IdP), such as Microsoft Entra ID or Okta, changes how users authenticate and access AWS accounts. Instead of managing individual IAM users and passwords, the company can centralize authentication and access management through its identity provider.

Which parts of the lab become unnecessary? Some IAM configurations would become less necessary because authentication and user lifecycle management would move to the external IdP.
- Creating individual IAM users: Employees would authenticate through the external identity provider rather than requiring separate IAM user accounts.
- Managing IAM passwords: Password policies and password resets would primarily be handled by the external IdP.
- Manually managing MFA for IAM users: MFA enforcement could be centralized through the IdP.
- Creating individual IAM access keys for employees: Users would generally obtain temporary AWS credentials through Identity Center rather than relying on long-lived access keys.
- Manually creating and deleting employee accounts: User provisioning and deprovisioning could be automated through SCIM synchronization. For example, when an employee leaves the company, disabling their identity in the external IdP can prevent future authentication through Identity Center.

Which parts of the lab still matter? Moving authentication to an external IdP does not eliminate the need for AWS security controls. The following lab components remain important:

- IAM policies - Control what authenticated identities can do in AWS.
- Least privilege - Ensure users receive only the permissions required for their jobs.
- MFA - Protects access to the external identity provider.
- CloudTrail - Records AWS API activity for auditing and investigations.
- EventBridge alerts - Detect suspicious AWS activities, including IAM changes.
- GuardDuty - Identifies potentially malicious activity and compromised credentials.
- Security groups - Restrict network access to AWS resources.
- Egress filtering - Limits unauthorized outbound connections.
- HTTPS and security headers - Protect application communications.
- S3 audit logging	 - Preserves security and operational records.
What new risks appear? Introducing an external identity provider creates additional security dependencies.
- Identity provider compromise - If an attacker compromises an employee's Microsoft Entra ID or Okta account, they may gain access to connected AWS accounts.
- Excessive federation permissions - Incorrectly configured permission sets or group assignments could give employees access to AWS resources beyond their responsibilities.
- Session and token theft - Attackers may steal authentication tokens or session credentials and use them to access AWS resources without needing the employee's password.
- SCIM provisioning mistakes - Incorrect provisioning or deprovisioning configurations could leave former employees with active access or assign excessive permissions to newly created accounts.
- Identity provider outage - If the external IdP becomes unavailable, employees may be unable to authenticate and access AWS resources, affecting business operations.
- Federation trust misconfiguration - Incorrect trust relationships, SAML configuration, or identity attribute mappings could allow unauthorized identities to obtain AWS access.
## Q19. Why is a token rotation safe with no restart, and what would break if the services accepted only the current token?

Token rotation is safe without restarting services because the application supports multiple valid tokens during a transition period. Instead of immediately invalidating the old token, the system temporarily accepts both the old and new tokens.

If services accepted only the current token, immediately replacing the old token could cause several problems; users with sessions relying on the old token could be logged out, applications still using the old token would receive authentication failures, API requests containing the previous token could fail with HTTP 401 Unauthorized, background jobs or processes using cached credentials could stop working, and service availability  could become unavailable until they retrieve and start using the new token.
