# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the **BLEA (Baseline Environment on AWS) Governance Base** for standalone accounts. It's an AWS CDK project that implements security baselines and governance controls following AWS Well-Architected Framework best practices.

The project is designed to be a foundation for enterprise-grade AWS applications with built-in security monitoring, compliance controls, and automated remediation capabilities.

## Key Commands

### Development
- `npm run build` - Compile TypeScript to JavaScript
- `npm run watch` - Watch for file changes and recompile
- `npm run test` - Run Jest tests
- `npm run clean` - Clean build artifacts

### CDK Operations
- `npm run synth` - Synthesize CDK templates (quiet mode)
- `npm run cdk` - Run CDK commands directly

### Configuration
The project uses configuration parameters defined in `parameter.ts`. Update the `devParameter` object with your environment settings:
- `securityNotifyEmail` - Email for security notifications
- `securitySlackWorkspaceId` - Slack workspace for notifications
- `securitySlackChannelId` - Slack channel for notifications

## Architecture

### Core Components

**Main Stack**: `BLEAGovBaseStandaloneStack` (lib/stack/blea-gov-base-standalone-stack.ts)
- Orchestrates all security and governance components
- Implements dependency management between constructs

**Security Constructs**:
1. **IAM** (lib/construct/iam.ts) - Role-based access control with predefined roles:
   - SysAdmin: Full access with MFA requirements and billing restrictions
   - IamAdmin: IAM management with MFA requirements
   - InstanceOps: EC2/ELB operations with network restrictions
   - ReadOnlyAdmin: Read-only access across AWS services

2. **Logging** (lib/construct/logging.ts) - Comprehensive audit logging:
   - CloudTrail with KMS encryption and CloudWatch Logs integration
   - AWS Config for configuration compliance tracking
   - S3 buckets with lifecycle policies and server access logging

3. **Detection** (lib/construct/detection.ts) - Security monitoring and alerting:
   - Amazon GuardDuty for threat detection
   - AWS Security Hub for centralized security management
   - CloudWatch alarms for critical security events
   - EventBridge rules for real-time security notifications
   - Automated remediation for security group violations

4. **Notification** (lib/construct/notification.ts) - Alert delivery:
   - AWS Chatbot integration for Slack notifications
   - SNS topics for email alerts

### Security Features

**Automated Monitoring**:
- IAM policy changes detection
- Unauthorized access attempts tracking
- New access key creation alerts
- Root user activity monitoring
- Security group and Network ACL changes
- CloudTrail configuration changes

**Compliance Controls**:
- AWS Config Conformance Pack for Control Tower Detective Guardrails
- Automatic remediation for default security group violations
- KMS key rotation enabled
- S3 bucket security policies enforced

## Testing

**Test Configuration**: Jest with TypeScript support
- Tests located in `test/` directory
- Snapshot testing with custom asset serializer
- CDK construct testing with proper isolation

**Running Tests**:
```bash
npm test  # Run all tests
```

## Deployment

**Prerequisites**:
1. Configure AWS credentials
2. Update `parameter.ts` with your environment values
3. Ensure CDK is bootstrapped in your target account/region

**Deploy**:
```bash
npm run build
npm run synth  # Verify template generation
cdk deploy    # Deploy the stack
```

## Important Notes

**Security Considerations**:
- All constructs implement least privilege access
- KMS encryption is used for sensitive data (CloudTrail logs, etc.)
- Billing actions are explicitly denied for non-admin roles
- MFA is required for administrative actions
- CloudTrail and Config cannot be disabled by non-root users

**Dependencies**:
- Logging construct must be deployed before Detection (Config dependency)
- CDK version 2.x required
- Node.js 18+ recommended

**Configuration Requirements**:
- Slack workspace and channel IDs are required for notifications
- Email address must be configured for SNS notifications
- AWS account and region should be specified in parameters

The codebase follows AWS CDK best practices with proper construct composition, resource tagging, and security-first design principles.