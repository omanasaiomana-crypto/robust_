/**
 * IdentityShield v3 - Attack Generator Scenarios & Payload Builders
 * Generates realistic Okta and AWS CloudTrail event batches.
 * Conforms to PRD §25.3, context.md Section 19, and Golden Rule 8.
 */

(function (window) {
  'use strict';

  // Seed data fallback (enhanced if generator/data/identities.json is loaded)
  let SEED = {
    identities: [
      {
        identity_id: "svc-report",
        name: "svc-report (Analytics Service)",
        email: "svc-report@corp.example",
        usual_city: "San Francisco",
        usual_country: "United States",
        usual_ip: "198.51.100.24",
        usual_asn: 15169,
        usual_isp: "Google LLC",
        roles: ["arn:aws:iam::123456789012:role/AnalyticsReportingRole"],
        admin_role: "arn:aws:iam::123456789012:role/OrganizationAccountAccessRole",
        target_secret: "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/credentials",
        target_bucket: "prod-analytics-exports",
        vpc_endpoint: "vpce-0a1b2c3d4e5f67890"
      },
      {
        identity_id: "sunita.deshmukh",
        name: "Sunita Deshmukh",
        email: "sunita.deshmukh@corp.example",
        usual_city: "Chennai",
        usual_country: "India",
        usual_ip: "103.50.162.71",
        usual_asn: 55836,
        usual_isp: "Reliance Jio",
        roles: ["arn:aws:iam::123456789012:role/DevOpsAdmin"],
        target_bucket: "corp-devops-artifacts",
        vpc_endpoint: "vpce-0a1b2c3d4e5f67890"
      },
      {
        identity_id: "bob.admin",
        name: "Bob Admin",
        email: "bob.admin@corp.example",
        usual_city: "San Jose",
        usual_country: "United States",
        usual_ip: "198.51.100.88",
        usual_asn: 15169,
        usual_isp: "Google LLC",
        roles: ["arn:aws:iam::123456789012:role/CloudAdmin"],
        target_secret: "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/iam/keys",
        vpc_endpoint: "vpce-0a1b2c3d4e5f67890"
      },
      {
        identity_id: "admin-corp",
        name: "Corporate Administrator",
        email: "admin@corp.example",
        usual_city: "San Francisco",
        usual_country: "United States",
        usual_ip: "198.51.100.10",
        usual_asn: 15169,
        usual_isp: "Google LLC",
        roles: ["arn:aws:iam::123456789012:role/SuperAdmin"],
        vpc_endpoint: "vpce-0a1b2c3d4e5f67890"
      }
    ],
    spray_users: [
      "alex.jones@corp.example", "brian.wilson@corp.example", "carol.danvers@corp.example",
      "david.miller@corp.example", "emma.watson@corp.example", "frank.castle@corp.example",
      "george.clark@corp.example", "helen.hunt@corp.example", "ian.wright@corp.example",
      "julia.roberts@corp.example", "kevin.bacon@corp.example", "laura.croft@corp.example",
      "michael.scott@corp.example", "natalie.portman@corp.example", "ivan.intern@corp.example"
    ],
    aws_account_id: "123456789012",
    default_region: "us-east-1"
  };

  // Try to load external identities.json if accessible
  fetch('data/identities.json')
    .then(r => r.ok ? r.json() : null)
    .then(data => { if (data) SEED = data; })
    .catch(() => { /* fallback remains active */ });

  function genId() {
    return window.crypto.randomUUID ? window.crypto.randomUUID() : 'uuid-' + Math.random().toString(36).substring(2, 12);
  }

  function isoTime(offsetSeconds = 0) {
    return new Date(Date.now() + offsetSeconds * 1000).toISOString();
  }

  /**
   * Helper to build a valid Okta System Log event.
   */
  function makeOktaEvent(opts = {}) {
    const actorEmail = opts.actorEmail || "svc-report@corp.example";
    const actorId = opts.actorId || "00u" + actorEmail.split('@')[0].replace(/[^a-zA-Z0-9]/g, '');

    return {
      uuid: opts.uuid || genId(),
      published: opts.published || isoTime(opts.offsetSeconds || 0),
      eventType: opts.eventType || "user.session.start",
      actor: {
        id: actorId,
        alternateId: actorEmail,
        displayName: opts.actorName || actorEmail.split('@')[0]
      },
      outcome: {
        result: opts.outcomeResult || "SUCCESS",
        reason: opts.outcomeReason || undefined
      },
      client: {
        ipAddress: opts.ipAddress || "198.51.100.24",
        userAgent: {
          rawUserAgent: opts.userAgent || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
        },
        geographicalContext: {
          country: opts.country || "United States",
          city: opts.city || "San Francisco",
          geolocation: opts.geolocation || { lat: 37.7749, lon: -122.4194 }
        }
      },
      authenticationContext: {
        externalSessionId: opts.sessionId || "okta:sess-" + genId().substring(0, 8)
      },
      securityContext: {
        asNumber: opts.asn || 15169,
        asOrg: opts.asOrg || "Google LLC",
        isp: opts.isp || "Google LLC",
        isProxy: Boolean(opts.isProxy),
        isHosting: Boolean(opts.isHosting)
      }
    };
  }

  /**
   * Helper to build a valid AWS CloudTrail record.
   */
  function makeCloudTrailEvent(opts = {}) {
    return {
      eventID: opts.eventID || genId(),
      eventTime: opts.eventTime || isoTime(opts.offsetSeconds || 0),
      eventName: opts.eventName || "GetCallerIdentity",
      eventSource: opts.eventSource || "sts.amazonaws.com",
      awsRegion: opts.awsRegion || "us-east-1",
      sourceIPAddress: opts.sourceIPAddress || "198.51.100.24",
      userAgent: opts.userAgent || "aws-sdk-python/1.34.0 Boto3/1.34.0 Python/3.11.8",
      userIdentity: opts.userIdentity || {
        type: "IAMUser",
        userName: opts.userName || "svc-report",
        arn: "arn:aws:iam::123456789012:user/" + (opts.userName || "svc-report"),
        accessKeyId: opts.accessKeyId || "AKIA" + genId().replace(/-/g, '').substring(0, 16).toUpperCase()
      },
      requestParameters: opts.requestParameters || {},
      responseElements: opts.responseElements || {},
      resources: opts.resources || [
        { ARN: "arn:aws:sts::123456789012:user" }
      ],
      vpcEndpointId: opts.vpcEndpointId || undefined
    };
  }

  // ---------------------------------------------------------------------------
  // SCENARIO DEFINITIONS (PRD §25.3)
  // ---------------------------------------------------------------------------

  const SCENARIOS = {
    // -------------------------------------------------------------------------
    // N1: Normal Workday
    // -------------------------------------------------------------------------
    N1: {
      id: "N1",
      title: "Normal Workday",
      category: "baseline",
      description: "Benign Okta login from San Francisco followed by routine CloudTrail read calls.",
      expectedOutcome: "No case created (Risk < 20)",
      buildBatches: () => {
        const sessId = "okta:sess-norm-" + genId().substring(0, 6);
        const oktaBatch = {
          source: "okta",
          sender_id: "laptop-generator",
          batch_id: "batch-n1-okta-" + genId().substring(0, 6),
          events: [
            makeOktaEvent({
              actorEmail: "svc-report@corp.example",
              sessionId: sessId,
              offsetSeconds: -10
            })
          ]
        };

        const ctBatch = {
          source: "cloudtrail",
          sender_id: "laptop-generator",
          batch_id: "batch-n1-ct-" + genId().substring(0, 6),
          events: [
            makeCloudTrailEvent({
              eventName: "GetCallerIdentity",
              eventSource: "sts.amazonaws.com",
              userName: "svc-report",
              offsetSeconds: -8
            }),
            makeCloudTrailEvent({
              eventName: "DescribeInstances",
              eventSource: "ec2.amazonaws.com",
              userName: "svc-report",
              offsetSeconds: -5
            }),
            makeCloudTrailEvent({
              eventName: "ListBuckets",
              eventSource: "s3.amazonaws.com",
              userName: "svc-report",
              offsetSeconds: -2
            })
          ]
        };

        return [oktaBatch, ctBatch];
      }
    },

    // -------------------------------------------------------------------------
    // E1: Okta Login -> AWS Escalation (HERO SCENARIO)
    // -------------------------------------------------------------------------
    E1: {
      id: "E1",
      title: "Okta Login → AWS Escalation",
      category: "hero",
      description: "Hero scenario: Anomaly login (Lagos) → SAML AssumeRole → CreateAccessKey → AttachUserPolicy (Admin) → AssumeRole → GetSecretValue.",
      expectedOutcome: "Case Risk ≥ 90, Restrict Applied, Revoke Pending",
      buildBatches: () => {
        const sessId = "okta:sess-hero-" + genId().substring(0, 6);
        const attackerIp = "102.89.23.4"; // Lagos, Nigeria
        const roleSessionName = "svc-report-session";
        const newAccessKey = "AKIAATTACK" + genId().replace(/-/g, '').substring(0, 10).toUpperCase();

        const oktaBatch = {
          source: "okta",
          sender_id: "laptop-generator",
          batch_id: "batch-e1-okta-" + genId().substring(0, 6),
          events: [
            makeOktaEvent({
              actorEmail: "svc-report@corp.example",
              ipAddress: attackerIp,
              country: "Nigeria",
              city: "Lagos",
              geolocation: { lat: 6.5244, lon: 3.3792 },
              asn: 37148,
              asOrg: "MTN Nigeria",
              sessionId: sessId,
              offsetSeconds: -15
            })
          ]
        };

        const ctBatch = {
          source: "cloudtrail",
          sender_id: "laptop-generator",
          batch_id: "batch-e1-ct-" + genId().substring(0, 6),
          events: [
            // 1. SAML AssumeRole
            makeCloudTrailEvent({
              eventName: "AssumeRoleWithSAML",
              eventSource: "sts.amazonaws.com",
              sourceIPAddress: attackerIp,
              offsetSeconds: -12,
              userIdentity: {
                type: "FederatedUser",
                userName: "svc-report@corp.example",
                arn: "arn:aws:sts::123456789012:federated-user/svc-report@corp.example"
              },
              requestParameters: {
                roleArn: "arn:aws:iam::123456789012:role/AnalyticsReportingRole",
                principalArn: "arn:aws:iam::123456789012:saml-provider/Okta"
              }
            }),
            // 2. CreateAccessKey
            makeCloudTrailEvent({
              eventName: "CreateAccessKey",
              eventSource: "iam.amazonaws.com",
              sourceIPAddress: attackerIp,
              offsetSeconds: -9,
              userIdentity: {
                type: "AssumedRole",
                arn: "arn:aws:sts::123456789012:assumed-role/AnalyticsReportingRole/" + roleSessionName,
                userName: roleSessionName
              },
              requestParameters: { userName: "svc-report" },
              responseElements: { accessKey: { accessKeyId: newAccessKey, status: "Active" } }
            }),
            // 3. AttachUserPolicy (Admin)
            makeCloudTrailEvent({
              eventName: "AttachUserPolicy",
              eventSource: "iam.amazonaws.com",
              sourceIPAddress: attackerIp,
              offsetSeconds: -6,
              userIdentity: {
                type: "IAMUser",
                userName: "svc-report",
                arn: "arn:aws:iam::123456789012:user/svc-report",
                accessKeyId: newAccessKey
              },
              requestParameters: {
                userName: "svc-report",
                policyArn: "arn:aws:iam::aws:policy/AdministratorAccess"
              }
            }),
            // 4. AssumeRole into OrganizationAccountAccessRole
            makeCloudTrailEvent({
              eventName: "AssumeRole",
              eventSource: "sts.amazonaws.com",
              sourceIPAddress: attackerIp,
              offsetSeconds: -3,
              userIdentity: {
                type: "IAMUser",
                userName: "svc-report",
                arn: "arn:aws:iam::123456789012:user/svc-report",
                accessKeyId: newAccessKey
              },
              requestParameters: {
                roleArn: "arn:aws:iam::123456789012:role/OrganizationAccountAccessRole",
                roleSessionName: "AdminEscalatedSession"
              }
            }),
            // 5. GetSecretValue
            makeCloudTrailEvent({
              eventName: "GetSecretValue",
              eventSource: "secretsmanager.amazonaws.com",
              sourceIPAddress: attackerIp,
              offsetSeconds: -1,
              userIdentity: {
                type: "AssumedRole",
                arn: "arn:aws:sts::123456789012:assumed-role/OrganizationAccountAccessRole/AdminEscalatedSession",
                userName: "AdminEscalatedSession"
              },
              requestParameters: {
                secretId: "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/credentials"
              }
            })
          ]
        };

        return [oktaBatch, ctBatch];
      }
    },

    // -------------------------------------------------------------------------
    // E2: Slow Escalation (Spread over 48h)
    // -------------------------------------------------------------------------
    E2: {
      id: "E2",
      title: "Slow Escalation (48h Spread)",
      category: "evasion",
      description: "Same attack chain as E1, but timestamps are spread over 48 hours to evade short correlation windows.",
      expectedOutcome: "Single Correlated Case across 48h",
      buildBatches: () => {
        const attackerIp = "102.89.23.4";
        const newAccessKey = "AKIASLOW" + genId().replace(/-/g, '').substring(0, 10).toUpperCase();

        const oktaBatch = {
          source: "okta",
          sender_id: "laptop-generator",
          batch_id: "batch-e2-okta-" + genId().substring(0, 6),
          events: [
            makeOktaEvent({
              actorEmail: "svc-report@corp.example",
              ipAddress: attackerIp,
              country: "Nigeria",
              city: "Lagos",
              offsetSeconds: -172800 // 48h ago
            })
          ]
        };

        const ctBatch = {
          source: "cloudtrail",
          sender_id: "laptop-generator",
          batch_id: "batch-e2-ct-" + genId().substring(0, 6),
          events: [
            makeCloudTrailEvent({
              eventName: "AssumeRoleWithSAML",
              sourceIPAddress: attackerIp,
              offsetSeconds: -129600 // 36h ago
            }),
            makeCloudTrailEvent({
              eventName: "CreateAccessKey",
              sourceIPAddress: attackerIp,
              offsetSeconds: -86400, // 24h ago
              requestParameters: { userName: "svc-report" },
              responseElements: { accessKey: { accessKeyId: newAccessKey } }
            }),
            makeCloudTrailEvent({
              eventName: "AttachUserPolicy",
              sourceIPAddress: attackerIp,
              offsetSeconds: -43200, // 12h ago
              requestParameters: {
                userName: "svc-report",
                policyArn: "arn:aws:iam::aws:policy/AdministratorAccess"
              }
            }),
            makeCloudTrailEvent({
              eventName: "AssumeRole",
              sourceIPAddress: attackerIp,
              offsetSeconds: -7200, // 2h ago
              requestParameters: {
                roleArn: "arn:aws:iam::123456789012:role/OrganizationAccountAccessRole"
              }
            }),
            makeCloudTrailEvent({
              eventName: "GetSecretValue",
              sourceIPAddress: attackerIp,
              offsetSeconds: -300 // 5m ago
            })
          ]
        };

        return [oktaBatch, ctBatch];
      }
    },

    // -------------------------------------------------------------------------
    // E3: Spoofed User Agent
    // -------------------------------------------------------------------------
    E3: {
      id: "E3",
      title: "Spoofed User-Agent",
      category: "evasion",
      description: "E1 attack chain, but masking attacker signatures with a standard corporate Windows Chrome User-Agent.",
      expectedOutcome: "Risk ≥ 90 (UA drift low weight; attack chain dominates)",
      buildBatches: () => {
        const spoofedUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36";
        const batches = SCENARIOS.E1.buildBatches();
        batches.forEach(b => {
          b.events.forEach(ev => {
            if (ev.client && ev.client.userAgent) ev.client.userAgent.rawUserAgent = spoofedUA;
            if (ev.userAgent) ev.userAgent = spoofedUA;
          });
        });
        return batches;
      }
    },

    // -------------------------------------------------------------------------
    // E4: Foreign VPC Endpoint Misuse
    // -------------------------------------------------------------------------
    E4: {
      id: "E4",
      title: "Foreign VPC Endpoint Misuse",
      category: "evasion",
      description: "EC2 instance role credentials used from an external non-AWS IP and unexpected foreign VPC endpoint.",
      expectedOutcome: "D-CRD-04 Triggered, Case Elevated",
      buildBatches: () => {
        const ctBatch = {
          source: "cloudtrail",
          sender_id: "laptop-generator",
          batch_id: "batch-e4-ct-" + genId().substring(0, 6),
          events: [
            makeCloudTrailEvent({
              eventName: "ListBuckets",
              eventSource: "s3.amazonaws.com",
              sourceIPAddress: "198.51.100.250", // External IP
              vpcEndpointId: "vpce-foreign-9999", // Unexpected VPC endpoint
              userIdentity: {
                type: "AssumedRole",
                userName: "ec2-worker-role",
                arn: "arn:aws:sts::123456789012:assumed-role/EC2WorkerRole/i-0123456789abcdef0"
              },
              offsetSeconds: -5
            }),
            makeCloudTrailEvent({
              eventName: "GetObject",
              eventSource: "s3.amazonaws.com",
              sourceIPAddress: "198.51.100.250",
              vpcEndpointId: "vpce-foreign-9999",
              requestParameters: { bucketName: "prod-customer-data", key: "backup.tar.gz" },
              offsetSeconds: -2
            })
          ]
        };

        return [ctBatch];
      }
    },

    // -------------------------------------------------------------------------
    // E5: Token Replay Across ASNs
    // -------------------------------------------------------------------------
    E5: {
      id: "E5",
      title: "Token Replay Across ASNs",
      category: "evasion",
      description: "Valid Okta session token replayed from a new ASN (Tor exit node) without prior re-authentication.",
      expectedOutcome: "D-SES-01 Triggered (Step-up or Restrict)",
      buildBatches: () => {
        const stolenSession = "okta:sess-replay-888";
        const oktaBatch = {
          source: "okta",
          sender_id: "laptop-generator",
          batch_id: "batch-e5-okta-" + genId().substring(0, 6),
          events: [
            // Legitimate session start in Chennai, India
            makeOktaEvent({
              actorEmail: "sunita.deshmukh@corp.example",
              ipAddress: "103.50.162.71",
              country: "India",
              city: "Chennai",
              asn: 55836,
              sessionId: stolenSession,
              offsetSeconds: -60
            }),
            // Stolen session call from Tor exit node in Germany
            makeOktaEvent({
              eventType: "user.authentication.verify",
              actorEmail: "sunita.deshmukh@corp.example",
              ipAddress: "185.220.101.5",
              country: "Germany",
              city: "Frankfurt",
              asn: 60729,
              asOrg: "Tor Exit Node Network",
              sessionId: stolenSession,
              offsetSeconds: -10
            })
          ]
        };

        return [oktaBatch];
      }
    },

    // -------------------------------------------------------------------------
    // E6: MFA Fatigue Attack
    // -------------------------------------------------------------------------
    E6: {
      id: "E6",
      title: "MFA Fatigue Attack",
      category: "evasion",
      description: "7 consecutive denied Okta Verify push notifications followed by 1 accept, then privileged IAM calls.",
      expectedOutcome: "D-SES-02 Case Triggered (MFA Fatigue Detected)",
      buildBatches: () => {
        const events = [];
        // 7 denies within 35 seconds
        for (let i = 0; i < 7; i++) {
          events.push(makeOktaEvent({
            eventType: "user.mfa.okta_verify.deny",
            actorEmail: "bob.admin@corp.example",
            outcomeResult: "FAILURE",
            outcomeReason: "USER_REJECTED",
            offsetSeconds: -45 + (i * 4)
          }));
        }
        // 1 accept
        events.push(makeOktaEvent({
          eventType: "user.mfa.okta_verify.accept",
          actorEmail: "bob.admin@corp.example",
          outcomeResult: "SUCCESS",
          offsetSeconds: -10
        }));

        const oktaBatch = {
          source: "okta",
          sender_id: "laptop-generator",
          batch_id: "batch-e6-okta-" + genId().substring(0, 6),
          events: events
        };

        const ctBatch = {
          source: "cloudtrail",
          sender_id: "laptop-generator",
          batch_id: "batch-e6-ct-" + genId().substring(0, 6),
          events: [
            makeCloudTrailEvent({
              eventName: "CreateUser",
              eventSource: "iam.amazonaws.com",
              userName: "bob.admin",
              requestParameters: { userName: "backdoor-admin" },
              offsetSeconds: -5
            })
          ]
        };

        return [oktaBatch, ctBatch];
      }
    },

    // -------------------------------------------------------------------------
    // E7: Blind the Monitors (Defense Evasion)
    // -------------------------------------------------------------------------
    E7: {
      id: "E7",
      title: "Blind the Monitors (Defense Evasion)",
      category: "evasion",
      description: "Attacker disables CloudTrail logging and deletes GuardDuty detector immediately following login.",
      expectedOutcome: "PB-04 Defense Evasion Override → Immediate Restrict",
      buildBatches: () => {
        const ctBatch = {
          source: "cloudtrail",
          sender_id: "laptop-generator",
          batch_id: "batch-e7-ct-" + genId().substring(0, 6),
          events: [
            makeCloudTrailEvent({
              eventName: "StopLogging",
              eventSource: "cloudtrail.amazonaws.com",
              userName: "admin-corp",
              requestParameters: { name: "arn:aws:cloudtrail:us-east-1:123456789012:trail/security-trail" },
              offsetSeconds: -8
            }),
            makeCloudTrailEvent({
              eventName: "DeleteDetector",
              eventSource: "guardduty.amazonaws.com",
              userName: "admin-corp",
              requestParameters: { detectorId: "1234567890abcdef1234567890abcdef" },
              offsetSeconds: -5
            }),
            makeCloudTrailEvent({
              eventName: "PutEventSelectors",
              eventSource: "cloudtrail.amazonaws.com",
              userName: "admin-corp",
              offsetSeconds: -2
            })
          ]
        };

        return [ctBatch];
      }
    },

    // -------------------------------------------------------------------------
    // E8: Hosting Proxy Login
    // -------------------------------------------------------------------------
    E8: {
      id: "E8",
      title: "Hosting Proxy Login (Unusual Hour)",
      category: "evasion",
      description: "Privileged admin login from a known hosting/cloud provider ASN (DigitalOcean) at 3:17 AM UTC.",
      expectedOutcome: "D-ACC-04 + D-ACC-03 Triggered (Step-up)",
      buildBatches: () => {
        // Construct 03:17:00 UTC timestamp on current date
        const d = new Date();
        d.setUTCHours(3, 17, 0, 0);

        const oktaBatch = {
          source: "okta",
          sender_id: "laptop-generator",
          batch_id: "batch-e8-okta-" + genId().substring(0, 6),
          events: [
            makeOktaEvent({
              actorEmail: "bob.admin@corp.example",
              published: d.toISOString(),
              ipAddress: "167.99.145.22",
              country: "Netherlands",
              city: "Amsterdam",
              asn: 14061,
              asOrg: "DigitalOcean LLC",
              isp: "DigitalOcean",
              isHosting: true
            })
          ]
        };

        return [oktaBatch];
      }
    },

    // -------------------------------------------------------------------------
    // E9: Distributed Password Spray
    // -------------------------------------------------------------------------
    E9: {
      id: "E9",
      title: "Password Spray Campaign",
      category: "campaign",
      description: "Attacker IP targets 15 corporate users with invalid credentials, followed by 1 successful compromise.",
      expectedOutcome: "D-CMP-01 Campaign Created & Attacker IP Blocked",
      buildBatches: () => {
        const attackerIp = "194.26.29.112";
        const events = [];
        const sprayUsers = SEED.spray_users.slice(0, 15);

        // 14 failures
        for (let i = 0; i < 14; i++) {
          events.push(makeOktaEvent({
            actorEmail: sprayUsers[i],
            ipAddress: attackerIp,
            outcomeResult: "FAILURE",
            outcomeReason: "INVALID_CREDENTIALS",
            offsetSeconds: -90 + (i * 5)
          }));
        }

        // 15th: Successful login
        events.push(makeOktaEvent({
          actorEmail: sprayUsers[14], // ivan.intern@corp.example
          ipAddress: attackerIp,
          outcomeResult: "SUCCESS",
          offsetSeconds: -5
        }));

        const oktaBatch = {
          source: "okta",
          sender_id: "laptop-generator",
          batch_id: "batch-e9-okta-" + genId().substring(0, 6),
          events: events
        };

        return [oktaBatch];
      }
    }
  };

  // ---------------------------------------------------------------------------
  // TAMPER TEST BUILDERS (PRD §25.3, T1-T5)
  // ---------------------------------------------------------------------------

  const TAMPER_TESTS = {
    T1: {
      id: "T1",
      title: "Unsigned Request (No Headers)",
      description: "Omit all X-IS-* authentication headers.",
      expectedStatus: 401,
      options: { omitHeaders: true }
    },
    T2: {
      id: "T2",
      title: "Corrupted Signature",
      description: "Send invalid HMAC-SHA256 signature hash.",
      expectedStatus: 401,
      options: { tamperSignature: "deadbeef00000000111122223333444455556666777788889999aaaabbbbcccc" }
    },
    T3: {
      id: "T3",
      title: "Stale Timestamp (Skew > 60s)",
      description: "Timestamp 120 seconds in the past to test clock skew guard.",
      expectedStatus: 401,
      options: { timestamp: Math.floor(Date.now() / 1000) - 120 }
    },
    T4: {
      id: "T4",
      title: "Replayed Nonce",
      description: "Send exact same nonce twice; second request must be rejected.",
      expectedStatus: 401,
      isReplay: true
    },
    T5: {
      id: "T5",
      title: "Oversized Payload (> 1.0 MB)",
      description: "Send payload exceeding the 1 MB body size ceiling (1.2 MB).",
      expectedStatus: 413,
      isOversized: true
    }
  };

  /**
   * Generates a benign background noise batch.
   */
  function buildNoiseBatch(eventCount = 10) {
    const ident = SEED.identities[Math.floor(Math.random() * SEED.identities.length)];
    const source = Math.random() > 0.5 ? "okta" : "cloudtrail";
    const events = [];

    for (let i = 0; i < Math.min(eventCount, 20); i++) {
      if (source === "okta") {
        events.push(makeOktaEvent({
          actorEmail: ident.email,
          ipAddress: ident.usual_ip,
          country: ident.usual_country,
          city: ident.usual_city,
          asn: ident.usual_asn,
          offsetSeconds: -i * 2
        }));
      } else {
        const apis = ["DescribeInstances", "GetCallerIdentity", "ListBuckets", "GetObject", "DescribeRegions"];
        events.push(makeCloudTrailEvent({
          eventName: apis[Math.floor(Math.random() * apis.length)],
          userName: ident.identity_id,
          sourceIPAddress: ident.usual_ip,
          offsetSeconds: -i * 2
        }));
      }
    }

    return {
      source: source,
      sender_id: "laptop-generator-noise",
      batch_id: "batch-noise-" + genId().substring(0, 6),
      events: events
    };
  }

  // Export to global window object
  window.ShieldScenarios = {
    SCENARIOS,
    TAMPER_TESTS,
    buildNoiseBatch,
    makeOktaEvent,
    makeCloudTrailEvent
  };
})(window);
