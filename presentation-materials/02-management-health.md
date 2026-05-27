# RAG Scan Stack - Management & Service Health Guide
**Operations, Monitoring & Administrative Tasks**

---

## Table of Contents

1. **Platform Administration Overview**
2. **Service Health Monitoring**
3. **Container & Service Management**
4. **Performance Monitoring & Metrics**
5. **Database Administration**
6. **User Management & Security**
7. **Backup & Recovery**
8. **Troubleshooting Guide**
9. **Maintenance Procedures**

---

## 1. Platform Administration Overview

### Administrative Responsibilities
- **🔧 Service Health Monitoring**: Ensure all components are operational
- **📊 Performance Management**: Monitor resource usage and optimize performance  
- **🔐 Security Administration**: Manage access controls and audit logging
- **💾 Data Management**: Backup, recovery, and data lifecycle policies
- **🔄 Update Management**: Apply security patches and feature updates
- **📈 Capacity Planning**: Scale resources based on testing demands

### Admin Access Methods
```bash
# Dashboard Admin Interface
https://localhost:3002/settings → System Administration

# Direct Container Access
docker exec -it <container-name> /bin/bash

# Database Administration
docker exec -it rag-postgres psql -U app -d scans

# Log Monitoring
docker compose logs -f <service-name>
```

---

## 2. Service Health Monitoring

![System Diagnostics](screenshots-complete/08-operations/diagnostics.png)


### Health Dashboard Overview

#### Real-Time Service Status
Navigate to: **Dashboard → Health Overview** or **Settings → System Status**

```
Service Categories:
🟢 Core Services: Essential platform components
🟡 Scanner Services: Vulnerability scanning engines  
🔵 AI Services: Machine learning and agent frameworks
🟣 Optional Services: Enhanced features and integrations
⚪ External Services: Third-party dependencies
```

#### Service Health Indicators
```
Status Colors:
✅ Healthy (Green): Service operational, all checks passing
⚠️ Degraded (Yellow): Service functional with non-critical issues
❌ Unhealthy (Red): Service down or critical failure
⏸️ Stopped (Gray): Service intentionally disabled
🔄 Starting (Blue): Service initializing or restarting
```

### Core Service Monitoring

#### Essential Services (Must be Healthy)
```
✅ rag-api: Main API server and data coordination
✅ pentest-dashboard: Web interface and BFF proxy
✅ rag-postgres: Primary database (if using local DB)
✅ container-logs: Service orchestration and Docker management
✅ embedder: Text processing and AI feature extraction
```

#### Critical Health Checks
- **Database Connectivity**: Connection pool status and query response times
- **API Response Times**: Service latency and throughput metrics
- **Memory Usage**: Container resource consumption and limits
- **Disk Space**: Storage utilization and available capacity
- **Network Connectivity**: Inter-service communication status

### Scanner Service Monitoring

#### Vulnerability Scanners
```
🔍 Scanning Services:
✅ nmap_scanner: Port discovery and service enumeration
✅ nuclei-runner: Template-based vulnerability detection
✅ web-scanner: Web application security testing
✅ playwright-scanner: Modern JavaScript application testing
✅ osint-runner: Open source intelligence gathering
✅ pd-runner: Network discovery and fingerprinting
✅ brutus-runner: Credential testing and brute force
```

#### Scanner Health Metrics
- **Queue Depth**: Pending scan jobs and processing capacity
- **Tool Availability**: Scanner binary status and version checking
- **Template Updates**: Nuclei template refresh and signature currency
- **Resource Usage**: CPU and memory consumption during scans
- **Error Rates**: Failed scan percentages and common failure modes

---

## 3. Container & Service Management

![Services Management](screenshots-complete/08-operations/services-management.png)


### Service Control Interface

#### Navigate to: Settings → Services

#### Profile-Based Service Groups
```
Service Profiles:
🔧 Core: Essential platform services (always running)
🔍 Scan: Vulnerability scanning engines
🤖 AI: Machine learning and agent services  
🎯 Offensive: Red team and exploitation tools
🔗 SSH-Tunnel: Remote access and tunneling
⚙️ Optional: Enhanced features (GPU, Kong, etc.)
```

#### Service Control Operations
```
Available Actions:
▶️ Start Profile: Launch all services in a profile group
⏸️ Stop Profile: Gracefully shutdown profile services
🔄 Restart Profile: Stop and restart all services
🔧 Start Individual: Launch specific container
⏹️ Stop Individual: Stop specific container
📊 View Logs: Stream real-time container logs
📈 Resource Usage: Monitor CPU, memory, disk I/O
```

### Container Management

#### Docker Compose Operations
```bash
# Profile Management
docker compose --profile gpu up -d        # Start GPU services
docker compose --profile optional up -d   # Start optional services
docker compose down                        # Stop all services

# Service-Specific Operations  
docker compose restart rag-api           # Restart API server
docker compose logs -f nuclei-runner     # Stream scanner logs
docker compose ps                        # Show running containers
```

#### Individual Container Management
```bash
# Container Operations
docker stop <container-name>             # Graceful shutdown
docker start <container-name>            # Start stopped container
docker restart <container-name>          # Stop and start
docker exec -it <container-name> bash    # Interactive shell

# Resource Monitoring
docker stats                             # Real-time resource usage
docker inspect <container-name>          # Detailed container info
docker logs --tail 100 <container-name>  # Recent log output
```

### Health Check Configuration

#### Automated Health Monitoring
```yaml
Health Check Intervals:
- API Services: 15-20 second intervals
- Scanners: 20-30 second intervals  
- Database: 10 second intervals
- Optional Services: 30 second intervals

Failure Thresholds:
- Retries: 3-5 attempts before marking unhealthy
- Timeout: 5-10 seconds per health check
- Start Period: 30-120 seconds for initialization
```

---

## 4. Performance Monitoring & Metrics

![OpSec Dashboard](screenshots-complete/08-operations/opsec-dashboard.png)


### Resource Monitoring

#### System-Level Metrics
```bash
# Host Resource Usage
htop                    # Interactive process monitor
df -h                   # Disk space usage
free -h                 # Memory utilization
iostat                  # Disk I/O statistics
```

#### Container Resource Monitoring
- **CPU Usage**: Per-container processor utilization
- **Memory Consumption**: RAM usage and swap activity  
- **Disk I/O**: Read/write operations and throughput
- **Network Traffic**: Inter-service communication volume
- **Storage Usage**: Persistent volume utilization

### Performance Dashboards

#### Navigate to: Settings → Diagnostics

#### Key Performance Indicators
```
Platform KPIs:
📊 Scan Throughput: Targets processed per hour
⏱️ Average Response Time: API latency percentiles  
🎯 Success Rate: Successful scan completion percentage
💾 Data Processing: Findings ingested per minute
🔄 Queue Performance: Job processing and wait times
```

#### Service-Specific Metrics
```
Per-Service Monitoring:
🔍 Scanner Performance: Tool execution times and success rates
🤖 AI Processing: Model inference latency and accuracy
💾 Database Performance: Query times and connection pooling
🌐 Web Interface: Page load times and user interactions
```

### Alerting & Notifications

#### Critical Alert Conditions
- **Service Downtime**: Core service failure or restart
- **Resource Exhaustion**: CPU, memory, or disk threshold exceeded
- **Database Issues**: Connection failures or slow queries
- **Security Events**: Authentication failures or unauthorized access
- **Scan Failures**: High error rates or tool unavailability

#### Alert Delivery Methods
- **Dashboard Notifications**: In-app alerts and status indicators
- **Email Alerts**: Administrative notifications for critical issues
- **Webhook Integration**: External monitoring system integration
- **Log-Based Alerts**: Pattern matching in service logs

---

## 5. Database Administration

### Database Overview

#### Supported Configurations
- **Local PostgreSQL**: Single-node database in `rag-postgres` container
- **Remote PostgreSQL**: External database with SSH tunnel support
- **High Availability**: Master/replica configurations for production
- **Cloud Managed**: AWS RDS, Azure Database, GCP Cloud SQL integration

### Database Health Monitoring

#### Navigate to: Settings → System Status → Database Section

#### Critical Database Metrics
```
Database KPIs:
🔗 Active Connections: Current client connections vs. pool limits
⚡ Query Performance: Average execution time and slow queries
💾 Storage Usage: Database size growth and available space
🔄 Replication Status: Master/replica sync lag (if applicable)
🔒 Lock Contention: Blocking queries and deadlock frequency
```

#### Connection Pool Management
```
Pool Configuration:
- Max Connections: Typically 10-50 based on workload
- Idle Timeout: Automatic connection cleanup (300 seconds)
- Health Checks: Connection validation queries
- Overflow Handling: Queue management for peak demand
```

### Database Maintenance

#### Regular Maintenance Tasks
```sql
-- Connection Status
SELECT count(*), state FROM pg_stat_activity GROUP BY state;

-- Database Size
SELECT pg_size_pretty(pg_database_size('scans'));

-- Active Queries  
SELECT pid, usename, application_name, state, query 
FROM pg_stat_activity WHERE state = 'active';

-- Index Usage
SELECT schemaname, tablename, indexname, idx_tup_read, idx_tup_fetch
FROM pg_stat_user_indexes ORDER BY idx_tup_read DESC LIMIT 10;
```

#### Backup & Recovery
```bash
# Database Backup
docker exec rag-postgres pg_dump -U app scans > backup.sql

# Full System Backup
docker run --rm -v rag-pgdata:/data -v $(pwd):/backup ubuntu \
  tar czf /backup/database-backup.tar.gz /data

# Recovery Operation
docker exec -i rag-postgres psql -U app scans < backup.sql
```

### Schema Management

#### Migration Tracking
- **Version Control**: Database schema versioning with migration scripts
- **Rollback Capability**: Safe schema changes with rollback procedures
- **Testing**: Schema validation in development before production
- **Documentation**: Change logs and impact assessment

---

## 6. User Management & Security

### Authentication & Authorization

#### User Access Control
```
Authentication Methods:
🔑 API Key: Service-to-service authentication
🖥️ Session-Based: Web interface user sessions
🔐 Certificate Auth: mTLS for service communication
🛡️ OAuth Integration: Enterprise SSO (planned feature)
```

#### Role-Based Access Control
```
User Roles:
👑 Administrator: Full system access and configuration
🔧 Operator: Scan execution and findings management  
👀 Viewer: Read-only access to findings and reports
🤖 Service Account: API-only access for integrations
```

### Security Configuration

#### Navigate to: Settings → Security

#### API Security Management
- **API Key Generation**: Secure key creation with expiration dates
- **Rate Limiting**: Request throttling to prevent abuse
- **IP Restrictions**: Source IP whitelist for sensitive operations
- **Audit Logging**: Complete access log with user attribution

#### Network Security
```
Security Controls:
🔒 TLS Encryption: All service communication encrypted
🛡️ Container Isolation: Network segmentation between services
🚪 Firewall Rules: Minimal exposed ports and access control
🔐 Certificate Management: Automated SSL certificate rotation
```

### Audit & Compliance

#### Security Monitoring
- **Access Logs**: User authentication and authorization events
- **Configuration Changes**: System modification tracking with rollback
- **Data Access**: Findings and sensitive data access logging
- **Failed Attempts**: Security event monitoring and alerting

#### Compliance Features
- **Data Retention**: Configurable retention policies for findings
- **Export Controls**: Secure data export with audit trails  
- **Privacy Controls**: PII handling and data anonymization
- **Regulatory Reporting**: Compliance report generation

---

## 7. Backup & Recovery

### Backup Strategy

#### Automated Backup Components
```
Backup Scope:
💾 Database: Full PostgreSQL backup with point-in-time recovery
🗂️ Configuration: Service configurations and environment settings
🔑 Secrets: Encrypted backup of keys, certificates, and credentials
📊 Scan Data: Findings, reports, and evidence files
📈 Metrics: Historical performance and audit data
```

#### Backup Frequency & Retention
```
Backup Schedule:
📅 Daily: Full database backup with 30-day retention
🕐 Hourly: Transaction log backup for point-in-time recovery
📅 Weekly: Complete system backup with 90-day retention
📅 Monthly: Archive backup with 1-year retention
```

### Recovery Procedures

#### Recovery Scenarios
1. **Service Restart**: Container or service-level recovery
2. **Data Corruption**: Database rollback to known good state
3. **Complete System Failure**: Full platform restoration
4. **Partial Data Loss**: Selective recovery of specific components

#### Recovery Time Objectives
```
Recovery Metrics:
🎯 RTO (Recovery Time Objective): 2-4 hours for full system
📊 RPO (Recovery Point Objective): 1 hour maximum data loss
⚡ Service Restart: 5-15 minutes for individual services
🔄 Database Recovery: 30-60 minutes for full restoration
```

### Disaster Recovery

#### High Availability Configuration
- **Database Replication**: Master/standby configuration with automatic failover
- **Load Balancing**: Distributed service deployment across multiple nodes  
- **Geographic Distribution**: Multi-site deployment for disaster recovery
- **Cloud Integration**: Hybrid on-premise/cloud backup strategies

---

## 8. Troubleshooting Guide

### Common Issues & Solutions

#### Service Startup Failures
```bash
# Check container status
docker compose ps

# View startup logs
docker compose logs <service-name>

# Common solutions
docker compose pull                    # Update images
docker compose down && docker compose up -d  # Full restart
docker system prune                   # Clean up resources
```

#### Database Connection Issues
```bash
# Test database connectivity
docker exec rag-postgres pg_isready -U app -d scans

# Check connection pool
docker exec rag-api python -c "
from api import db
print(db.engine.pool.status())
"

# Reset connections
docker compose restart rag-api rag-postgres
```

#### Scanner Tool Failures
```bash
# Check tool availability
docker exec nuclei-runner nuclei -version
docker exec nmap_scanner nmap --version

# Update scanner databases
docker exec nuclei-runner nuclei -update-templates
docker exec osint-runner /usr/bin/update-tools.sh

# Clear scan queue
docker exec rag-api python -c "
from api import clear_scan_queue
clear_scan_queue()
"
```

### Performance Issues

#### High Resource Usage
```bash
# Identify resource-hungry containers
docker stats --no-stream

# Check system resources
df -h                          # Disk space
free -h                        # Memory usage
top -p $(pgrep -d',' -f docker) # Docker processes
```

#### Slow Response Times
1. **Database Performance**: Check slow queries and connection pool
2. **Network Latency**: Verify inter-service communication
3. **Resource Contention**: Monitor CPU and memory utilization
4. **Disk I/O**: Check storage performance and available space

### Log Analysis

#### Centralized Log Collection
```bash
# View all service logs
docker compose logs --tail=100 -f

# Service-specific logs
docker compose logs rag-api --tail=50
docker compose logs nuclei-runner --since=1h

# Error pattern search
docker compose logs | grep -i error
docker compose logs | grep -i "failed\|exception\|timeout"
```

#### Log Level Configuration
- **DEBUG**: Detailed execution information for development
- **INFO**: Normal operation events and status updates
- **WARN**: Non-critical issues that may need attention
- **ERROR**: Service errors requiring immediate investigation
- **CRITICAL**: System failures requiring immediate response

---

## 9. Maintenance Procedures

### Regular Maintenance Tasks

#### Daily Maintenance
```bash
# Health check verification
curl -k https://localhost:3002/api/health

# Database maintenance
docker exec rag-postgres psql -U app -d scans -c "VACUUM ANALYZE;"

# Log rotation
docker system prune --filter "until=24h"

# Resource monitoring
docker stats --no-stream | head -10
```

#### Weekly Maintenance
```bash
# Update scanner templates
docker exec nuclei-runner nuclei -update-templates
docker exec osint-runner /scripts/update-wordlists.sh

# Database optimization
docker exec rag-postgres psql -U app -d scans -c "REINDEX DATABASE scans;"

# Security scanning
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image --severity HIGH,CRITICAL rag-scan-stack-*
```

#### Monthly Maintenance
- **System Updates**: Apply security patches and minor updates
- **Capacity Planning**: Review resource usage trends and plan scaling
- **Security Audit**: Review access logs and security configurations
- **Backup Verification**: Test backup restore procedures
- **Performance Review**: Analyze metrics and optimize configurations

### Update Management

#### Version Control Strategy
```
Update Categories:
🔒 Security Patches: Apply immediately for critical vulnerabilities
🐛 Bug Fixes: Apply during scheduled maintenance windows
✨ Feature Updates: Plan deployment with stakeholder approval
🔧 Configuration Changes: Test in development before production
```

#### Update Procedure
1. **Backup Current State**: Full system backup before changes
2. **Update in Development**: Test updates in non-production environment
3. **Plan Maintenance Window**: Schedule downtime with stakeholders
4. **Apply Updates**: Execute changes with rollback capability
5. **Validate Functionality**: Comprehensive testing post-update
6. **Document Changes**: Update documentation and notify users

### Monitoring & Alerting Maintenance

#### Alert Tuning
- **Threshold Adjustment**: Optimize alert thresholds based on historical data
- **False Positive Reduction**: Refine alert conditions to reduce noise
- **Escalation Procedures**: Update contact information and escalation paths
- **Integration Testing**: Verify external monitoring system integration

---

## Emergency Procedures

### Critical System Failure
1. **Immediate Response**: Assess scope of failure and potential causes
2. **Service Isolation**: Stop affected services to prevent cascade failures
3. **Stakeholder Notification**: Alert management and affected users
4. **Recovery Execution**: Follow documented recovery procedures
5. **Root Cause Analysis**: Post-incident investigation and remediation
6. **Process Improvement**: Update procedures based on lessons learned

### Security Incident Response
1. **Incident Detection**: Identify and classify security events
2. **Containment**: Isolate affected systems and limit damage
3. **Evidence Preservation**: Secure logs and forensic evidence
4. **Communication**: Notify security team and management
5. **Recovery**: Restore systems to secure operational state
6. **Post-Incident Review**: Analyze response and improve security controls

---

## Conclusion

Effective management of the RAG Scan Stack requires proactive monitoring, regular maintenance, and rapid response to issues. This guide provides the foundation for maintaining a healthy, secure, and high-performing security testing platform.

**Key Success Factors:**
- ✅ **Proactive Monitoring**: Continuous health checks and performance monitoring
- ✅ **Automated Maintenance**: Scheduled tasks and automated recovery procedures  
- ✅ **Documentation**: Maintain current procedures and configuration documentation
- ✅ **Training**: Ensure operational team understands platform architecture and procedures
- ✅ **Testing**: Regular disaster recovery and incident response testing

**For Additional Support:**
- **📚 Technical Documentation**: Platform architecture and API reference
- **🛠️ Troubleshooting Wiki**: Community-contributed solutions and best practices
- **📞 Emergency Contacts**: Escalation procedures for critical issues
- **💬 Operations Channel**: Team communication for coordination and knowledge sharing