# Architectural Lessons Learned

## Database Management in Container-Logs Service (Anti-Pattern)

**Problem**: Database configuration management was incorrectly placed in the `container-logs` service.

**Why This Is Wrong**:
- **Single Responsibility Principle Violation**: A logging service should only handle logs, not database configuration
- **Service Boundaries**: Configuration management belongs in configuration services, not logging services
- **Debugging Nightmare**: When database toggle doesn't work, developers look in database/config services, not logging services
- **Maintenance Burden**: Future developers have to hunt through unrelated services to find functionality

**Root Cause**: Feature creep without architectural governance. Database management functionality was added to the first available service rather than the correct one.

**Impact**:
- Remote database toggle functionality is unreliable
- Developer confusion about where functionality lives
- HTTP connectivity issues between services
- Difficult to test and maintain

**Proper Solution**:
1. **Move to BFF**: Database configuration should be managed directly in the BFF or delegated to rag-api
2. **Clear Service Boundaries**: Each service has a single, well-defined responsibility
3. **Webhooks**: All configuration changes emit proper webhook events for external integrations

**Lesson**: Always ask "Does this functionality belong in this service?" before implementing. Architecture violations compound over time.

---

## Why This Happened

Database configuration was likely added to container-logs because:
1. It already had file system access (.env mounting)
2. It was "convenient" - quick implementation
3. No architectural review process

**Prevention**: 
- Code reviews should include architectural concerns
- Service responsibility documentation
- Clear boundaries in docker-compose service definitions