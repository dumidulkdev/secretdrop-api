package com.secretdrop.audit;

import com.secretdrop.audit.dto.AuditLogResponse;
import com.secretdrop.common.api.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/audit")
@Tag(name = "Audit", description = "Paged audit trail of secret lifecycle events")
public class AuditController {

    private final AuditLogRepository auditLogRepository;

    public AuditController(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    @GetMapping
    @Operation(summary = "List audit events", description = "Returns paginated audit log entries ordered by time descending.")
    public ApiResponse<Page<AuditLogResponse>> list(@PageableDefault(size = 20) Pageable pageable) {
        Page<AuditLogResponse> page = auditLogRepository.findAllByOrderByOccurredAtDesc(pageable)
                .map(entry -> new AuditLogResponse(
                        entry.getSecretIdHash(),
                        entry.getEventType(),
                        entry.getOccurredAt()));
        return ApiResponse.of(page);
    }
}