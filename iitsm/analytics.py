"""Reporting and analytics engine generating operational dashboard metrics."""
from datetime import datetime
from typing import Any, Dict, List

from .enums import Priority, SLAStatus, Status
from .models import Technician
from .sla import incident_sla_status


class DashboardAnalytics:
    def __init__(self, incident_repo, user_repo, service_repo):
        self.incidents = incident_repo
        self.users = user_repo
        self.services = service_repo

    def get_incident_overview(self, incidents=None) -> Dict[str, Any]:
        all_incidents = self.incidents.all() if incidents is None else incidents
        now = datetime.now()

        total = len(all_incidents)
        open_count = sum(1 for i in all_incidents if i.status not in (Status.RESOLVED, Status.VERIFIED, Status.CLOSED))
        critical = sum(1 for i in all_incidents if i.priority == Priority.P1)
        resolved = sum(1 for i in all_incidents if i.status in (Status.RESOLVED, Status.VERIFIED, Status.CLOSED))
        
        sla_violations = sum(1 for i in all_incidents if incident_sla_status(i, now) == "VIOLATED")
        at_risk = sum(1 for i in all_incidents if incident_sla_status(i, now) == "AT_RISK")

        by_priority = {
            "P1": sum(1 for i in all_incidents if i.priority == Priority.P1),
            "P2": sum(1 for i in all_incidents if i.priority == Priority.P2),
            "P3": sum(1 for i in all_incidents if i.priority == Priority.P3),
            "P4": sum(1 for i in all_incidents if i.priority == Priority.P4),
        }

        by_status = {}
        for s in Status:
            by_status[s.name] = sum(1 for i in all_incidents if i.status == s)

        sla_rate = round(((total - sla_violations) / total * 100), 1) if total > 0 else 100.0
        resolved_with_times = [i for i in all_incidents if i.resolved_at and i.created_at]
        mttr = round(sum((i.resolved_at - i.created_at).total_seconds() / 60 for i in resolved_with_times) / len(resolved_with_times), 1) if resolved_with_times else 0.0

        return {
            "total_incidents": total,
            "open_incidents": open_count,
            "critical_incidents": critical,
            "resolved_incidents": resolved,
            "closed_incidents": sum(1 for i in all_incidents if i.status == Status.CLOSED),
            "sla_violations": sla_violations,
            "at_risk_incidents": at_risk,
            "sla_compliance_rate": sla_rate,
            "mttr_minutes": mttr,
            "by_priority": by_priority,
            "priority_breakdown": by_priority,
            "by_status": by_status
        }

    def get_technician_workload_report(self) -> List[Dict[str, Any]]:
        techs = [u for u in self.users.all() if isinstance(u, Technician)]
        rows = []
        for t in sorted(techs, key=lambda x: x.id):
            utilization = round((t.workload / t.max_workload * 100), 1) if t.max_workload > 0 else 0.0
            tier_title = t.escalation_tier.title if hasattr(t, "escalation_tier") else "Technician"
            rows.append({
                "technician_id": t.id,
                "name": t.name,
                "tier": tier_title,
                "skills": sorted(t.skills),
                "experience_years": t.experience_years,
                "active_incidents": t.workload,
                "max_workload": t.max_workload,
                "utilization_percent": utilization,
                "total_resolved": getattr(t, "total_resolved", 0),
                "is_available": t.available
            })
        return rows

    def get_service_analysis_report(self) -> List[Dict[str, Any]]:
        services = self.services.all()
        all_incidents = self.incidents.all()
        now = datetime.now()
        rows = []

        for svc in sorted(services, key=lambda s: s.criticality, reverse=True):
            svc_incidents = [i for i in all_incidents if i.service.name == svc.name]
            total = len(svc_incidents)
            open_count = sum(1 for i in svc_incidents if i.status not in (Status.RESOLVED, Status.VERIFIED, Status.CLOSED))
            critical = sum(1 for i in svc_incidents if i.priority == Priority.P1)
            violations = sum(1 for i in svc_incidents if incident_sla_status(i, now) == "VIOLATED")

            rows.append({
                "service_name": svc.name,
                "criticality": svc.criticality,
                "default_category": getattr(svc, "default_category", "APPLICATION"),
                "total_incidents": total,
                "open_incidents": open_count,
                "critical_incidents": critical,
                "sla_compliance_rate": round((total - violations) / total * 100, 1) if total else 100.0,
                "sla_violations": violations
            })
        return rows

    overview = get_incident_overview
    technician_workload_report = get_technician_workload_report
    service_analysis_report = get_service_analysis_report
