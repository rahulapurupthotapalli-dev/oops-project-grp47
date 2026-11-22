# Intelligent IT Service Management & Incident Resolution System (I-ITSM)

Enterprise IT Service Management and Incident Resolution Platform designed around Object-Oriented Programming (OOP) principles and GoF Design Patterns.

Developed for CS F213 / MAC F212 Object Oriented Programming, Semester-I 2026-2027, BITS Pilani, Hyderabad Campus.

[![Live Demo on Vercel](https://img.shields.io/badge/Live_Demo-Vercel-black?style=for-the-badge&logo=vercel)](https://oops-project-grp47.vercel.app/)

> 🌐 **Live Demo**: [https://oops-project-grp47.vercel.app/](https://oops-project-grp47.vercel.app/)

---

## Key Features

- **Full Incident Lifecycle**: Enforces valid sequential transitions (`NEW` -> `CLASSIFIED` -> `ASSIGNED` -> `ACKNOWLEDGED` -> `IN_PROGRESS` -> `RESOLVED` -> `VERIFIED` -> `CLOSED`) and rejects illegal state jumps via the **State Pattern**.
- **Dynamic Priority Engine**: Calculates priorities (P1 Critical through P4 Low) dynamically using service business criticality, impact, urgency, and affected users scale with crowd multiplier.
- **Runtime Swappable Assignment Strategies**: Supports Skill-Based, Load-Based, and Round-Robin technician allocation via the **Strategy Pattern**, swappable on the fly by administrators.
- **4-Tier Automated Escalation Hierarchy**: Escalates unresolved or SLA-breaching tickets across Support Engineers (Tier 1), Team Leads (Tier 2), Systems Administrators (Tier 3), and IT Operations Managers (Tier 4).
- **Proactive SLA Management**: Computes response and resolution deadlines per priority tier, alerts at 80% duration threshold, and executes automated breach sweeps every 60 seconds.
- **Decoupled Notifications & Immutable Audit Trail**: Dispatches notifications across In-App and Email channels while recording an append-only audit trail using the **Observer Pattern**.
- **AI-Assisted Diagnostics & Resolution Engine**: Matches similar historical resolved incidents via token similarity and provides diagnostic checklists and root-cause hypotheses (Innovation Challenge, +10 marks).
- **Multi-Criteria Search & Filtering**: Supports searching across 8 criteria (Incident ID, free text, status, priority, category, service, technician, and SLA status).
- **Persistent SQLite Relational Storage**: Implements the **Repository Pattern** for database persistence with PBKDF2-HMAC-SHA256 password security and HMAC signed tokens.
- **Role-Tailored Web GUI**: Single-page application styled with Tailwind CSS providing customized workspaces for Employees, Technicians, and Administrators with 1-click role demo switching.

---

## Architecture & Design Patterns

| Pattern | Module | Purpose |
|:---|:---|:---|
| **State Pattern** | `iitsm/states.py` | Encapsulates lifecycle transitions; illegal jumps raise `InvalidStateTransition`. |
| **Strategy Pattern** | `iitsm/strategies.py` | Dynamic priority scoring (`WeightedScorePriority`) and swappable assignment (`SkillBased`, `LoadBased`, `RoundRobin`). |
| **Observer Pattern** | `iitsm/events.py` | Event bus decoupling lifecycle events from `SQLiteAuditLog`, `InAppNotifier`, and `EmailNotifier`. |
| **Factory Pattern** | `iitsm/service.py` | `IncidentFactory` validates parameters and handles sequential incident ID generation. |
| **Repository Pattern** | `iitsm/sqlite_repository.py` | Decouples business logic from SQLite persistence and powers multi-criteria search. |

---

## Quick Start Guide

### 1. Requirements & Setup
- Python 3.10+ (Tested on Python 3.12)
- Install dependencies:
```bash
python -m pip install -r requirements.txt
```

### 2. Launch the Application
Start the FastAPI server and embedded Single-Page Application:
```bash
python app.py
```
Open your web browser and navigate to:
**http://localhost:8000**

The system automatically initializes and seeds `iitsm.db` with realistic users, services, SLA policies, and 25 realistic incidents spanning all lifecycle stages.

### 3. Quick Role Switcher
In the web interface top navigation bar, click any role button to switch instantly:
- **Priya (Employee)**: Submit new tickets with real-time NLP category auto-suggestion, track status, verify resolutions with feedback. Incidents list is strictly scoped to own tickets.
- **Alex (T1 Tech)**: View assigned queue, acknowledge tickets, start investigations, post notes, and apply AI resolution fixes.
- **David (T2 Lead)** & **Marcus (T3 SysAdmin)**: Handle escalated complex tickets and multi-department service interruptions.
- **Chakri (Admin/CIO)**: Swap assignment strategies, trigger proactive SLA sweeps, review workload heatmaps, and inspect analytics KPIs.

The account dialog accepts any seeded account or a newly registered employee. For a demonstration, sign in as the technician named on the specific ticket. Each technician sees their own queue. Employees can reply in the ticket notes, verify resolutions and read their notifications. Administrators can open **Manage services & team** to create users and services, manage technician capacity, register categories and set each service’s response and resolution targets. New SLA targets apply to future reports. The dashboard delivers its styles and icons locally.

### 4. Running the Automated Test Suite
Run all tests from the project directory:

```bash
python -m pytest -q
```

The suite includes the original 44 tests and seven integration regressions. The integration tests use temporary databases and cover simultaneous reports, restart persistence, access controls, the complete lifecycle, SLA alert deduplication, configuration changes and transaction rollback.

### 5. Official Academic PDF Report
The official submission report is provided directly as `I-ITSM_Group_Report.pdf` in the project root directory. It contains the complete technical specifications, architecture and UML diagrams, technology selection justifications, test cases documentation, and team responsibilities.

---

## Project Structure

```
├── app.py                     # FastAPI REST API controller & background SLA daemon
├── DOCUMENTATION.md           # Full technical documentation, specifications & test cases
├── I-ITSM_Group_Report.pdf    # Official academic report deliverable
├── requirements.txt           # Project dependencies
├── diagram_architecture.png   # Architectural component diagram
├── diagram_class.png          # UML Class Diagram (Domain entities & Design Patterns)
├── diagram_er.png             # Entity-Relationship diagram (SQLite schema)
├── diagram_use_case.png       # UML Use Case Diagram (Actors & system boundaries)
├── static/
│   └── index.html             # Responsive Tailwind CSS Single-Page Application
├── tests/
│   ├── test_full.py           # Integration & persistence tests
│   └── test_core.py           # Domain model unit tests
└── iitsm/
    ├── __init__.py
    ├── enums.py               # Role, Priority, Status, SLAStatus, EscalationTier
    ├── models.py              # User, Employee, Technician, Admin, ITService, Incident
    ├── states.py              # State Pattern lifecycle classes
    ├── strategies.py          # Strategy Pattern (Priority & Assignment)
    ├── events.py              # Observer Pattern (EventBus, AuditLog, Notifiers)
    ├── exceptions.py          # Domain-specific custom exceptions
    ├── intelligence.py        # Duplicate detection & NLP auto-categorization
    ├── sla.py                 # SLA deadline calculation, warnings & violations
    ├── service.py             # IncidentService & IncidentFactory
    ├── repository.py          # Generic Repository interface & in-memory implementation
    ├── sqlite_repository.py   # SQLite persistence layer with 8-criteria search
    ├── auth.py                # PBKDF2-HMAC-SHA256 hasher & HMAC token manager
    ├── analytics.py           # Dashboard analytics & technician workload KPIs
    ├── ai_assistant.py        # Historical resolution matcher & AI diagnostics
    ├── seeder.py              # Comprehensive database seeder
    └── bootstrap.py           # Composition root wiring all system components
```

---

## Default Seeded Credentials & Security Notes
All seeded demo users share the default test password:
- **Password**: `password123`
- **Administrator**: `admin1` (Chakradhar Reddy)
- **Technicians**: `tech_t1_1` (Alex Rivera), `tech_t2_1` (David Kim), `tech_t3_1` (Marcus Brody), `tech_t4_1` (Vikramaditya Rao)
- **Employees**: `emp1` (Priya Sharma), `emp2` (James Wilson), `emp3` (Ananya Iyer)

### Security Notes
- **Bearer Token Secret**: The HMAC-SHA256 token manager checks the environment variable `IITSM_SECRET_KEY`, and generates a random process key when the variable is unset. Set a private, stable value if sessions must survive a restart.
- **CORS Allowed Origins**: Configurable via `IITSM_ALLOWED_ORIGINS` (same-origin by default).
- **Employee Data Isolation**: Employees are strictly restricted to their own reported incidents at the API layer; any request parameter overrides are prevented.
- **Seeded Database**: The database file `iitsm.db` is auto-generated and seeded upon startup if not present.

---

### Transactional Guarantees and Architecture
Reports allocate incident IDs inside SQLite write transactions. Failed reports roll back, and repeated SLA sweeps retain the warning and breach history. The employee dashboard counts that employee's reports, the technician dashboard counts their assigned tickets, and the administrator sees organization-wide figures. The test database path can be overridden with `IITSM_DB_PATH`.
The prepared accounts and one-click role buttons are for a local classroom demonstration. The default launch binds to `127.0.0.1`.
