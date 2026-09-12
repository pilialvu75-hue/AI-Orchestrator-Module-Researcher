# `network.http` candidate comparison

| Dimension | `dart-lang/http` 1.6.0 | `cfug/dio` 5.11.1 |
| --- | --- | --- |
| Immutable source | `907782f5a792e7a5b0ed92f118c0ad91f3ecde51` | `4684e29dabaa2655606f1620a4ed316ee3f8c963` |
| License | BSD-3-Clause | MIT |
| Retry | Built-in `RetryClient` | Custom interceptor / `dio_smart_retry` companion |
| Timeout | Trusted wrapper using abort trigger | First-class timeout support |
| Cancellation | `AbortableRequest` / `Abortable` | First-class abort/cancel |
| Swappability | Explicit `Client` interface with multiple implementations | Custom adapters; AI-Orchestrator adapter still needed |
| Runtime dependency surface | 4 package dependencies | 7 package dependencies including web adapter |
| Tests / CI | Yes / yes; Dependabot | Yes / yes; CodeQL, SECURITY, Dependabot |
| Human integration estimate | Low | Medium |
| Machine pre-screen score | 0.7900 | 0.8325 |

## Recommendation

There is no absolute winner.

**Default for the small LEGO slot:** `dart-lang/http` 1.6.0. Its architecture most closely
resembles the intended interchangeable `network.http.v1` boundary and should require the thinnest
trusted adapter.

**Rich alternative:** Dio 5.11.1. Prefer it when interceptors, upload/download/progress,
first-class timeout controls or Dio ecosystem integrations reduce total project work enough to
justify the larger surface.

Both remain only `SHORTLISTED`. Library certification has not occurred.
