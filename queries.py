"""Dashboard KPI queries against the security_gate views.

Trailing semicolons are left off on purpose: Athena's API rejects them.
"""

QUERIES = {
    # K1 Posture: PR runs and block rate per week
    "k1_posture": """
        SELECT date_trunc('week', ts) AS week, count(*) AS runs,
               sum(CASE WHEN verdict = 'blocked' THEN 1 ELSE 0 END) AS blocked,
               round(100.0 * avg(CASE WHEN verdict = 'blocked' THEN 1.0 ELSE 0 END), 1) AS block_rate_pct,
               sum(CASE WHEN verdict = 'error' THEN 1 ELSE 0 END) AS gate_errors
        FROM security_gate.v_runs GROUP BY 1 ORDER BY 1
    """,
    # K2 New findings by severity per week
    "k2_new_by_severity": """
        SELECT date_trunc('week', ts) AS week, severity, count(*) AS new_findings
        FROM security_gate.v_findings WHERE is_new GROUP BY 1, 2 ORDER BY 1, 2
    """,
    # K3 Findings per check (blocking vs warning)
    "k3_by_check": """
        SELECT check_name, count(*) AS findings,
               sum(CASE WHEN blocking THEN 1 ELSE 0 END) AS blocking
        FROM security_gate.v_findings GROUP BY 1 ORDER BY findings DESC
    """,
    # K4 Top 10 rules
    "k4_top_rules": """
        SELECT check_name, rule, max(message) AS example, count(*) AS hits,
               count(DISTINCT repo) AS repos
        FROM security_gate.v_findings GROUP BY 1, 2 ORDER BY hits DESC LIMIT 10
    """,
    # K5 Repos ranked by risk
    "k5_repos": """
        SELECT repo, count(DISTINCT run_id) AS runs_with_findings,
               sum(CASE WHEN blocking THEN 1 ELSE 0 END) AS blocking_findings,
               sum(CASE WHEN severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS high_or_critical
        FROM security_gate.v_findings GROUP BY 1 ORDER BY blocking_findings DESC
    """,
    # K6 Time to fix: first blocked run of a PR -> first passing run after it
    "k6_time_to_fix": """
        WITH pr_runs AS (SELECT repo, pr, ts, verdict FROM security_gate.v_runs WHERE pr IS NOT NULL),
        first_block AS (SELECT repo, pr, min(ts) AS blocked_at FROM pr_runs
                        WHERE verdict = 'blocked' GROUP BY 1, 2),
        fixed AS (SELECT b.repo, b.pr, b.blocked_at, min(p.ts) AS fixed_at
                  FROM first_block b JOIN pr_runs p
                    ON p.repo = b.repo AND p.pr = b.pr AND p.verdict = 'passed' AND p.ts > b.blocked_at
                  GROUP BY 1, 2, 3)
        SELECT (SELECT count(*) FROM first_block) AS prs_blocked, count(*) AS prs_fixed,
               round(avg(date_diff('minute', blocked_at, fixed_at)) / 60.0, 1) AS avg_hours_to_fix
        FROM fixed
    """,
    # K7 Gate health: check status mix and average time per check
    "k7_gate_health": """
        SELECT check_name, count(*) AS runs,
               sum(CASE WHEN status = 'FAIL' THEN 1 ELSE 0 END) AS fail,
               sum(CASE WHEN status = 'WARN' THEN 1 ELSE 0 END) AS warn,
               sum(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END) AS error,
               sum(CASE WHEN status = 'N/A' THEN 1 ELSE 0 END) AS not_applicable,
               round(avg(seconds), 1) AS avg_seconds
        FROM security_gate.v_checks GROUP BY 1 ORDER BY 1
    """,
    # K8 AI review: calls, cost and funnel
    "k8_ai_review": """
        SELECT count(*) AS ai_reviews, sum(ai_calls) AS calls, sum(ai_candidates) AS candidates,
               round(sum(ai_cost_usd), 4) AS cost_usd,
               round(avg(ai_cost_usd), 4) AS avg_cost_per_review
        FROM security_gate.v_checks WHERE check_name = 'AI review' AND ai_calls IS NOT NULL
    """,
    # K9 Coding-time AI use per developer per day (gateway)
    "k9_gateway_daily": """
        SELECT dt, developer, count(*) AS requests, sum(total_tokens) AS tokens,
               round(sum(est_cost_usd), 2) AS est_cost_usd, round(avg(latency_s), 1) AS avg_latency_s,
               sum(CASE WHEN status <> 'success' THEN 1 ELSE 0 END) AS failed,
               sum(CASE WHEN policy_blocked THEN 1 ELSE 0 END) AS policy_blocked
        FROM security_gate.v_gateway GROUP BY 1, 2 ORDER BY 1 DESC, requests DESC
    """,
    # K10 Model and client mix (gateway)
    "k10_model_mix": """
        SELECT model_group, split_part(client, ' ', 1) AS client, count(*) AS requests
        FROM security_gate.v_gateway GROUP BY 1, 2 ORDER BY requests DESC
    """,
    # K11 Per developer: coding-time AI use vs PR outcomes
    "k11_developer": """
        WITH g AS (SELECT developer, count(*) AS ai_requests, sum(total_tokens) AS ai_tokens
                   FROM security_gate.v_gateway GROUP BY 1),
             r AS (SELECT developer, count(*) AS pr_runs,
                          sum(CASE WHEN verdict = 'blocked' THEN 1 ELSE 0 END) AS blocked_runs
                   FROM security_gate.v_runs GROUP BY 1),
             f AS (SELECT developer, count(*) AS findings,
                          sum(CASE WHEN blocking THEN 1 ELSE 0 END) AS blocking_findings
                   FROM security_gate.v_findings GROUP BY 1)
        SELECT coalesce(g.developer, r.developer, f.developer) AS developer,
               g.ai_requests, g.ai_tokens, r.pr_runs, r.blocked_runs, f.findings, f.blocking_findings
        FROM g FULL OUTER JOIN r ON g.developer = r.developer
               FULL OUTER JOIN f ON coalesce(g.developer, r.developer) = f.developer
        ORDER BY r.pr_runs DESC NULLS LAST
    """,
}
