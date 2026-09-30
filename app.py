"""Security Gate dashboard: Athena views -> Streamlit.

Run:  streamlit run app.py

Settings are read from Streamlit secrets (.streamlit/secrets.toml, or the
secrets box on Streamlit Community Cloud) first, then environment variables:
  ATHENA_S3_OUTPUT, ATHENA_WORKGROUP, ATHENA_DATABASE, AWS_REGION,
  DASHBOARD_CACHE_SECONDS, and optionally AWS_PROFILE.

AWS credentials: if AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY are in secrets,
they are used. Otherwise boto3's default chain applies: env vars, AWS_PROFILE
or ~/.aws (aws configure / aws sso login), or an attached IAM role on
ECS, App Runner, EC2 or EKS. On AWS hosting, prefer the role: no keys needed.
"""

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import awswrangler as wr
import boto3
import pandas as pd
import streamlit as st

from queries import QUERIES


def setting(key: str, default=None):
    """Streamlit secrets first, then environment variables, then the default."""
    try:
        if key in st.secrets:
            return st.secrets[key]
    except Exception:  # no secrets.toml present
        pass
    return os.getenv(key, default)


DATABASE = setting("ATHENA_DATABASE", "security_gate")
S3_OUTPUT = setting("ATHENA_S3_OUTPUT", "s3://sg-personal-reports/athena-results/")
WORKGROUP = setting("ATHENA_WORKGROUP", "primary")
REGION = setting("AWS_REGION", "us-east-1")
CACHE_TTL = int(setting("DASHBOARD_CACHE_SECONDS", "300"))

# Explicit credentials only if provided; None lets boto3 use its default chain.
AWS_KEY_ID = setting("AWS_ACCESS_KEY_ID")
AWS_SECRET = setting("AWS_SECRET_ACCESS_KEY")
AWS_TOKEN = setting("AWS_SESSION_TOKEN")
AWS_PROFILE = setting("AWS_PROFILE")

st.set_page_config(page_title="Security Gate", page_icon="🛡️", layout="wide")

LOGO = Path(__file__).parent / "images" / "moring-logo.png"
if LOGO.exists():
    st.logo(str(LOGO), size="large")

# ---------------------------------------------------------------- data access

def run_query(sql: str) -> pd.DataFrame:
    # One session per thread: boto3 sessions are not thread-safe.
    session = boto3.Session(
        aws_access_key_id=AWS_KEY_ID,
        aws_secret_access_key=AWS_SECRET,
        aws_session_token=AWS_TOKEN,
        profile_name=None if AWS_KEY_ID else AWS_PROFILE,
        region_name=REGION,
    )
    return wr.athena.read_sql_query(
        sql=sql,
        database=DATABASE,
        s3_output=S3_OUTPUT,
        workgroup=WORKGROUP,
        ctas_approach=False,  # plain SELECT; no temp tables or extra Glue permissions
        boto3_session=session,
    )


@st.cache_data(ttl=CACHE_TTL, show_spinner="Querying Athena...")
def load_all() -> tuple[dict, dict, datetime]:
    """Run every KPI query in parallel. Returns (frames, errors, loaded_at)."""
    frames, errors = {}, {}
    with ThreadPoolExecutor(max_workers=len(QUERIES)) as pool:
        futures = {name: pool.submit(run_query, sql) for name, sql in QUERIES.items()}
        for name, fut in futures.items():
            try:
                frames[name] = fut.result()
            except Exception as exc:  # keep the rest of the dashboard alive
                errors[name] = f"{type(exc).__name__}: {exc}"
    return frames, errors, datetime.now(timezone.utc)


frames, errors, loaded_at = load_all()


def df(name: str) -> pd.DataFrame:
    return frames.get(name, pd.DataFrame())


def show_table(name: str, **kwargs) -> None:
    data = df(name)
    if data.empty:
        st.info("No rows yet." if name not in errors else "Query failed; see the sidebar.")
    else:
        st.dataframe(data, use_container_width=True, hide_index=True, **kwargs)


def num(value, fmt="{:,.0f}", empty="—"):
    return empty if value is None or pd.isna(value) else fmt.format(value)


# ---------------------------------------------------------------- sidebar

with st.sidebar:
    st.subheader("Security Gate")
    st.caption(f"Data as of {loaded_at:%Y-%m-%d %H:%M} UTC. Cached for {CACHE_TTL // 60} min.")
    if st.button("Refresh now", use_container_width=True):
        load_all.clear()
        st.rerun()
    if errors:
        st.error(f"{len(errors)} of {len(QUERIES)} queries failed.")
        for name, msg in errors.items():
            with st.expander(name):
                st.code(msg, language=None)


# ---------------------------------------------------------------- headline numbers

st.title("Security Gate")

k1, k6, k8 = df("k1_posture"), df("k6_time_to_fix"), df("k8_ai_review")
total_runs = k1["runs"].sum() if not k1.empty else None
total_blocked = k1["blocked"].sum() if not k1.empty else None
block_rate = (100 * total_blocked / total_runs) if total_runs else None
gate_errors = k1["gate_errors"].sum() if not k1.empty else None

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Runs", num(total_runs))
c2.metric("Block rate", num(block_rate, "{:.1f}%"))
c3.metric("Gate errors", num(gate_errors))
c4.metric(
    "Avg hours to fix",
    num(k6["avg_hours_to_fix"].iloc[0] if not k6.empty else None, "{:.1f}"),
    help="First blocked run of a PR to the first passing run after it.",
)
c5.metric("AI review cost", num(k8["cost_usd"].iloc[0] if not k8.empty else None, "${:,.2f}"))

if not k6.empty:
    st.caption(f"{num(k6['prs_fixed'].iloc[0])} of {num(k6['prs_blocked'].iloc[0])} blocked PRs have since passed.")


# ---------------------------------------------------------------- tabs

posture, risk, health, ai = st.tabs(["Posture", "Where risk comes from", "Gate health", "AI usage"])

with posture:
    left, right = st.columns(2)
    with left:
        st.markdown("**Block rate per week (%)**")
        if not k1.empty:
            st.line_chart(k1, x="week", y="block_rate_pct")
    with right:
        st.markdown("**Runs vs blocked per week**")
        if not k1.empty:
            st.bar_chart(k1, x="week", y=["runs", "blocked"], stack=False)

    st.markdown("**New findings by severity per week**")
    k2 = df("k2_new_by_severity")
    if k2.empty:
        st.info("No new findings yet.")
    else:
        pivot = k2.pivot_table(index="week", columns="severity", values="new_findings",
                               aggfunc="sum", fill_value=0)
        st.bar_chart(pivot)

with risk:
    left, right = st.columns(2)
    with left:
        st.markdown("**Findings per check**")
        k3 = df("k3_by_check")
        if not k3.empty:
            k3 = k3.assign(warning=k3["findings"] - k3["blocking"])
            st.bar_chart(k3, x="check_name", y=["blocking", "warning"], horizontal=True)
    with right:
        st.markdown("**Repos ranked by risk**")
        show_table("k5_repos")

    st.markdown("**Top 10 rules**")
    show_table("k4_top_rules", column_config={"example": st.column_config.TextColumn(width="large")})

with health:
    st.markdown("**Check status mix and average time**")
    show_table("k7_gate_health")

    st.markdown("**AI review funnel**")
    if not k8.empty:
        row = k8.iloc[0]
        a, b, c, d = st.columns(4)
        a.metric("Reviews", num(row["ai_reviews"]))
        b.metric("Model calls", num(row["calls"]))
        c.metric("Candidates", num(row["candidates"]))
        d.metric("Avg cost / review", num(row["avg_cost_per_review"], "${:.4f}"))

with ai:
    st.markdown("**Developers: coding-time AI use vs PR outcomes**")
    show_table("k11_developer")

    left, right = st.columns([2, 1])
    with left:
        st.markdown("**Daily gateway use per developer**")
        show_table("k9_gateway_daily", height=400)
    with right:
        st.markdown("**Models and clients in use**")
        show_table("k10_model_mix", height=400)
