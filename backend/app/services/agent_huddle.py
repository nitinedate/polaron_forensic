"""Legacy task compatibility. All decisions belong to progressAgent."""
def run_agent_huddle(db, job_id: str, *, schema_name: str) -> dict:
    from app.services.retired_agents import retired_huddle_result
    return retired_huddle_result(job_id)
