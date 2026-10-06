"""Resume report generation for a stuck job."""
from app.tasks import report_gen_task

JOB = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
RUN = "796ec01d-873c-42bf-824f-2a1bbd2a1db2"
SCHEMA = "firm_aetheris"

report_gen_task.delay(SCHEMA, JOB, RUN)
print("queued resume", JOB, RUN)
