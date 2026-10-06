"""Add evidence_prompt columns to reports_objective for AXIOM-aligned Section C."""

from alembic import op

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE public.reports_objective ADD COLUMN IF NOT EXISTS evidence_prompt text"
    )
    op.execute(
        "ALTER TABLE public.reports_objective "
        "ADD COLUMN IF NOT EXISTS required_observation_fields text"
    )
    op.execute(
        "ALTER TABLE public.reports_objective "
        "ADD COLUMN IF NOT EXISTS expected_output_fields text"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE public.reports_objective DROP COLUMN IF EXISTS expected_output_fields")
    op.execute("ALTER TABLE public.reports_objective DROP COLUMN IF EXISTS required_observation_fields")
    op.execute("ALTER TABLE public.reports_objective DROP COLUMN IF EXISTS evidence_prompt")
