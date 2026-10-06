"""AXIOM artifact catalog tables (Magnet AXIOM 10.2.0).

Revision ID: 002
Revises: 001
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "axiom_objectives",
        sa.Column("objective_id", sa.Text(), primary_key=True),
        sa.Column("procedure_id", sa.Text(), nullable=True),
        sa.Column("domain", sa.Text(), nullable=True),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("statement", sa.Text(), nullable=True),
        sa.Column("primary_artifact_families", sa.Text(), nullable=True),
        sa.Column("required_observation_fields", sa.Text(), nullable=True),
        sa.Column("minimum_corroboration", sa.Text(), nullable=True),
        sa.Column("limitations", sa.Text(), nullable=True),
        sa.Column("priority", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    op.create_table(
        "axiom_procedures",
        sa.Column("procedure_id", sa.Text(), primary_key=True),
        sa.Column("objective_id", sa.Text(), nullable=True),
        sa.Column("domain", sa.Text(), nullable=True),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("detailed_procedure", sa.Text(), nullable=True),
        sa.Column("mandatory_corroboration", sa.Text(), nullable=True),
        sa.Column("expected_output_fields", sa.Text(), nullable=True),
        sa.Column("limitations", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    op.create_table(
        "axiom_artifacts",
        sa.Column("artifact_id", sa.Text(), primary_key=True),
        sa.Column("platform", sa.Text(), nullable=False),
        sa.Column("category", sa.Text(), nullable=False),
        sa.Column("application_or_profile", sa.Text(), nullable=True),
        sa.Column("artifact_name", sa.Text(), nullable=False),
        sa.Column("recovery_method", sa.Text(), nullable=True),
        sa.Column("reference_page", sa.Integer(), nullable=True),
        sa.Column("primary_objective_id", sa.Text(), nullable=True),
        sa.Column("secondary_objective_ids", sa.Text(), nullable=True),
        sa.Column("procedure_id", sa.Text(), nullable=True),
        sa.Column("observation_focus", sa.Text(), nullable=True),
        sa.Column("outline_path", sa.Text(), nullable=True),
        sa.Column("prompt_question", sa.Text(), nullable=True),
        sa.Column("critical", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("source_version", sa.Text(), nullable=True),
        sa.Column("source_published", sa.Text(), nullable=True),
        sa.Column("source_url", sa.Text(), nullable=True),
        sa.Column("mapping_note", sa.Text(), nullable=True),
        sa.Column("metadata", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("platform", "category", "artifact_name", name="uq_axiom_artifact_platform_cat_name"),
    )
    op.create_index("ix_axiom_artifacts_platform", "axiom_artifacts", ["platform"])
    op.create_index("ix_axiom_artifacts_platform_category", "axiom_artifacts", ["platform", "category"])


def downgrade() -> None:
    op.drop_index("ix_axiom_artifacts_platform_category", table_name="axiom_artifacts")
    op.drop_index("ix_axiom_artifacts_platform", table_name="axiom_artifacts")
    op.drop_table("axiom_artifacts")
    op.drop_table("axiom_procedures")
    op.drop_table("axiom_objectives")
