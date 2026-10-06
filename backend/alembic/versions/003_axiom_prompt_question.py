"""Add prompt_question to axiom_artifacts.

Revision ID: 003
Revises: 002
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE public.axiom_artifacts ADD COLUMN IF NOT EXISTS prompt_question text")
    op.execute("ALTER TABLE public.axiom_artifacts ADD COLUMN IF NOT EXISTS metadata jsonb NOT NULL DEFAULT '{}'::jsonb")


def downgrade() -> None:
    op.drop_column("axiom_artifacts", "metadata")
    op.drop_column("axiom_artifacts", "prompt_question")
