"""Add prompt_question to axiom objectives/procedures.

Revision ID: 004
Revises: 003
"""

from typing import Sequence, Union

from alembic import op

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE public.axiom_objectives ADD COLUMN IF NOT EXISTS prompt_question text")
    op.execute("ALTER TABLE public.axiom_procedures ADD COLUMN IF NOT EXISTS prompt_question text")


def downgrade() -> None:
    op.execute("ALTER TABLE public.axiom_objectives DROP COLUMN IF EXISTS prompt_question")
    op.execute("ALTER TABLE public.axiom_procedures DROP COLUMN IF EXISTS prompt_question")
