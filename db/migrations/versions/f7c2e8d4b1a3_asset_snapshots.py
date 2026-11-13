"""asset snapshots for delta scanning

Revision ID: f7c2e8d4b1a3
Revises: e5b1c3d9a7f2
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'f7c2e8d4b1a3'
down_revision: Union[str, None] = 'e5b1c3d9a7f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'asset_snapshots',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('program_id', sa.Integer(), nullable=False),
        sa.Column('fingerprint', sa.Text(), nullable=False),
        sa.Column('item_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['program_id'], ['programs.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    op.drop_table('asset_snapshots')
