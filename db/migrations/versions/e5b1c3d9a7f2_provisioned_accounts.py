"""provisioned accounts for IDOR testing

Revision ID: e5b1c3d9a7f2
Revises: d1a7c0e4b2f9
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'e5b1c3d9a7f2'
down_revision: Union[str, None] = 'd1a7c0e4b2f9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('programs', sa.Column('allow_account_provisioning', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column('programs', sa.Column('account_email_domain', sa.String(length=200), nullable=True))
    op.create_table(
        'provisioned_accounts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('program_id', sa.Integer(), nullable=False),
        sa.Column('label', sa.String(length=50), nullable=False),
        sa.Column('identifier', sa.String(length=200), nullable=False),
        sa.Column('register_host', sa.String(length=300), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='created'),
        sa.Column('secret_encrypted', sa.Text(), nullable=True),
        sa.Column('session_encrypted', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['program_id'], ['programs.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    op.drop_table('provisioned_accounts')
    op.drop_column('programs', 'account_email_domain')
    op.drop_column('programs', 'allow_account_provisioning')
