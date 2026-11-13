"""scan accuracy fields (evidence, normalization, confidence, urls)

Revision ID: d1a7c0e4b2f9
Revises: cf81cafbb3a8
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd1a7c0e4b2f9'
down_revision: Union[str, None] = 'cf81cafbb3a8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('scan_runs', sa.Column('error', sa.Text(), nullable=True))
    op.add_column('scan_runs', sa.Column('blocked_hosts', sa.Text(), nullable=True))

    op.add_column('findings', sa.Column('vuln_class', sa.String(length=100), nullable=True))
    op.add_column('findings', sa.Column('cwe', sa.String(length=20), nullable=True))
    op.add_column('findings', sa.Column('request', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('response', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('curl_command', sa.Text(), nullable=True))

    op.add_column('correlated_findings', sa.Column('vuln_class', sa.String(length=100), nullable=True))
    op.add_column('correlated_findings', sa.Column('cwe', sa.String(length=20), nullable=True))
    op.add_column('correlated_findings', sa.Column('confidence', sa.String(length=10), nullable=False, server_default='low'))
    op.add_column('correlated_findings', sa.Column('verified', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column('correlated_findings', sa.Column('reproduction', sa.Text(), nullable=True))

    op.add_column('hosts', sa.Column('urls', sa.Text(), nullable=True))
    op.add_column('hosts', sa.Column('dns_wildcard', sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    op.drop_column('hosts', 'dns_wildcard')
    op.drop_column('hosts', 'urls')
    for col in ('reproduction', 'verified', 'confidence', 'cwe', 'vuln_class'):
        op.drop_column('correlated_findings', col)
    for col in ('curl_command', 'response', 'request', 'cwe', 'vuln_class'):
        op.drop_column('findings', col)
    op.drop_column('scan_runs', 'blocked_hosts')
    op.drop_column('scan_runs', 'error')
