"""create scans table

Revision ID: a518050937c9
Revises: 
Create Date: 2026-06-04 10:26:32.724563
"""

from alembic import op
import sqlalchemy as sa

revision = 'a518050937c9'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'scans',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('target', sa.String(512), nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('port_range', sa.String(100), nullable=True),
        sa.Column('risk_score', sa.Integer(), nullable=True),
        sa.Column('risk_label', sa.String(20), nullable=True),
        sa.Column('current_module', sa.String(50), nullable=True),
        sa.Column('result_json', sa.Text(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_scans_target', 'scans', ['target'])
    op.create_index('ix_scans_status', 'scans', ['status'])
    op.create_index('ix_scans_started_at', 'scans', ['started_at'])


def downgrade():
    op.drop_index('ix_scans_started_at', table_name='scans')
    op.drop_index('ix_scans_status', table_name='scans')
    op.drop_index('ix_scans_target', table_name='scans')
    op.drop_table('scans')