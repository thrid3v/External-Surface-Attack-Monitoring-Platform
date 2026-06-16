"""add schedules and alerts tables

Revision ID: c2b3d4e5f6a7
Revises: b1a2c3d4e5f6
Create Date: 2026-06-16 00:30:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = 'c2b3d4e5f6a7'
down_revision = 'b1a2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'schedules',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('owner_email', sa.String(320), nullable=False),
        sa.Column('target', sa.String(512), nullable=False),
        sa.Column('port_range', sa.String(100), nullable=True),
        sa.Column('profile', sa.String(50), nullable=True),
        sa.Column('modules', sa.Text(), nullable=True),
        sa.Column('interval_minutes', sa.Integer(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('next_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_schedules_owner_email', 'schedules', ['owner_email'])
    op.create_index('ix_schedules_next_run_at', 'schedules', ['next_run_at'])

    op.create_table(
        'alerts',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('owner_email', sa.String(320), nullable=False),
        sa.Column('target', sa.String(512), nullable=False),
        sa.Column('scan_id', sa.String(36), nullable=True),
        sa.Column('type', sa.String(50), nullable=False),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('read', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_alerts_owner_email', 'alerts', ['owner_email'])
    op.create_index('ix_alerts_created_at', 'alerts', ['created_at'])


def downgrade():
    op.drop_index('ix_alerts_created_at', table_name='alerts')
    op.drop_index('ix_alerts_owner_email', table_name='alerts')
    op.drop_table('alerts')
    op.drop_index('ix_schedules_next_run_at', table_name='schedules')
    op.drop_index('ix_schedules_owner_email', table_name='schedules')
    op.drop_table('schedules')
