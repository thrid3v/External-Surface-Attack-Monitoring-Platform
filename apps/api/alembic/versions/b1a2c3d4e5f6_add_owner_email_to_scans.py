"""add owner_email to scans

Revision ID: b1a2c3d4e5f6
Revises: a518050937c9
Create Date: 2026-06-16 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = 'b1a2c3d4e5f6'
down_revision = 'a518050937c9'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('scans', sa.Column('owner_email', sa.String(320), nullable=True))
    op.create_index('ix_scans_owner_email', 'scans', ['owner_email'])


def downgrade():
    op.drop_index('ix_scans_owner_email', table_name='scans')
    op.drop_column('scans', 'owner_email')
