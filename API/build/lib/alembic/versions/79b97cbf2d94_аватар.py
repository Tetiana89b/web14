"""аватар

Revision ID: 79b97cbf2d94
Revises: 7249a1804bed
Create Date: 2023-07-16 17:59:37.444641

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '79b97cbf2d94'
down_revision = '7249a1804bed'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('contacts', sa.Column('avatar_url', sa.String))



def downgrade() -> None:
    pass
