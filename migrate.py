"""
Database migration script
Run this to initialize or reset the database
"""
from app.db.database import init_db, drop_db, engine
from app.db.models import Base
import sys


def create_tables():
    """Create all database tables"""
    print("Creating database tables...")
    init_db()
    print("✓ Database tables created successfully!")


def reset_database():
    """Drop and recreate all tables (WARNING: Deletes all data)"""
    response = input("⚠️  This will delete all data. Are you sure? (yes/no): ")
    if response.lower() == 'yes':
        print("Dropping existing tables...")
        drop_db()
        print("Creating new tables...")
        init_db()
        print("✓ Database reset successfully!")
    else:
        print("Operation cancelled.")


def show_tables():
    """Show all tables in the database"""
    print("\nDatabase Tables:")
    print("-" * 40)
    for table in Base.metadata.sorted_tables:
        print(f"  - {table.name}")
    print("-" * 40)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "init":
            create_tables()
            show_tables()
        elif command == "reset":
            reset_database()
            show_tables()
        elif command == "show":
            show_tables()
        else:
            print("Unknown command. Available commands: init, reset, show")
    else:
        print("Database Migration Script")
        print("\nUsage:")
        print("  python migrate.py init   - Initialize database tables")
        print("  python migrate.py reset  - Reset database (deletes all data)")
        print("  python migrate.py show   - Show all tables")
