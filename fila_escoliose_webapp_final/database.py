from flask import g
import logging
import os
import sqlite3
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
engine = None
db_session = None

def get_db():
    """Connect to the application's configured database.
    The connection is unique for each request and will be reused if called again.
    """
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row

    return g.db

def close_db(e=None):
    """Close the database connection at the end of the request."""
    db = g.pop('db', None)

    if db is not None:
        db.close()

def init_db():
    """Initialize the database."""
    global engine
    from flask import current_app
    
    db = get_db()
    
    # Create tables if they don't exist
    if os.path.exists('schema.sql'):
        with current_app.open_resource('schema.sql') as f:
            db.executescript(f.read().decode('utf8'))

def init_app(app):
    """Initialize the Flask application with database functionality."""
    global engine, db_session
    
    # Register database functions with the Flask app
    app.teardown_appcontext(close_db)
    
    # Set up SQLAlchemy
    # Make sure we're using the right database path from app config
    database_path = app.config['DATABASE']
    engine = create_engine(f"sqlite:///{database_path}")
    
    # Log some debug information
    logger = logging.getLogger(__name__)
    logger.info(f"Initializing database engine with path: {database_path}")
    logger.info(f"Engine created: {engine}")
    
    db_session = scoped_session(sessionmaker(autocommit=False,
                                             autoflush=False,
                                             bind=engine))
    Base.query = db_session.query_property()
    
    # Ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass
    
    # Return the engine to verify it was created
    return engine

def get_db_session():
    """Returns the SQLAlchemy database session."""
    return db_session