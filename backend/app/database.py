import logging
from pathlib import Path

from sqlalchemy import create_engine, text as sql_text
from sqlalchemy.orm import declarative_base, sessionmaker

logger = logging.getLogger("ruleforge.database")

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "ruleforge.db"

engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _add_missing_columns(table: str, additions: dict[str, str]) -> None:
    with engine.begin() as connection:
        columns = {row[1] for row in connection.execute(sql_text(f"PRAGMA table_info({table})"))}
        for column, ddl in additions.items():
            if column not in columns:
                connection.execute(sql_text(ddl))
                logger.info("Applied local DB migration: added %s.%s", table, column)


def init_db() -> None:
    """Initialize the local SQLite schema and apply backward-compatible dev migrations."""
    Base.metadata.create_all(bind=engine)
    try:
        _add_missing_columns(
            "iocs",
            {
                "enrichment_source": "ALTER TABLE iocs ADD COLUMN enrichment_source VARCHAR",
                "enrichment_summary": "ALTER TABLE iocs ADD COLUMN enrichment_summary TEXT",
                "enrichment_json": "ALTER TABLE iocs ADD COLUMN enrichment_json TEXT",
                "judge_decision": "ALTER TABLE iocs ADD COLUMN judge_decision VARCHAR",
                "judge_score": "ALTER TABLE iocs ADD COLUMN judge_score INTEGER",
                "judge_reason": "ALTER TABLE iocs ADD COLUMN judge_reason TEXT",
            },
        )
        _add_missing_columns(
            "mitre_mappings",
            {
                "judge_decision": "ALTER TABLE mitre_mappings ADD COLUMN judge_decision VARCHAR",
                "judge_score": "ALTER TABLE mitre_mappings ADD COLUMN judge_score INTEGER",
                "judge_reason": "ALTER TABLE mitre_mappings ADD COLUMN judge_reason TEXT",
            },
        )
        _add_missing_columns(
            "detection_rules",
            {
                "judge_decision": "ALTER TABLE detection_rules ADD COLUMN judge_decision VARCHAR",
                "judge_score": "ALTER TABLE detection_rules ADD COLUMN judge_score INTEGER",
                "judge_reason": "ALTER TABLE detection_rules ADD COLUMN judge_reason TEXT",
            },
        )
    except Exception as exc:
        logger.warning("Local DB migration skipped: %s", exc)
