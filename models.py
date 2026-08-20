"""SQLAlchemy models for ROCK AXEE Bot Hosting Panel."""

from datetime import datetime, date
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Date, ForeignKey, Text
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(80), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(20), default="user")  # 'owner' or 'user'
    approved = Column(Boolean, default=False)
    expiry = Column(Date, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    bots = relationship("Bot", back_populates="owner", cascade="all, delete-orphan")

    def is_expired(self) -> bool:
        if self.expiry is None:
            return False
        return date.today() > self.expiry

    def __repr__(self):
        return f"<User {self.username}>"


class Bot(Base):
    __tablename__ = "bots"

    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String(50), unique=True, nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    filepath = Column(String(512), nullable=False)
    main_file = Column(String(255), nullable=True)
    bot_dir = Column(String(512), nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    status = Column(String(20), default="stopped")  # 'stopped', 'running', 'pending', 'setup', 'rejected', 'deleted'
    logpath = Column(String(512), nullable=True)
    pid = Column(Integer, nullable=True)
    req_installed = Column(Boolean, default=False)
    restart_count = Column(Integer, default=0)
    started_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="bots")

    def uptime_str(self) -> str:
        if self.status != "running" or not self.started_at:
            return "—"
        delta = datetime.utcnow() - self.started_at
        days = delta.days
        hours, remainder = divmod(delta.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        else:
            return f"{minutes}m {seconds}s"

    def __repr__(self):
        return f"<Bot {self.uid}>"


class KeyValue(Base):
    __tablename__ = "keyvalues"

    id = Column(Integer, primary_key=True)
    k = Column(String(100), unique=True, nullable=False)
    v = Column(Text, nullable=True)

    def __repr__(self):
        return f"<KeyValue {self.k}>"
