from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Float, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = Column(Integer, primary_key=True)
    full_name = Column(String(100), nullable=False)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(20), nullable=False, default='Captain') # 'Super Admin', 'Admin', 'Captain'
    team_id = Column(Integer, ForeignKey('team.id'), nullable=True)
    team = relationship('Team', back_populates='captain')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if password is None:
            return False
        return check_password_hash(self.password_hash, password)

class Team(db.Model):
    id = Column(Integer, primary_key=True)
    team_name = Column(String(100), unique=True, nullable=False)
    captain_name = Column(String(100), nullable=False)
    purse = Column(Integer, default=10000)
    purse_spent = Column(Integer, default=0)
    players_taken_count = Column(Integer, default=0)
    slots_remaining = Column(Integer, default=15) # Assuming max 15 slots

    captain = relationship('User', uselist=False, back_populates='team')
    players = relationship('Player', back_populates='team', lazy='dynamic')

class Player(db.Model):
    id = Column(Integer, primary_key=True)
    player_name = Column(String(100), nullable=False)
    image_filename = Column(String(100), nullable=True, default='default_player.png')
    is_retained = Column(Boolean, default=False, nullable=False)
    role = Column(String(50), nullable=True)

    # --- CPL 2024 Stats REMOVED ---

    # Overall Records
    overall_matches = Column(Integer, nullable=True)
    overall_runs = Column(Integer, nullable=True)
    overall_wickets = Column(Integer, nullable=True)
    overall_sr = Column(Float, nullable=True)
    overall_hs = Column(Integer, nullable=True)
    
    # Detailed Stats
    batting_inn = Column(Integer, nullable=True)
    batting_avg = Column(Float, nullable=True)
    bowling_inn = Column(Integer, nullable=True)
    bowling_avg = Column(Float, nullable=True)
    econ = Column(Float, nullable=True)
    bbi = Column(String(20), nullable=True)

    # Auction Status
    status = Column(String(20), default='Unsold', nullable=False)
    sold_price = Column(Integer, default=0)
    team_id = Column(Integer, ForeignKey('team.id'), nullable=True)
    team = relationship('Team', back_populates='players')