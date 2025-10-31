import os
from flask import Flask, render_template, redirect, url_for, request, flash, session, send_file
from models import db, User, Team, Player # Keep your existing models import
from dotenv import load_dotenv
import datetime
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from functools import wraps
import random
import pandas as pd
import io
from sqlalchemy import inspect # Needed for checking if tables exist
import math # Needed for import

# Load environment variables
load_dotenv()

app = Flask(__name__)

# --- CONFIGURATION ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///project.db')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_to_change_later_98765')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# --- LOGIN MANAGER SETUP ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'You must be logged in to view this page.'
login_manager.login_message_category = 'error'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- DATABASE CREATION & SEEDING (FOR FIRST DEPLOY) ---
def import_players_from_csv(filepath='players_data.csv'):
    """Reads player data from CSV and populates the database."""
    try:
        df = pd.read_csv(filepath).fillna(value=pd.NA)
        print(f"Reading data from {filepath}...")
    except FileNotFoundError:
        print(f"Error: CSV file not found at {filepath}. Player seeding skipped.")
        return False
    except Exception as e:
        print(f"Error reading CSV file: {e}. Player seeding skipped.")
        return False

    teams_map = {team.team_name.strip(): team.id for team in Team.query.all()}
    new_players_count = 0
    updated_players_count = 0

    for index, row in df.iterrows():
        try:
            player_name = str(row['player_name']).strip() if pd.notna(row['player_name']) else None
            if not player_name:
                print(f"Skipping row {index + 2}: Missing player name.")
                continue

            player = Player.query.filter_by(player_name=player_name).first()

            is_retained_val = row.get('is_retained', False)
            is_retained = str(is_retained_val).strip().upper() in ['TRUE', '1', 'YES', 'T']
            retaining_team_name = str(row.get('retaining_team_name', '')).strip() if pd.notna(row.get('retaining_team_name')) else ''
            last_year_price_val = row.get('last_year_price', 0)
            last_year_price = int(float(last_year_price_val)) if pd.notna(last_year_price_val) and str(last_year_price_val).strip() else 0
            team_id = None
            if is_retained and retaining_team_name:
                if retaining_team_name in teams_map: team_id = teams_map[retaining_team_name]
                else: print(f"Warning: Retaining team '{retaining_team_name}' not found for '{player_name}'."); is_retained = False
            image_filename = str(row.get('image_filename')).strip() if pd.notna(row.get('image_filename')) else None
            
            def safe_int(value, default=0):
                if pd.isna(value) or value is None or (isinstance(value, str) and not value.strip()): return default
                if isinstance(value, float) and math.isnan(value): return default
                try: return int(float(value))
                except (ValueError, TypeError): return default
            def safe_float(value, default=0.0):
                if pd.isna(value) or value is None or (isinstance(value, str) and not value.strip()): return default
                if isinstance(value, float) and math.isnan(value): return default
                try: return float(value)
                except (ValueError, TypeError): return default

            player_data = {
                'player_name': player_name, 'image_filename': image_filename if image_filename else 'default_player.png',
                'is_retained': is_retained, 'team_id': team_id, 'sold_price': last_year_price if is_retained else 0,
                'status': 'Retained' if is_retained else 'Unsold',
                'cpl_2024_team': str(row.get('cpl_2024_team')).strip() if pd.notna(row.get('cpl_2024_team')) else None,
                'cpl_2024_innings': safe_int(row.get('cpl_2024_innings')), 'cpl_2024_runs': safe_int(row.get('cpl_2024_runs')),
                'cpl_2024_wickets': safe_int(row.get('cpl_2024_wickets')), 'cpl_2024_sr': safe_float(row.get('cpl_2024_sr')),
                'cpl_2024_hs': safe_int(row.get('cpl_2024_hs')),
                'overall_matches': safe_int(row.get('overall_matches')), 'overall_runs': safe_int(row.get('overall_runs')),
                'overall_wickets': safe_int(row.get('overall_wickets')), 'overall_sr': safe_float(row.get('overall_sr')),
                'overall_hs': safe_int(row.get('overall_hs'))
            }

            if not player:
                player = Player(**player_data); db.session.add(player); new_players_count += 1
            else:
                print(f"Player '{player_name}' already exists. Updating details.")
                player.is_retained = player_data['is_retained']; player.team_id = player_data['team_id']; player.sold_price = player_data['sold_price']; player.image_filename = player_data['image_filename']
                if player_data['is_retained'] and player.status != 'Sold': player.status = 'Retained'
                elif not player_data['is_retained'] and player.status == 'Retained': player.status = 'Unsold'
                player.cpl_2024_wickets = player_data['cpl_2024_wickets']; player.overall_sr = player_data['overall_sr']; player.overall_hs = player_data['overall_hs']
                updated_players_count += 1
        except Exception as e:
            print(f"Error processing row {index + 2} for player '{row.get('player_name', 'N/A')}': {e}"); db.session.rollback()
    
    try: db.session.commit(); print(f"Import complete. Added: {new_players_count}, Updated: {updated_players_count}")
    except Exception as e: db.session.rollback(); print(f"Error during final database commit: {e}")
    return True

def recalculate_initial_team_stats():
    """Calculates team stats based on retained players."""
    print("Recalculating initial team stats based on retained players...")
    all_teams = Team.query.all(); max_slots = 15
    for team in all_teams:
        retained_players = team.players.filter_by(is_retained=True).all()
        retained_count = len(retained_players); retained_cost = sum(p.sold_price for p in retained_players if p.sold_price is not None)
        team.players_taken_count = retained_count; team.slots_remaining = max_slots - retained_count
        team.purse_spent = retained_cost; team.purse = 10000 - retained_cost
        print(f"Team: {team.team_name}, Retained: {retained_count}, Cost: {retained_cost}, Purse Left: {team.purse}, Slots Left: {team.slots_remaining}")
    try: db.session.commit(); print("Initial team stats updated successfully.")
    except Exception as e: db.session.rollback(); print(f"Error updating team stats: {e}")

@app.before_request
def create_tables():
    if not hasattr(app, 'tables_created'):
        with app.app_context():
            inspector = db.inspect(db.engine)
            tables_exist = inspector.has_table("user")
            if not tables_exist:
                db.create_all(); print("Database tables created.")
                if User.query.count() == 0:
                    print("Creating Super Admin..."); super_admin = User( full_name="Super Admin", username="superadmin", role="Super Admin"); super_admin.set_password("admin123"); db.session.add(super_admin); db.session.commit(); print("Super Admin created...")
                if Team.query.count() == 0:
                     teams = [ Team(team_name="APJ Tamizhan Youngstars", captain_name="Silambu R"), Team(team_name="SPARTAN ROCKERZ", captain_name="Barathi K"), Team(team_name="Crazy-11", captain_name="Nithyaraj"), Team(team_name="Jolly Players", captain_name="Vinoth"), Team(team_name="Dada Warriors", captain_name="Praveen prabhakaran"), Team(team_name="Thunder Strikers", captain_name="Gurunathan S") ]
                     db.session.bulk_save_objects(teams); db.session.commit(); print(f"{len(teams)} teams seeded.")
                if Player.query.count() == 0:
                    print("Seeding players from CSV...")
                    if import_players_from_csv(): # Run import
                        recalculate_initial_team_stats() # Recalculate stats after import
                    else:
                        print("Player seeding failed.")
            else:
                print("Database tables already exist.")
        app.tables_created = True

# --- CUSTOM DECORATORS for security ---
def role_required(role_names):
    if not isinstance(role_names, list): role_names = [role_names]
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated: return login_manager.unauthorized()
            if current_user.role != 'Super Admin' and current_user.role not in role_names:
                flash('You do not have permission to access this page.', 'error'); return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator
def check_admin_password(username, password):
    user = User.query.filter_by(username=username).first()
    if user and (user.role == 'Admin' or user.role == 'Super Admin') and user.check_password(password):
        return True
    return False

# --- PUBLIC ROUTES ---
@app.route('/')
def home():
    total_players = Player.query.count(); retained_players_count = Player.query.filter_by(is_retained=True).count(); auction_pool_count = total_players - retained_players_count; team_count = Team.query.count(); max_total_slots = team_count * 15; total_auction_slots_available = max_total_slots - retained_players_count
    try:
        auction_date_str = "2025-12-20"; auction_date = datetime.datetime.strptime(auction_date_str, "%Y-%m-%d").date(); today = datetime.date.today(); days_to_go = (auction_date - today).days
        if days_to_go < 0: days_to_go = 0
    except ValueError: days_to_go = 60
    return render_template('index.html', active_page='home', player_count=auction_pool_count, team_count=team_count, slots_remaining=total_auction_slots_available, days_to_go=days_to_go)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
         if current_user.role == 'Captain': return redirect(url_for('teams'))
         else: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username'); password = request.form.get('password'); user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user); flash('Logged in successfully!', 'success')
            if user.role == 'Captain': return redirect(url_for('teams'))
            else: return redirect(url_for('dashboard'))
        else: flash('Invalid username or password.', 'error')
    return render_template('login.html', active_page='login')

@app.route('/logout')
@login_required
def logout():
    logout_user(); session.pop('auction_started', None); session.pop('current_player_id', None); session.pop('auction_round', None); session.pop('round_complete', None); session.pop('auction_complete', None); session.pop('auction_paused', None)
    flash('You have been logged out.', 'success'); return redirect(url_for('home'))

# --- PROTECTED ROUTES ---
@app.route('/dashboard')
@login_required
@role_required(['Admin'])
def dashboard():
    all_users = []
    if current_user.role == 'Super Admin':
        all_users = User.query.filter(User.id != current_user.id).order_by(User.role, User.full_name).all()
    return render_template('dashboard.html', active_page='dashboard', all_users=all_users)

@app.route('/players')
@login_required
def players():
    all_players = Player.query.order_by(Player.is_retained.desc(), Player.player_name).all()
    return render_template('players.html', active_page='players', players=all_players)

# --- TEAMS ROUTE (PUBLIC) ---
@app.route('/teams')
def teams():
    all_teams = Team.query.options(db.joinedload(Team.players)).order_by(Team.team_name).all()
    return render_template('teams.html', active_page='teams', teams=all_teams, current_user=current_user)

# --- AUCTION ROUTES (PUBLIC, content conditional) ---
@app.route('/auctions')
def auctions():
    all_teams = Team.query.all()
    auction_started = session.get('auction_started', False); auction_round = session.get('auction_round', 1); round_complete = session.get('round_complete', False); auction_complete = session.get('auction_complete', False); auction_paused = session.get('auction_paused', False); current_player = None; next_round_players_count = 0
    total_auction_players = Player.query.filter_by(is_retained=False).count()
    sold_players_count = Player.query.filter_by(is_retained=False, status='Sold').count()
    currently_unsold_count = Player.query.filter_by(is_retained=False, status='Unsold').count()
    marked_unsold_count = Player.query.filter(Player.is_retained==False, (Player.status.like('Round % Unsold') | (Player.status == 'Unsold Final'))).count()
    total_remaining_count = currently_unsold_count + marked_unsold_count
    if auction_started and not round_complete and not auction_complete and not auction_paused:
        player_id = session.get('current_player_id')
        if player_id:
            current_player = Player.query.get(player_id)
            if current_player and current_player.status != 'Unsold':
                 session.pop('current_player_id', None); current_player = None
                 if current_user.is_authenticated and current_user.role in ['Admin', 'Super Admin']: return redirect(url_for('next_player'))
    if round_complete:
        next_round_status = f'Round {auction_round} Unsold'
        next_round_players_count = Player.query.filter(Player.is_retained==False, Player.status==next_round_status).count()
        if next_round_players_count == 0:
             still_unsold = Player.query.filter_by(is_retained=False, status='Unsold').count()
             if still_unsold == 0: auction_complete = True; auction_started = False; session['auction_complete'] = True; session['auction_started'] = False
    return render_template('auctions.html',
                           active_page='auctions', all_teams=all_teams,
                           auction_started=auction_started, round_complete=round_complete,
                           auction_complete=auction_complete, auction_paused=auction_paused,
                           next_round_players_count=next_round_players_count,
                           auction_round=auction_round, player=current_player,
                           current_user=current_user,
                           total_auction_players=total_auction_players, sold_players_count=sold_players_count,
                           remaining_players_count=total_remaining_count, currently_unsold_count=currently_unsold_count,
                           marked_unsold_count=marked_unsold_count)

@app.route('/next_player')
@login_required
@role_required(['Admin'])
def next_player():
    if session.get('auction_paused'): flash('Auction is paused. Resume before proceeding.', 'warning'); return redirect(url_for('auctions'))
    auction_round = session.get('auction_round', 1); current_round_status = 'Unsold'; next_round_status_check = f'Round {auction_round} Unsold'; unsold_players = Player.query.filter_by(status=current_round_status, is_retained=False).all()
    if not unsold_players:
        players_for_next_round_count = Player.query.filter_by(status=next_round_status_check, is_retained=False).count()
        if players_for_next_round_count > 0: flash(f'Round {auction_round} complete. Ready for Round {auction_round + 1}.', 'info'); session['round_complete'] = True; session['auction_started'] = False; session.pop('current_player_id', None)
        else: flash(f'Auction complete after Round {auction_round}! All non-retained players processed.', 'success'); session['auction_started'] = False; session['auction_complete'] = True; session.pop('current_player_id', None)
        return redirect(url_for('auctions'))
    random_player = random.choice(unsold_players); session['auction_started'] = True; session['current_player_id'] = random_player.id; session['round_complete'] = False; session['auction_complete'] = False
    return redirect(url_for('auctions'))

@app.route('/start_next_round')
@login_required
@role_required(['Admin'])
def start_next_round():
    auction_round = session.get('auction_round', 1); round_complete = session.get('round_complete', False)
    if not round_complete: flash('Cannot start next round until the current one is complete.', 'warning'); return redirect(url_for('auctions'))
    completed_round_status = f'Round {auction_round} Unsold'; players_for_next_round = Player.query.filter_by(status=completed_round_status, is_retained=False).all()
    if not players_for_next_round: flash('No players available for the next round.', 'info'); session['auction_complete'] = True; session['auction_started'] = False; session['round_complete'] = False; return redirect(url_for('auctions'))
    for player in players_for_next_round: player.status = 'Unsold'
    db.session.commit(); next_round_number = auction_round + 1; session['auction_round'] = next_round_number; session['round_complete'] = False; session['auction_started'] = True; session['auction_paused'] = False
    flash(f'Starting Round {next_round_number}!', 'success'); return redirect(url_for('next_player'))

@app.route('/sold/<int:player_id>', methods=['POST'])
@login_required
@role_required(['Admin'])
def mark_sold(player_id):
    if session.get('auction_paused'): flash('Auction is paused. Resume before marking player sold.', 'warning'); return redirect(url_for('auctions'))
    player = Player.query.get_or_404(player_id);
    if player.is_retained or player.status != 'Unsold' or not session.get('auction_started') or session.get('current_player_id') != player_id: flash('This player is not currently up for auction or action already taken.', 'error'); return redirect(url_for('auctions'))
    try: team_id = int(request.form.get('team_id')); sold_price = int(request.form.get('sold_price'))
    except (ValueError, TypeError): flash('Invalid team or price.', 'error'); return redirect(url_for('auctions'))
    team = Team.query.get_or_404(team_id)
    if team.slots_remaining <= 0: flash(f'{team.team_name} has no remaining slots!', 'error'); return redirect(url_for('auctions'))
    if team.purse < sold_price: flash(f'{team.team_name} does not have enough purse (Remaining: {team.purse})!', 'error'); return redirect(url_for('auctions'))
    player.status = 'Sold'; player.sold_price = sold_price; player.team_id = team.id; team.purse -= sold_price; team.purse_spent += sold_price; team.players_taken_count += 1; team.slots_remaining -= 1
    db.session.commit(); flash(f'{player.player_name} sold to {team.team_name} for {sold_price} points!', 'success')
    session.pop('current_player_id', None); return redirect(url_for('next_player'))

@app.route('/unsold/<int:player_id>', methods=['POST'])
@login_required
@role_required(['Admin'])
def mark_unsold(player_id):
    if session.get('auction_paused'): flash('Auction is paused. Resume before marking player unsold.', 'warning'); return redirect(url_for('auctions'))
    player = Player.query.get_or_404(player_id);
    if player.is_retained or player.status != 'Unsold' or not session.get('auction_started') or session.get('current_player_id') != player_id: flash('This player is not currently up for auction or action already taken.', 'error'); return redirect(url_for('auctions'))
    auction_round = session.get('auction_round', 1); player.status = f'Round {auction_round} Unsold'; flash_msg = f'{player.player_name} marked as unsold for Round {auction_round}. Available in next round.'
    db.session.commit(); flash(flash_msg, 'info'); session.pop('current_player_id', None)
    return redirect(url_for('next_player'))

@app.route('/restart_auction', methods=['GET', 'POST'])
@login_required
@role_required(['Admin'])
def restart_auction():
    if request.method == 'POST':
        if not current_user.is_authenticated: flash('Authentication error. Please log in again.', 'error'); return redirect(url_for('login'))
        password = request.form.get('password')
        if not password or not current_user.check_password(password): flash('Invalid admin password. Auction not reset.', 'error'); return render_template('restart_confirm.html', active_page='auctions')
        try:
            players_to_reset = Player.query.filter_by(is_retained=False).all()
            for player in players_to_reset: player.status = 'Unsold'; player.sold_price = 0; player.team_id = None
            teams_to_reset = Team.query.all(); max_slots = 15
            for team in teams_to_reset:
                retained_players = Player.query.filter_by(team_id=team.id, is_retained=True).all()
                retained_count = len(retained_players); retained_cost = sum(p.sold_price for p in retained_players if p.sold_price is not None)
                team.players_taken_count = retained_count; team.slots_remaining = max_slots - retained_count; team.purse_spent = retained_cost; team.purse = 10000 - retained_cost
            db.session.commit()
            session.pop('auction_started', None); session.pop('current_player_id', None); session.pop('auction_round', None); session.pop('round_complete', None); session.pop('auction_complete', None); session.pop('auction_paused', None)
            flash('Auction has been reset! (Retained players kept)', 'success'); return redirect(url_for('auctions'))
        except Exception as e: db.session.rollback(); flash(f'An error occurred while resetting the auction: {e}', 'error'); return redirect(url_for('auctions'))
    return render_template('restart_confirm.html', active_page='auctions')

@app.route('/pause_auction', methods=['POST'])
@login_required
@role_required(['Admin'])
def pause_auction():
    if not session.get('auction_started', False) or session.get('auction_complete', False): flash('Auction is not currently running or is already complete.', 'warning'); return redirect(url_for('auctions'))
    session['auction_paused'] = True; flash('Auction paused.', 'info'); return redirect(url_for('auctions'))

@app.route('/resume_auction', methods=['GET', 'POST'])
@login_required
@role_required(['Admin'])
def resume_auction():
    if not session.get('auction_paused', False): flash('Auction is not paused.', 'warning'); return redirect(url_for('auctions'))
    if request.method == 'POST':
        if not current_user.is_authenticated: flash('Authentication error. Please log in again.', 'error'); return redirect(url_for('login'))
        password = request.form.get('password')
        if not password or not current_user.check_password(password): flash('Invalid admin credentials. Auction not resumed.', 'error'); return render_template('resume_confirm.html', active_page='auctions')
        session['auction_paused'] = False; flash('Auction resumed.', 'success')
        if session.get('current_player_id'): return redirect(url_for('auctions'))
        else: return redirect(url_for('next_player'))
    return render_template('resume_confirm.html', active_page='auctions')

# --- ADMIN & SUPER ADMIN ROUTES ---
@app.route('/create_user', methods=['GET', 'POST'])
@login_required
@role_required(['Admin'])
def create_user():
    teams = Team.query.all()
    if request.method == 'POST':
        full_name = request.form.get('full_name'); username = request.form.get('username'); password = request.form.get('password'); role = request.form.get('role'); team_id = request.form.get('team_id')
        if current_user.role == 'Admin' and role in ['Super Admin', 'Admin']:
             flash('Admins can only create Captains.', 'error'); return redirect(url_for('create_user'))
        existing_user = User.query.filter_by(username=username).first()
        if existing_user: flash(f'Username "{username}" already exists.', 'error'); return redirect(url_for('create_user'))
        new_user = User(full_name=full_name, username=username, role=role, team_id=int(team_id) if team_id and role == 'Captain' else None)
        new_user.set_password(password); db.session.add(new_user); db.session.commit()
        flash(f'Login created for {full_name}!', 'success'); return redirect(url_for('dashboard'))
    return render_template('create_user.html', active_page='create_user', teams=teams)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required(['Super Admin']) # Only Super Admins can edit
def edit_user(user_id):
    user_to_edit = User.query.get_or_404(user_id) # Find the user or show 404 error
    teams = Team.query.all() # Get teams for the dropdown
    if request.method == 'POST':
        new_full_name = request.form.get('full_name'); new_username = request.form.get('username'); new_role = request.form.get('role'); new_team_id = request.form.get('team_id'); new_password = request.form.get('password')
        if new_username != user_to_edit.username and User.query.filter(User.username == new_username, User.id != user_id).first():
            flash(f'Username "{new_username}" is already taken.', 'error')
            return render_template('edit_user.html', active_page='dashboard', user=user_to_edit, teams=teams)
        user_to_edit.full_name = new_full_name; user_to_edit.username = new_username; user_to_edit.role = new_role
        user_to_edit.team_id = int(new_team_id) if new_team_id and new_role == 'Captain' else None
        if new_password: user_to_edit.set_password(new_password); flash('Password updated successfully.', 'info')
        try:
            db.session.commit(); flash(f'User "{user_to_edit.full_name}" updated successfully!', 'success'); return redirect(url_for('dashboard'))
        except Exception as e: db.session.rollback(); flash(f'Error updating user: {e}', 'error')
    return render_template('edit_user.html', active_page='dashboard', user=user_to_edit, teams=teams)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@role_required(['Super Admin']) # Only Super Admins can delete
def delete_user(user_id):
    if user_id == current_user.id: flash('You cannot delete your own account.', 'error'); return redirect(url_for('dashboard'))
    user_to_delete = User.query.get_or_404(user_id)
    try:
        db.session.delete(user_to_delete); db.session.commit(); flash(f'User "{user_to_delete.username}" deleted successfully.', 'success')
    except Exception as e: db.session.rollback(); flash(f'Error deleting user: {e}', 'error')
    return redirect(url_for('dashboard'))

# --- EXPORT ROUTE ---
@app.route('/export_team_excel/<int:team_id>')
@login_required
def export_team_excel(team_id):
    team = Team.query.get_or_404(team_id)
    team_players = team.players.order_by(Player.is_retained.desc(), Player.player_name).all()
    players_data = []
    for player in team_players:
        price_label = player.sold_price if player.sold_price is not None else 0
        status_label = "Retained" if player.is_retained else ("Sold" if player.status == 'Sold' else "Unsold/Other")
        players_data.append({'Player Name': player.player_name, 'Status': status_label, 'Price (Points)': price_label,
                             'Overall Matches': player.overall_matches, 'Overall Runs': player.overall_runs, 'Overall Wickets': player.overall_wickets,
                             'Overall SR': player.overall_sr, 'Overall HS': player.overall_hs, # Added
                             'CPL 2024 Team': player.cpl_2024_team, 'CPL 2024 Innings': player.cpl_2024_innings,
                             'CPL 2024 Runs': player.cpl_2024_runs, 'CPL 2024 Wickets': player.cpl_2024_wickets, # Added
                             'CPL 2024 SR': player.cpl_2024_sr, 'CPL 2024 HS': player.cpl_2024_hs})
    if not players_data: flash(f"{team.team_name} has no players to export.", "info"); return redirect(url_for('teams'))
    df = pd.DataFrame(players_data); output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer: df.to_excel(writer, index=False, sheet_name=team.team_name)
    output.seek(0); return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', download_name=f'{team.team_name}_players.xlsx', as_attachment=True)


# --- RUN THE APP ---
if __name__ == '__main__':
    app.run(debug=True)