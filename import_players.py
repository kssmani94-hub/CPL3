import pandas as pd
from app import app, db
from models import Player, Team
import math

def import_players_from_csv(filepath='players_data.csv'):
    """Reads player data from CSV and populates the database."""
    try:
        df = pd.read_csv(filepath).fillna(value=pd.NA)
        print(f"Reading data from {filepath}...")
    except FileNotFoundError:
        print(f"Error: CSV file not found at {filepath}")
        return
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        return

    with app.app_context():
        teams_map = {team.team_name.strip(): team.id for team in Team.query.all()}

    new_players_count = 0
    updated_players_count = 0

    with app.app_context():
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
                    else: print(f"Warning: Retaining team '{retaining_team_name}' not found for player '{player_name}'."); is_retained = False
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
                def safe_str(value, default=None):
                    if pd.isna(value) or value is None: return default
                    return str(value).strip()

                # --- Data mapping (CPL_2024 fields removed) ---
                player_data = {
                    'player_name': player_name,
                    'image_filename': image_filename if image_filename else 'default_player.png',
                    'is_retained': is_retained,
                    'team_id': team_id,
                    'sold_price': last_year_price if is_retained else 0,
                    'status': 'Retained' if is_retained else 'Unsold',
                    'role': safe_str(row.get('role'), 'N/A'),
                    'overall_matches': safe_int(row.get('overall_matches')),
                    'overall_runs': safe_int(row.get('overall_runs')),
                    'overall_wickets': safe_int(row.get('overall_wickets')),
                    'overall_sr': safe_float(row.get('overall_sr')),
                    'overall_hs': safe_int(row.get('overall_hs')),
                    'batting_inn': safe_int(row.get('batting_inn')),
                    'batting_avg': safe_float(row.get('batting_avg')),
                    'bowling_inn': safe_int(row.get('bowling_inn')),
                    'bowling_avg': safe_float(row.get('bowling_avg')),
                    'econ': safe_float(row.get('econ')),
                    'bbi': safe_str(row.get('bbi'), '-'),
                }

                if not player:
                    player = Player(**player_data)
                    db.session.add(player)
                    new_players_count += 1
                else:
                    print(f"Player '{player_name}' already exists. Updating details.")
                    for key, value in player_data.items():
                        setattr(player, key, value)
                    if player_data['is_retained'] and player.status != 'Sold': player.status = 'Retained'
                    elif not player_data['is_retained'] and player.status == 'Retained': player.status = 'Unsold'
                    updated_players_count += 1
            except Exception as e:
                print(f"Error processing row {index + 2} for player '{row.get('player_name', 'N/A')}': {e}"); db.session.rollback()
        
        try:
            db.session.commit()
            print(f"Import complete. Added: {new_players_count}, Updated: {updated_players_count}")
        except Exception as e:
            db.session.rollback()
            print(f"Error during final database commit: {e}")

    recalculate_initial_team_stats()


def recalculate_initial_team_stats():
    """Calculates team stats based on retained players."""
    print("Recalculating initial team stats based on retained players...")
    with app.app_context():
        all_teams = Team.query.all()
        max_slots = 15
        for team in all_teams:
            retained_players = team.players.filter_by(is_retained=True).all()
            retained_count = len(retained_players); retained_cost = sum(p.sold_price for p in retained_players if p.sold_price is not None)
            team.players_taken_count = retained_count; team.slots_remaining = max_slots - retained_count
            team.purse_spent = retained_cost; team.purse = 10000 - retained_cost
            print(f"Team: {team.team_name}, Retained: {retained_count}, Cost: {retained_cost}, Purse Left: {team.purse}, Slots Left: {team.slots_remaining}")
        try:
            db.session.commit()
            print("Initial team stats updated successfully.")
        except Exception as e:
            db.session.rollback()
            print(f"Error updating team stats: {e}")

if __name__ == '__main__':
    with app.app_context():
        inspector = db.inspect(db.engine)
        if not inspector.has_table("player") or not inspector.has_table("team"):
            print("Database tables ('player' or 'team') not found.")
            print("Please run the Flask app once (`flask run`) to create the database and tables before importing.")
        else:
            print("Resetting ALL player data for fresh import...")
            Player.query.delete()
            db.session.commit()
            print("Existing players deleted.")
            import_players_from_csv()