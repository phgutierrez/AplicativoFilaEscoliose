import shutil
from datetime import datetime
import os

def backup_database():
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    source = "db.sqlite3"
    backup_dir = "backups"
    
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
        
    backup_file = f"{backup_dir}/db_backup_{timestamp}.sqlite3"
    shutil.copy2(source, backup_file)
    
    # Manter apenas os últimos 5 backups
    backups = sorted([f for f in os.listdir(backup_dir) if f.startswith('db_backup_')])
    for old_backup in backups[:-5]:
        os.remove(os.path.join(backup_dir, old_backup))