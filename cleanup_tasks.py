import os
import time
import logging
from datetime import datetime, timedelta

# Setup logging
logger = logging.getLogger(__name__)

def clean_temporary_files(temp_dir=None, max_age_hours=24):
    """
    Remove temporary files older than the specified age.
    
    Args:
        temp_dir (str): Directory containing temporary files. If None, will use the 'tmp' directory in the current folder.
        max_age_hours (int): Maximum age of files in hours before they are deleted.
    """
    if temp_dir is None:
        # Use the default tmp directory in the current folder
        temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tmp')
    
    if not os.path.exists(temp_dir) or not os.path.isdir(temp_dir):
        logger.warning(f"Temporary directory does not exist: {temp_dir}")
        return
    
    logger.info(f"Cleaning temporary files from {temp_dir} older than {max_age_hours} hours")
    
    # Calculate the cutoff time
    cutoff_time = time.time() - (max_age_hours * 3600)
    
    # Count of files removed
    count = 0
    
    try:
        # Loop through all files in the temp directory
        for filename in os.listdir(temp_dir):
            file_path = os.path.join(temp_dir, filename)
            
            # Skip directories
            if os.path.isdir(file_path):
                continue
            
            # Check if the file is older than the cutoff time
            file_mod_time = os.path.getmtime(file_path)
            if file_mod_time < cutoff_time:
                try:
                    os.remove(file_path)
                    count += 1
                    logger.debug(f"Removed temporary file: {file_path}")
                except Exception as e:
                    logger.error(f"Failed to remove temporary file {file_path}: {str(e)}")
        
        logger.info(f"Cleanup completed. Removed {count} temporary files.")
    except Exception as e:
        logger.error(f"Error during cleanup of temporary files: {str(e)}")