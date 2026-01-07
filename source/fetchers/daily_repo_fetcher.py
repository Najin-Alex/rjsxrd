"""Module for fetching VPN configs from daily-updated repository."""

import datetime
import base64
from typing import List, Optional
from urllib.parse import urljoin
import sys
import os

# Add the source directory to the path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fetchers.fetcher import fetch_data
from utils.logger import log
from utils.file_utils import prepare_config_content


def generate_date_filename(date: datetime.date) -> str:
    """Generate filename in format v2YYYYMMDD based on the given date."""
    return f"v2{date.strftime('%Y%m%d')}"


def fetch_daily_configs(base_url: str, date: datetime.date) -> Optional[List[str]]:
    """Fetch configs from daily-updated repository for a specific date."""
    filename = generate_date_filename(date)
    url = urljoin(base_url, filename)

    try:
        content = fetch_data(url)
        # Check if content is base64-encoded (common for VPN config repositories)
        try:
            # Try to decode as base64
            decoded_bytes = base64.b64decode(content.strip())
            decoded_content = decoded_bytes.decode('utf-8')
            configs = prepare_config_content(decoded_content)
        except Exception:
            # If base64 decoding fails, treat as plain text
            configs = prepare_config_content(content)

        log(f"Successfully fetched {len(configs)} configs from {url}")
        return configs
    except Exception as e:
        log(f"Error fetching configs from {url}: {str(e)[:200]}...")
        return None


def fetch_daily_configs_with_timezone_fallback(base_url: str, target_date: Optional[datetime.date] = None) -> List[str]:
    """Fetch configs from daily-updated repository with timezone fallback logic.

    Tries to fetch configs starting from target date, then expands to previous and next days
    until successfully fetching configs from 10 different dates.

    Returns combined configs from up to 10 successful fetches, or empty list if all attempts fail.
    """
    if target_date is None:
        target_date = datetime.date.today()

    all_configs = []
    successful_fetches = 0
    max_fetches = 10
    date_offset = 0

    # Continue fetching until we reach max_fetches or exhaust reasonable date range
    while successful_fetches < max_fetches:
        dates_to_try = []

        # Add current date_offset (both positive and negative)
        if date_offset == 0:
            dates_to_try.append(target_date)
        else:
            dates_to_try.append(target_date + datetime.timedelta(days=date_offset))
            dates_to_try.append(target_date - datetime.timedelta(days=date_offset))

        for date in dates_to_try:
            if successful_fetches >= max_fetches:
                break

            configs = fetch_daily_configs(base_url, date)
            if configs is not None:
                log(f"Successfully fetched configs for date {date} ({generate_date_filename(date)}) - {len(configs)} configs")
                all_configs.extend(configs)
                successful_fetches += 1
                if successful_fetches >= max_fetches:
                    break

        date_offset += 1

        # Limit search to reasonable range (e.g., 30 days in either direction)
        if date_offset > 30:
            break

    log(f"Completed fetching. Successfully fetched configs from {successful_fetches} different dates")
    if not all_configs:
        log(f"No configs found after trying multiple dates")

    return all_configs


def fetch_configs_from_daily_repo(base_url: str = "https://raw.githubusercontent.com/free-nodes/v2rayfree/refs/heads/main/") -> List[str]:
    """Main function to fetch configs from the daily-updated repository."""
    log(f"Fetching configs from daily-updated repository: {base_url}")
    configs = fetch_daily_configs_with_timezone_fallback(base_url)
    log(f"Total configs fetched from daily repository: {len(configs)}")
    return configs