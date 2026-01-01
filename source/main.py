"""Main module for VPN config generator with refactored, streamlined logic."""

import os
import sys
import argparse

# Add the source directory to the path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from processors.config_processor import process_all_configs
from utils.github_handler import GitHubHandler
from utils.logger import log, print_logs


def main(dry_run: bool = False, output_dir: str = "../githubmirror"):
    """Main execution function with streamlined logic."""
    log("Starting VPN config generation...")

    # Process all configs following the new streamlined approach
    file_pairs = process_all_configs(output_dir)

    # Upload files to GitHub if not in dry-run mode
    if not dry_run and file_pairs:
        github_handler = GitHubHandler()
        github_handler.upload_multiple_files(file_pairs)

    # Print logs
    print_logs()
    log("VPN config generation completed!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download configs and upload to GitHub")
    parser.add_argument("--dry-run", action="store_true", help="Only download and save locally, don't upload to GitHub")
    args = parser.parse_args()

    main(dry_run=args.dry_run)