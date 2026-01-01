"""GitHub API handler for uploading files."""

from github import Github, Auth, GithubException
import time
import os
import concurrent.futures
from typing import Optional
from config.settings import GITHUB_TOKEN, REPO_NAME
from utils.logger import log, updated_files, _UPDATED_FILES_LOCK


class GitHubHandler:
    def __init__(self):
        if GITHUB_TOKEN:
            self.g = Github(auth=Auth.Token(GITHUB_TOKEN))
        else:
            self.g = Github()

        self.repo = self.g.get_repo(REPO_NAME)

        # Check GitHub API limits
        try:
            remaining, limit = self.g.rate_limiting
            if remaining < 100:
                log(f"Warning: {remaining}/{limit} GitHub API requests remaining")
            else:
                log(f"Available GitHub API requests: {remaining}/{limit}")
        except Exception as e:
            log(f"Could not check GitHub API limits: {e}")

    def upload_file(self, local_path: str, remote_path: str):
        """Uploads a local file to GitHub repository."""
        if not self._file_exists(local_path):
            log(f"File {local_path} not found.")
            return

        with open(local_path, "r", encoding="utf-8") as file:
            content = file.read()

        max_retries = 5

        for attempt in range(1, max_retries + 1):
            try:
                # Try to get the existing file to check for changes
                try:
                    file_in_repo = self.repo.get_contents(remote_path)
                    current_sha = file_in_repo.sha
                except GithubException as e_get:
                    if getattr(e_get, "status", None) == 404:
                        # File doesn't exist, create it
                        basename = self._get_basename(remote_path)
                        self.repo.create_file(
                            path=remote_path,
                            message=f"First commit {basename}: {self._get_timestamp()}",
                            content=content,
                        )
                        log(f"File {remote_path} created.")
                        self._add_to_updated_files(remote_path)
                        return
                    else:
                        msg = e_get.data.get("message", str(e_get))
                        log(f"Error getting {remote_path}: {msg}")
                        return

                try:
                    remote_content = file_in_repo.decoded_content.decode("utf-8", errors="replace")
                    if remote_content == content:
                        log(f"No changes for {remote_path}.")
                        return
                except Exception:
                    pass

                # Update the file
                basename = self._get_basename(remote_path)
                try:
                    self.repo.update_file(
                        path=remote_path,
                        message=f"Update {basename}: {self._get_timestamp()}",
                        content=content,
                        sha=current_sha,
                    )
                    log(f"File {remote_path} updated in repository.")
                    self._add_to_updated_files(remote_path)
                    return
                except GithubException as e_upd:
                    if getattr(e_upd, "status", None) == 409:
                        if attempt < max_retries:
                            wait_time = 0.5 * (2 ** (attempt - 1))
                            log(f"SHA conflict for {remote_path}, attempt {attempt}/{max_retries}, waiting {wait_time} sec")
                            time.sleep(wait_time)
                            continue
                        else:
                            log(f"Could not update {remote_path} after {max_retries} attempts")
                            return
                    else:
                        msg = e_upd.data.get("message", str(e_upd))
                        log(f"Error uploading {remote_path}: {msg}")
                        return

            except Exception as e_general:
                short_msg = str(e_general)
                if len(short_msg) > 200:
                    short_msg = short_msg[:200] + "…"
                log(f"Unexpected error updating {remote_path}: {short_msg}")
                return

        log(f"Could not update {remote_path} after {max_retries} attempts")


    def upload_multiple_files(self, file_pairs: list, dry_run: bool = False):
        """Uploads multiple config files to GitHub."""
        max_workers_upload = max(2, min(6, len(file_pairs)))

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers_upload) as upload_pool:
            upload_futures = []

            for local_path, remote_path in file_pairs:
                if dry_run:
                    log(f"Dry-run: skipping upload of {remote_path} (local path {local_path})")
                else:
                    upload_futures.append(
                        upload_pool.submit(self.upload_file, local_path, remote_path)
                    )

            for uf in concurrent.futures.as_completed(upload_futures):
                _ = uf.result()


    def _file_exists(self, path: str) -> bool:
        """Checks if a local file exists."""
        return os.path.exists(path)

    def _get_basename(self, remote_path: str) -> str:
        """Extracts the basename from a remote path."""
        return os.path.basename(remote_path)

    def _get_timestamp(self) -> str:
        """Gets the current timestamp."""
        from config.settings import OFFSET
        return OFFSET

    def _extract_source_name(self, url: str) -> str:
        """Extracts source name from URL."""
        from utils.logger import extract_source_name
        return extract_source_name(url)

    def _add_to_updated_files(self, remote_path: str):
        """Adds a file to the updated files set."""
        path_parts = remote_path.split('/')
        if len(path_parts) >= 2:
            folder_or_filename = path_parts[1]
            if folder_or_filename == "bypass":
                # Handle bypass files (e.g., bypass/bypass-1.txt, bypass/bypass-all.txt)
                if len(path_parts) >= 3:
                    bypass_filename = path_parts[2]
                    if bypass_filename.startswith("bypass-") and bypass_filename.endswith(".txt"):
                        if bypass_filename == "bypass-all.txt":
                            # Use a special number to represent bypass-all.txt in updated_files
                            file_index = 99999
                        else:
                            # Extract number from bypass-N.txt
                            num_str = bypass_filename.replace("bypass-", "").replace(".txt", "")
                            try:
                                file_index = int(num_str)
                            except ValueError:
                                file_index = -1  # Invalid bypass file
                    else:
                        # Default to -1 if it's not a bypass file
                        file_index = -1
                else:
                    file_index = -1
            else:
                # Handle default files (e.g., default/1.txt, etc.)
                try:
                    file_index = int(folder_or_filename.split('.')[0])
                except ValueError:
                    file_index = -1
        else:
            file_index = -1

        if file_index != -1:
            with _UPDATED_FILES_LOCK:
                updated_files.add(file_index)