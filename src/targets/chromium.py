import re
import subprocess as sp
from datetime import datetime
from pathlib import Path
from shutil import which
from typing import List

from loguru import logger

from targets.factory import TargetFactory


class Chromium(TargetFactory):
    """
    A class representing the Chromium browser repository.
    """

    _target_type = "chromium"
    _build_commands = ""  # Will be populated from compile_commands.json

    def checkout_commit(self, commit_id, is_before=False, **kwargs):
        """
        Checkout a specific commit in the Chromium repository and prepare the build environment.

        Args:
            commit_id (str): The commit ID to checkout.
            is_before (bool): Whether to checkout before the commit.
            arch (str): The architecture to build for (x64, arm64, etc.).
            build_config (str): The build configuration (debug/release).
            llvm_path (str/Path): Custom LLVM path to use (optional).
            skip_chromium_build (bool): Skip Chromium build (preserve existing out/ directory).
        """
        # Extract flags from kwargs
        skip_chromium_build = kwargs.get("skip_chromium_build", False)

        logger.info(
            f"Checking out commit {commit_id} {'before' if is_before else 'after'}"
        )

        if skip_chromium_build:
            logger.info("Skipping Chromium build - preserving existing out/ directory")
        else:
            # Clean previous build artifacts
            logger.info("Cleaning previous build artifacts")
            res = sp.run(
                ["rm", "-rf", "out"], cwd=self.repo.working_dir, capture_output=True
            )
            if res.returncode != 0:
                logger.warning(f"Failed to clean out directory: {res.stderr.decode()}")

        if is_before:
            # Get the parent commit for "before" state
            commit_id = commit_id + "^"

        # Reset any uncommitted changes from previous runs
        try:
            self.repo.git.reset("--hard")
            self.repo.git.clean("-fd")
            
            # Also clean submodules to avoid gclient sync issues
            self.repo.git.submodule("foreach", "--recursive", "git reset --hard")
            self.repo.git.submodule("foreach", "--recursive", "git clean -fd")
        except Exception as e:
            logger.warning(f"Failed to clean repository state: {e}")

        self.repo.git.checkout(commit_id)

        # Try to sync dependencies with gclient
        repo_dir = Path(self.repo.working_dir)
        gclient_exe = which("gclient")

        # If gclient not in PATH, try common locations
        if not gclient_exe:
            potential_paths = [
                Path.home() / "depot_tools" / "gclient",
                Path("/usr/local/bin/gclient"),
                Path("/opt/depot_tools/gclient"),
            ]
            for path in potential_paths:
                if path.exists():
                    gclient_exe = str(path)
                    break

        # Check for .gclient file in current or parent directory
        has_gclient_config = (repo_dir / ".gclient").exists() or (
            repo_dir.parent / ".gclient"
        ).exists()

        if gclient_exe and has_gclient_config:
            logger.info("Syncing dependencies with gclient...")
            try:
                res = sp.run(
                    [gclient_exe, "sync"],
                    cwd=self.repo.working_dir,
                    capture_output=True,
                    timeout=1800,  # 30 minutes for Chromium sync
                    text=True,
                )
                if res.returncode != 0:
                    logger.error(f"Failed to sync dependencies: {res.stderr}")
                    logger.warning("Dependency sync failed, attempting build anyway...")
                    # For static analysis, we can often proceed without full dependency sync
                    logger.info("Note: Use skip_gclient_sync=True to bypass this step entirely")
                else:
                    logger.info("Dependency sync completed.")
            except sp.TimeoutExpired:
                logger.error("gclient sync timed out after 30 minutes")
                logger.warning("Proceeding without complete dependency sync...")
        else:
            if not gclient_exe:
                logger.warning("Skipping gclient sync: 'gclient' not found on PATH.")
            if not has_gclient_config:
                logger.warning(
                    "Skipping gclient sync: .gclient not found (client not configured)."
                )

        # Generate build files using gn
        arch = kwargs.get("arch", "x64")
        build_config = kwargs.get("build_config", "release")
        build_dir = f"out/{arch}_{build_config}"

        # Check if we should use custom LLVM (from kwargs)
        custom_llvm_path = kwargs.get("llvm_path")

        # Convert to Path if string provided
        if custom_llvm_path and not isinstance(custom_llvm_path, Path):
            custom_llvm_path = Path(custom_llvm_path)

        if custom_llvm_path and custom_llvm_path.exists():
            logger.info(f"Using custom LLVM from {custom_llvm_path}")

            # Get the clang version
            clang_version_result = sp.run(
                [str(custom_llvm_path / "bin" / "clang"), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            clang_version = "21"  # default
            if clang_version_result.returncode == 0:
                version_match = re.search(r"clang version (\d+)", clang_version_result.stdout)
                if version_match:
                    clang_version = version_match.group(1)

            gn_args = [
                f'target_cpu="{arch}"',
                f"is_debug={'true' if build_config == 'debug' else 'false'}",
                f'clang_base_path="{custom_llvm_path}"',
                "clang_use_chrome_plugins=false",
                f'clang_version="{clang_version}"',
                "use_custom_libcxx=true",
                "is_clang=true",
                "use_lld=true",
                "treat_warnings_as_errors=false",
                # Chromium specific settings
                "enable_nacl=false",
                "dcheck_always_on=false",
                "is_component_build=false",
                "symbol_level=1",
                # Use LLVM's ar and ranlib
                f'ar="{custom_llvm_path}/bin/llvm-ar"',
                f'ranlib="{custom_llvm_path}/bin/llvm-ranlib"',
            ]
        else:
            logger.info(
                "Using system clang (no custom LLVM path provided or path doesn't exist)"
            )

            gn_args = [
                f'target_cpu="{arch}"',
                f"is_debug=false",
                "enable_nacl=false",
                "dcheck_always_on=false",
                "is_component_build=false",
                "symbol_level=1",
                "treat_warnings_as_errors=false",
            ]

        # Locate gn from PATH or common Chromium location
        gn_exe = which("gn")
        if not gn_exe:
            candidate = repo_dir / "buildtools" / "linux64" / "gn"
            if candidate.exists():
                gn_exe = str(candidate)
        if not gn_exe:
            raise RuntimeError(
                "GN executable not found. Install depot_tools or ensure 'gn' is on PATH."
            )

        # Apply version-specific patches before generating build files
        self._apply_version_patches()

        logger.info(
            f"Generating build files for {arch.upper()}/{build_config.upper()} with arguments: {' '.join(gn_args)}"
        )
        # Also export compile_commands.json for static analysis
        res = sp.run(
            [
                gn_exe,
                "gen",
                build_dir,
                f"--args={' '.join(gn_args)}",
                "--export-compile-commands",
            ],
            cwd=self.repo.working_dir,
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            logger.error(f"Failed to generate build files: {res.stderr}")
            logger.error(res.stdout)
            raise RuntimeError(f"Failed to generate build files: {res.stderr}")

        logger.info(f"Build files generated successfully for {build_dir}")

    def _apply_version_patches(self):
        """
        Apply version-specific patches to handle build system incompatibilities.
        This method is called after checking out a commit to fix known issues.
        """
        # Fix exec_script_whitelist -> exec_script_allowlist change
        self._fix_exec_script_naming()

    def _fix_exec_script_naming(self):
        """
        Fix the exec_script_whitelist -> exec_script_allowlist naming change.
        This change occurred in Chromium around 2021 (similar to V8's change).
        """
        gn_file = Path(self.repo.working_dir) / ".gn"
        if not gn_file.exists():
            return

        try:
            content = gn_file.read_text()

            # Check if we need to patch (has old naming)
            if "exec_script_whitelist" in content:
                # First check if build_dotfile_settings has the new naming
                dotfile_settings = (
                    Path(self.repo.working_dir) / "build" / "dotfile_settings.gni"
                )
                if dotfile_settings.exists():
                    settings_content = dotfile_settings.read_text()
                    if (
                        "exec_script_allowlist" in settings_content
                        and "exec_script_whitelist" not in settings_content
                    ):
                        # The build system uses new naming but .gn uses old - need to patch
                        logger.info(
                            "Patching Chromium .gn file: exec_script_whitelist -> exec_script_allowlist"
                        )
                        patched_content = content.replace(
                            "exec_script_whitelist", "exec_script_allowlist"
                        )
                        gn_file.write_text(patched_content)
                        logger.info("Successfully patched Chromium .gn file for compatibility")

            # Handle the reverse case (old build system, new .gn file)
            elif "exec_script_allowlist" in content:
                dotfile_settings = (
                    Path(self.repo.working_dir) / "build" / "dotfile_settings.gni"
                )
                if dotfile_settings.exists():
                    settings_content = dotfile_settings.read_text()
                    if (
                        "exec_script_whitelist" in settings_content
                        and "exec_script_allowlist" not in settings_content
                    ):
                        # The build system uses old naming but .gn uses new - need to patch
                        logger.info(
                            "Patching Chromium .gn file: exec_script_allowlist -> exec_script_whitelist"
                        )
                        patched_content = content.replace(
                            "exec_script_allowlist", "exec_script_whitelist"
                        )
                        gn_file.write_text(patched_content)
                        logger.info("Successfully patched Chromium .gn file for compatibility")
            
            # if "angle_dotfile_settings.exec_script_whitelist" in content:
            #     logger.info(
            #         "Patching Chromium .gn file: angle_dotfile_settings.exec_script_whitelist -> angle_dotfile_settings.exec_script_allowlist"
            #     )
            #     patched_content = content.replace(
            #         "angle_dotfile_settings.exec_script_whitelist",
            #         "angle_dotfile_settings.exec_script_allowlist"
            #     )
            #     gn_file.write_text(patched_content)
            #     logger.info("Successfully patched Chromium .gn file for compatibility")

        except Exception as e:
            logger.warning(f"Failed to apply Chromium exec_script patch: {e}")
            # Non-fatal - let the build fail with proper error message if needed

    @staticmethod
    def get_object_name(file_name: str) -> str:
        """
        Get the object file name for a given source file in Chromium build system.
        """
        file_path = Path(file_name)
        stem_name = file_path.stem

        # Chromium uses ninja build system, object files are typically in obj/ subdirectory
        # The structure is usually obj/path/to/source/filename.o
        
        # Convert source path to object path
        # Remove common prefixes and convert to object directory structure
        if file_path.parts:
            # Handle different source directories
            if file_path.parts[0] in ["src", "chrome", "content", "components", "ui"]:
                # Most Chromium sources follow this pattern
                relative_path = "/".join(file_path.parts)
            else:
                relative_path = str(file_path)
            
            # Convert to object file path
            obj_path = f"obj/{relative_path}"
            obj_path = Path(obj_path).with_suffix(".o")
            return str(obj_path)
        else:
            # Fallback for simple filenames
            return f"obj/{stem_name}.o"

    @staticmethod
    def get_objects_from_patch(patch: str) -> List[str]:
        """
        Get the objects to analyze from a patch.
        """
        # Find `--- a/` lines in the patch
        pattern = r"^--- a/(.*)$"
        matches = re.findall(pattern, patch, re.MULTILINE)
        # Filter for C/C++ files (Chromium is primarily C++)
        matches = [
            match for match in matches 
            if match.endswith((".cc", ".cpp", ".c", ".mm", ".m"))
        ]
        # Convert to object file names
        matches = [Chromium.get_object_name(match) for match in matches]
        return matches

    @staticmethod
    def get_source_files_from_patch(patch: str) -> List[str]:
        """
        Get the source files to analyze from a patch.
        """
        # Find `--- a/` lines in the patch
        pattern = r"^--- a/(.*)$"
        matches = re.findall(pattern, patch, re.MULTILINE)
        # Filter for C/C++ files (Chromium is primarily C++)
        matches = [
            match for match in matches 
            if match.endswith((".cc", ".cpp", ".c", ".mm", ".m", ".h"))
        ]
        return matches

    def get_commit_parent(self, commit_id: str) -> str:
        """
        Get the parent commit of a given commit.
        
        Args:
            commit_id: The commit ID
            
        Returns:
            str: Parent commit ID
        """
        try:
            result = sp.run(
                ["git", "rev-parse", f"{commit_id}^"],
                cwd=self.repo.working_dir,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                logger.error(f"Failed to get parent for commit {commit_id}: {result.stderr}")
                return commit_id + "^"  # Fallback to git syntax
                
        except Exception as e:
            logger.error(f"Error getting parent for commit {commit_id}: {e}")
            return commit_id + "^"  # Fallback to git syntax

    def get_chromium_targets(self) -> List[str]:
        """
        Get common Chromium build targets for analysis.
        
        Returns:
            List of common Chromium targets that can be built independently.
        """
        common_targets = [
            "//base:base",
            "//net:net", 
            "//content/browser:browser",
            "//content/renderer:renderer",
            "//chrome/browser:browser",
            "//chrome/renderer:renderer",
            "//ui/base:base",
            "//components/policy:policy",
            "//components/variations:variations",
            "//gpu/command_buffer:command_buffer",
            "//media:media",
            "//third_party/blink/renderer/core:core",
            "//third_party/blink/renderer/platform:platform",
        ]
        return common_targets

    def build_chromium_target(self, target: str, **kwargs) -> bool:
        """
        Build a specific Chromium target using ninja.
        
        Args:
            target: The target to build (e.g., "//base:base")
            **kwargs: Additional build arguments
            
        Returns:
            bool: True if build succeeded, False otherwise
        """
        arch = kwargs.get("arch", "x64")
        build_config = kwargs.get("build_config", "release")
        build_dir = f"out/{arch}_{build_config}"
        jobs = kwargs.get("jobs", 32)
        timeout = kwargs.get("timeout", 1800)
        
        # Find ninja executable
        ninja_exe = which("ninja")
        if not ninja_exe:
            candidate = Path(self.repo.working_dir) / "third_party" / "ninja" / "ninja"
            if candidate.exists():
                ninja_exe = str(candidate)
        
        if not ninja_exe:
            logger.error("Ninja executable not found")
            return False
            
        # Build the target
        logger.info(f"Building Chromium target: {target} with {jobs} jobs")
        
        try:
            res = sp.run(
                [ninja_exe, "-C", build_dir, f"-j{jobs}", target],
                cwd=self.repo.working_dir,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if res.returncode == 0:
                logger.info(f"Successfully built target: {target}")
                return True
            else:
                logger.error(f"Failed to build target {target}: {res.stderr}")
                return False
                
        except sp.TimeoutExpired:
            logger.error(f"Build timeout for target {target}")
            return False
        except Exception as e:
            logger.error(f"Build error for target {target}: {e}")
            return False