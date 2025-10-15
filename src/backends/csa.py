import glob
import json
import os
import random
import re
import shlex
import shutil
import subprocess as sp
import threading
import json
import os
import random
import re
import shlex
import shutil
import subprocess as sp
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from html2text import html2text
from loguru import logger

from backends.factory import AnalysisBackendFactory
from checker_data import ReportData
from targets.factory import TargetFactory
from targets.linux import Linux
from tools import monitor_build_output, remove_text_section


class ClangBackend(AnalysisBackendFactory):
    """
    Concrete implementation of the Backend class for CSA.
    """

    _default_args = [
        ("-disable-checker", "core"),
        ("-disable-checker", "cplusplus"),
        ("-disable-checker", "deadcode"),
        ("-disable-checker", "unix"),
        ("-disable-checker", "nullability"),
        ("-disable-checker", "security"),
        ("-maxloop", 4),
        ("-o", "tmp/SAGenTestCSAResult"),
    ]

    _v8_args = [
        ("-disable-checker", "core"),
        ("-disable-checker", "cplusplus"),
        ("-disable-checker", "deadcode"),
        ("-disable-checker", "unix"),
        ("-disable-checker", "nullability"),
        ("-disable-checker", "security"),
        ("-maxloop", 8),
        ("-o", "tmp/SAGenTestCSAResult"),
    ]

    _chromium_args = [
        ("-disable-checker", "core"),
        ("-disable-checker", "cplusplus"),
        ("-disable-checker", "deadcode"),
        ("-disable-checker", "unix"),
        ("-disable-checker", "nullability"),
        ("-disable-checker", "security"),
        ("-maxloop", 8),
        ("-o", "tmp/SAGenTestCSAResult"),
    ]

    def build_checker(
        self,
        checker_code: str,
        log_dir: Path,
        checker_name="SAGenTest",
        attempt=1,
        jobs=8,
        timeout=300,
    ):
        """
        Build the checker in the CSA backend.

        Args:
            checker_code (str): The checker code to build.
        """
        # Write the checker code to a file
        checker_file_path = (
            self.backend_path
            / "clang/lib/Analysis/plugins"
            / f"{checker_name}Handling"
            / f"{checker_name}Checker.cpp"
        )
        build_dir = self.backend_path / "build"
        if not checker_file_path.parent.exists():
            raise FileNotFoundError(
                f"Directory {checker_file_path.parent} does not exist."
            )
        if not build_dir.exists():
            raise FileNotFoundError(f"Directory {build_dir} does not exist.")
        log_dir.mkdir(parents=True, exist_ok=True)

        checker_file_path.write_text(checker_code)
        # Build the checker using the provided build command
        try:
            process = sp.run(
                ["make", f"-j{jobs}", f"{checker_name}Plugin"],
                cwd=build_dir,
                capture_output=True,
                timeout=timeout,
            )
            (log_dir / f"build_steout_{attempt}.log").write_bytes(process.stdout)
            (log_dir / f"build_stderr_{attempt}.log").write_bytes(process.stderr)
            return process.returncode, process.stderr.decode()
        except Exception as e:
            logger.error(f"Compilation command failed: {e}")
            # Write error to stderr log if possible
            try:
                (log_dir / f"build_error_{attempt}.log").write_text(
                    f"Error running subprocess: {e}\n"
                )
            except Exception as log_e:
                logger.error(f"Failed to write error to log file: {log_e}")
            return -1, f"Error running subprocess: {e}"

    def build_checker_group(
        self,
        checker_data_list: List,
        log_dir: Path,
        attempt=1,
        jobs=8,
        timeout=300,
    ):
        """
        Build multiple checkers simultaneously for group scanning.

        Args:
            checker_data_list: List of CheckerData objects with unique checker names
            log_dir: Directory to store build logs
            attempt: Build attempt number
            jobs: Number of parallel jobs
            timeout: Build timeout in seconds

        Returns:
            Tuple of (return_code, stderr_output, built_checker_names)
        """
        from checker_data import CheckerData

        log_dir.mkdir(parents=True, exist_ok=True)
        built_checker_names = []
        build_errors = []

        logger.info(f"Building group of {len(checker_data_list)} checkers...")

        # First, create plugin directories for all unique checker names
        self._create_group_plugin_directories(checker_data_list)

        # Build each checker individually
        for i, checker_data in enumerate(checker_data_list):
            if not isinstance(checker_data, CheckerData):
                logger.error(f"Invalid checker data at index {i}")
                continue

            # Generate unique checker name from checker_id
            checker_name = self._generate_unique_checker_name(checker_data.checker_id)

            # Replace SAGenTestChecker with the unique name in the code
            modified_code = self._replace_checker_name_in_code(
                checker_data.repaired_checker_code, checker_name
            )

            logger.info(
                f"Building checker {checker_name} ({i+1}/{len(checker_data_list)})"
            )

            try:
                return_code, stderr = self.build_checker(
                    checker_code=modified_code,
                    log_dir=log_dir / f"checker_{checker_name}",
                    checker_name=checker_name,
                    attempt=attempt,
                    jobs=jobs,
                    timeout=timeout,
                )

                if return_code == 0:
                    built_checker_names.append(checker_name)
                    logger.info(f"✓ Successfully built checker {checker_name}")
                else:
                    logger.error(f"✗ Failed to build checker {checker_name}")
                    build_errors.append(f"{checker_name}: {stderr}")

            except Exception as e:
                logger.error(f"Error building checker {checker_name}: {e}")
                build_errors.append(f"{checker_name}: {str(e)}")

        # Overall result
        if built_checker_names:
            logger.info(
                f"Group build completed: {len(built_checker_names)}/{len(checker_data_list)} checkers built successfully"
            )
            return 0, "\n".join(build_errors), built_checker_names
        else:
            logger.error("Group build failed: no checkers built successfully")
            return -1, "\n".join(build_errors), []

    def _generate_unique_checker_name(self, checker_id: str) -> str:
        """Generate a unique checker name from checker_id."""
        # Remove the KN- prefix and clean up the name
        name = checker_id.replace("KN-", "").replace("-", "_")
        # Ensure it's a valid C++ identifier
        name = re.sub(r"[^a-zA-Z0-9_]", "_", name)
        # Ensure it starts with a letter
        if name and not name[0].isalpha():
            name = f"Checker_{name}"
        # Limit length
        if len(name) > 30:
            name = name[:30]

        return name or "SAGenTest"

    def _replace_checker_name_in_code(self, checker_code: str, new_name: str) -> str:
        """Replace SAGenTestChecker with the new unique name in the checker code."""
        # Replace class name and all references
        modified_code = checker_code.replace("SAGenTestChecker", f"{new_name}Checker")

        # Also replace the checker registration
        modified_code = modified_code.replace(
            "custom.SAGenTestChecker", f"custom.{new_name}Checker"
        )

        return modified_code

    def _create_group_plugin_directories(self, checker_data_list: List):
        """Create plugin directories for all checkers in the group."""
        plugin_dir = self.backend_path / "clang/lib/Analysis/plugins"
        if not plugin_dir.exists():
            logger.error(f"Plugin directory {plugin_dir} does not exist")
            return

        logger.info(
            f"Creating plugin directories for {len(checker_data_list)} checkers..."
        )

        # Copy create_plugin.py to plugins directory (following setup_llvm.py pattern)
        llvm_utils_script = (
            Path(__file__).parent.parent / "llvm_utils" / "create_plugin.py"
        )
        create_plugin_script = plugin_dir / "create_plugin.py"

        if llvm_utils_script.exists():
            logger.info("Copying create_plugin.py to plugins directory...")
            # Use cp command like setup_llvm.py does
            sp.run(["cp", str(llvm_utils_script), str(plugin_dir) + "/"])
        else:
            logger.warning(
                "create_plugin.py not found in llvm_utils, will use manual creation"
            )

        for checker_data in checker_data_list:
            checker_name = self._generate_unique_checker_name(checker_data.checker_id)

            # Check if plugin directory already exists
            plugin_handling_dir = plugin_dir / f"{checker_name}Handling"
            # if plugin_handling_dir.exists():
            #     logger.debug(f"Plugin directory {checker_name}Handling already exists")
            #     continue

            if create_plugin_script.exists():
                try:
                    # Use the create_plugin.py script exactly like setup_llvm.py does
                    logger.info(f"Creating plugin directory for {checker_name}")
                    result = sp.run(
                        ["python3", "create_plugin.py", checker_name],
                        cwd=plugin_dir.absolute(),  # Use absolute path like setup_llvm.py
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )

                    if result.returncode == 0:
                        logger.debug(
                            f"✓ Successfully created plugin directory for {checker_name}"
                        )
                        continue
                    else:
                        logger.warning(
                            f"create_plugin.py failed for {checker_name}: {result.stderr}"
                        )

                except Exception as e:
                    logger.warning(
                        f"create_plugin.py script failed for {checker_name}: {e}"
                    )

            # Fallback to manual creation
            logger.info(f"Using manual creation for {checker_name}")
            self._create_plugin_directory_manually(checker_name, plugin_dir)

        logger.info("Plugin directory creation completed")

        # Regenerate CMake configuration to recognize new plugins
        self._regenerate_cmake_build_system()

    def _create_plugin_directory_manually(self, checker_name: str, plugin_dir: Path):
        """Manually create plugin directory structure if create_plugin.py fails."""
        try:
            plugin_handling_dir = plugin_dir / f"{checker_name}Handling"
            plugin_handling_dir.mkdir(exist_ok=True)

            # Create CMakeLists.txt matching create_plugin.py format
            lib_name = f"{checker_name}Plugin"
            cpp_file_name = f"{checker_name}Checker.cpp"
            exports_file_name = f"{checker_name}Checker.exports"

            cmake_content = f"""
set(LLVM_LINK_COMPONENTS
  Support
  )

set(LLVM_EXPORTED_SYMBOL_FILE ${{CMAKE_CURRENT_SOURCE_DIR}}/{exports_file_name})
add_llvm_library({lib_name} MODULE BUILDTREE_ONLY {cpp_file_name})

clang_target_link_libraries({lib_name} PRIVATE
  clangAnalysis
  clangAST
  clangStaticAnalyzerCore
  clangStaticAnalyzerFrontend
  )
"""
            cmake_file = plugin_handling_dir / "CMakeLists.txt"
            cmake_file.write_text(cmake_content.strip())

            # Create .exports file matching create_plugin.py format
            exports_content = """clang_registerCheckers
clang_analyzerAPIVersionString"""
            exports_file = plugin_handling_dir / exports_file_name
            exports_file.write_text(exports_content)

            # Create minimal checker .cpp file
            checker_class_name = f"{checker_name}Checker"
            cpp_content = f"""#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"

using namespace clang;
using namespace ento;

namespace {{
/*The checker callbacks are to be decided.*/
class {checker_class_name} : public Checker<check::PreCall> {{
  mutable std::unique_ptr<BugType> BT;

public:
  // Main Check Logic
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const; // Tmp
}};
}} // end anonymous namespace


extern "C" void clang_registerCheckers(CheckerRegistry &registry) {{
  registry.addChecker<{checker_class_name}>(
      "custom.{checker_class_name}",
      "/*Description to be filled*/",
      "");
}}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;"""
            cpp_file = plugin_handling_dir / cpp_file_name
            cpp_file.write_text(cpp_content)

            # Update main CMakeLists.txt to include this plugin
            main_cmake = plugin_dir / "CMakeLists.txt"
            if main_cmake.exists():
                main_content = main_cmake.read_text()
                add_line = f"add_subdirectory({checker_name}Handling)"

                if add_line not in main_content:
                    # Add before the last endif()
                    lines = main_content.split("\n")
                    for i in range(len(lines) - 1, -1, -1):
                        if "endif()" in lines[i]:
                            lines.insert(i, f"  {add_line}")
                            break

                    main_cmake.write_text("\n".join(lines))
                    logger.info(f"✓ Updated main CMakeLists.txt for {checker_name}")

            logger.info(f"✓ Manually created plugin directory for {checker_name}")

        except Exception as e:
            logger.error(
                f"✗ Failed to manually create plugin directory for {checker_name}: {e}"
            )

    def _regenerate_cmake_build_system(self):
        """Regenerate CMake build system to recognize new plugins."""
        try:
            build_dir = self.backend_path / "build"
            if not build_dir.exists():
                logger.error(f"Build directory {build_dir} does not exist")
                return False

            logger.info("Regenerating CMake build system for new plugins...")

            # Run cmake to regenerate build files (following setup_llvm.py pattern)
            cmake_cmd = 'cmake -DLLVM_ENABLE_PROJECTS="clang;lld" -DLLVM_TARGETS_TO_BUILD=X86 -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles" ../llvm'

            result = sp.run(
                cmake_cmd,
                shell=True,
                cwd=build_dir,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )

            if result.returncode == 0:
                logger.info("✓ CMake regeneration completed successfully")
                return True
            else:
                logger.error(f"✗ CMake regeneration failed: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"✗ Failed to regenerate CMake build system: {e}")
            return False

    def validate_checker(
        self,
        checker_code,
        commit_id,
        patch,
        target: TargetFactory,
        skip_build_checker=False,
    ) -> Tuple[int, int]:

        if target._target_type == "linux":
            return self._validate_checker_linux(
                checker_code, commit_id, patch, target, skip_build_checker
            )
        elif target._target_type == "v8":
            return self._validate_checker_v8(
                checker_code, commit_id, patch, target, skip_build_checker
            )
        elif target._target_type == "chromium":
            return self._validate_checker_chromium(
                checker_code, commit_id, patch, target, skip_build_checker
            )
        else:
            raise NotImplementedError(
                f"Validation for target type {target._target_type} is not implemented."
            )

    def run_checker(
        self,
        checker_code,
        commit_id,
        target,
        object_to_analyze=None,
        jobs=32,
        output_dir="tmp",
        skip_build_checker=False,
        skip_checkout=False,
        **kwargs,
    ) -> int:
        """
        Run the checker against a commit and patch.
        This will dispatch the analysis to the appropriate method based on the target type.

        Args:
            commit_id (str): The commit ID to run the checker against.
            object_to_analyze (str): The object file to analyze.
            target (TargetFactory): The target to be tested.
            jobs (int): Number of jobs to run in parallel.
            output_dir (str): Directory to save the output.

        Returns:
            int: Number of bugs found.
        """

        if target._target_type == "linux":
            return self._run_checker_linux(
                checker_code,
                commit_id,
                target,
                object_to_analyze=object_to_analyze,
                jobs=jobs,
                output_dir=output_dir,
                skip_build_checker=skip_build_checker,
                skip_checkout=skip_checkout,
                **kwargs,
            )
        elif target._target_type == "v8":
            return self._run_checker_v8(
                checker_code,
                commit_id,
                target,
                object_to_analyze=object_to_analyze,
                jobs=jobs,
                output_dir=output_dir,
                skip_build_checker=skip_build_checker,
                skip_checkout=skip_checkout,
                **kwargs,
            )
        elif target._target_type == "chromium":
            return self._run_checker_chromium(
                checker_code,
                commit_id,
                target,
                object_to_analyze=object_to_analyze,
                jobs=jobs,
                output_dir=output_dir,
                skip_build_checker=skip_build_checker,
                skip_checkout=skip_checkout,
                **kwargs,
            )
        else:
            raise NotImplementedError(
                f"Running checker for target type {target._target_type} is not implemented."
            )

    """Self defined functions"""

    def _validate_checker_linux(
        self,
        checker_code: str,
        commit_id: str,
        patch: str,
        target: Linux,
        skip_build_checker=False,
    ):
        """
        Validate the checker against a commit and patch.
        We use x86 architecture for Linux by default.

        Args:
            commit_id (str): The commit ID to validate against.
            patch (str): The patch to apply.
            target (str): The target file or directory.
        """

        TP, TN = 0, 0
        if not skip_build_checker:
            self.build_checker(
                checker_code,
                Path("tmp"),
                attempt=1,
            )

        comd_prefix = self._generate_command()
        olddefcmd = comd_prefix + "make LLVM=1 ARCH=x86 olddefconfig"
        target.checkout_commit(commit_id, is_before=True, olddefcmd=olddefcmd)

        # Get the modified objects from the patch
        num_bug_obj = {}
        objects = target.get_objects_from_patch(patch)
        for obj in objects:
            comd = comd_prefix + f"make LLVM=1 ARCH=x86 {obj} -j8"
            logger.info("Running: " + comd)
            try:
                res = sp.run(
                    comd,
                    shell=True,
                    text=True,
                    cwd=target.repo.working_dir,
                    capture_output=True,
                    timeout=300,
                )
                output = res.stdout
            except sp.TimeoutExpired:
                raise Exception(f"Compilation Timeout: {comd}")

            logger.info(f"Buggy: {obj} {res.returncode}")
            if (
                res.returncode == 0
                and "Please consider submitting a bug report" in output
            ):
                logger.info("Buggy: Error in scan!")
                logger.debug(output)
                return -2, -2
            elif res.returncode == 0 and "No bugs found" not in output:
                # scan-build: 0 bugs found.
                num_bugs = self.get_num_bugs(output)
                num_bug_obj[obj] = num_bugs
                TP += 1
                logger.info(f"Buggy: {num_bugs} bugs found")
            elif res.returncode == 0:
                logger.info("Buggy: No bugs found!")
            elif res.returncode != 0:
                logger.info("Buggy: Error in build!")
                return -1, -1

        olddefcmd = comd_prefix + "make LLVM=1 ARCH=x86 olddefconfig"
        target.checkout_commit(commit_id, is_before=False, olddefcmd=olddefcmd)
        for obj in objects:
            comd = comd_prefix + f"make LLVM=1 ARCH=x86 {obj} -j8 2>&1"
            try:
                res = sp.run(
                    comd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    cwd=target.repo.working_dir,
                    timeout=300,
                )
                output = res.stdout
            except sp.TimeoutExpired:
                raise Exception(f"Compilation Timeout: {comd}")

            logger.info(f"Non-buggy: {obj} {res.returncode}")

            if res.returncode == 0 and "No bugs found" in output:
                TN += 1
                logger.info("Non-buggy: No bugs found!")
            elif res.returncode == 0:
                num_bugs = self.get_num_bugs(output)
                if num_bugs < num_bug_obj.get(obj, 0) and num_bugs < 5:
                    TN += 1
                elif num_bugs > num_bug_obj.get(obj, 0):
                    TN -= 1
                logger.info(f"Non-buggy: {num_bugs} bugs found")
            elif res.returncode != 0:
                logger.info("Non-buggy: Error in build!")
                return -1, -1
        return TP, TN

    def _run_checker_linux(
        self,
        checker_code: str,
        commit_id: str,
        target: Linux,
        object_to_analyze: str = None,
        jobs: int = 32,
        output_dir: str = "tmp",
        skip_build_checker: bool = False,
        skip_checkout: bool = False,
        **kwargs,
    ):
        """
        Run the checker against a commit and patch.

        Args:
            commit_id (str): The commit ID to run the checker against.
            object_to_analyze (str): The object file to analyze.
            target (Linux): The target to be tested.
            object_to_analyze (str): The object file to analyze.
            jobs (int): Number of jobs to run in parallel.
            output_dir (str): Directory to save the output.

        Returns:
            int: Number of bugs found.
        """

        output_dir = Path(output_dir)
        arch = kwargs.get("arch", "x86")
        timeout = kwargs.get("timeout", 1800)

        if not skip_build_checker:
            build_res, _ = self.build_checker(checker_code, Path("tmp"), attempt=1)
            if build_res != 0:
                logger.error("Build failed, skipping analysis.")
                raise Exception("Build failed, skipping analysis.")

        comd_prefix = self._generate_command(no_output=True)
        comd_prefix += "-o " + output_dir.absolute().as_posix()

        # Note: kernel cleaning is handled by target.checkout_commit() which runs 'make clean'
        olddefcmd = comd_prefix + f" make LLVM=1 ARCH={arch} olddefconfig"
        if not skip_checkout:
            target.checkout_commit(commit_id, olddefmd=olddefcmd)

        # Process the command based on the architecture
        if arch == "arm64":
            comd = (
                comd_prefix
                + f" make LLVM=1 ARCH={arch} CROSS_COMPILE=aarch64-linux-gnu- -j{jobs}"
            )
        elif arch == "riscv":
            comd = (
                comd_prefix
                + f" make LLVM=1 ARCH={arch} CROSS_COMPILE=riscv64-unknown-linux-gnu- -j{jobs}"
            )
        else:
            comd = comd_prefix + f" make LLVM=1 ARCH={arch} -j{jobs}"

        # Object to analyze
        if object_to_analyze:
            comd += f" {object_to_analyze}"
        logger.info("Running: " + comd)

        scan_process = sp.Popen(
            comd,
            shell=True,
            cwd=target.repo.working_dir,
            stdout=sp.PIPE,
            stderr=sp.PIPE,
        )
        output, completed = monitor_build_output(
            scan_process, warning_limit=300, timeout=timeout
        )

        num_bugs = 0
        if completed == "Complete":
            return_code = scan_process.wait()
            if return_code != 0:
                logger.error("Fail to build the kernel with checker!")
                logger.error("Return code: " + str(return_code))
                (output_dir / "scan_error.log").write_text(output)
                return -999
            if "No bugs found" not in output:
                num_bugs = self.get_num_bugs(output)
                logger.success(f"{num_bugs} bugs found!")
        elif completed == "Timeout":
            num_bugs = -1
            logger.warning("Timeout!")
        else:
            num_bugs = -10
            logger.warning("Too many bugs found!")

        return num_bugs

    def _get_compile_entries_for_v8_sources(
        self, compile_commands_path: Path, source_files: List[str]
    ) -> dict:
        """
        Extract compile entries for specific source files from compile_commands.json.

        Args:
            compile_commands_path: Path to compile_commands.json
            source_files: List of source files to find entries for

        Returns:
            dict: Mapping of source file to compile command entry
        """
        compile_entries = {}

        if not compile_commands_path.exists():
            logger.error(f"compile_commands.json not found at {compile_commands_path}")
            return compile_entries

        try:
            with open(compile_commands_path, "r") as f:
                commands = json.load(f)

            # Find compile entries for each source file
            for source_file in source_files:
                normalized_source = f"../../{source_file}"
                for cmd in commands:
                    if cmd.get("file") == normalized_source:
                        compile_entries[source_file] = cmd
                        break

        except Exception as e:
            logger.error(f"Failed to read compile_commands.json: {e}")

        return compile_entries

    def _validate_checker_v8(
        self,
        checker_code: str,
        commit_id: str,
        patch: str,
        target,
        skip_build_checker=False,
    ):
        """
        Validate the checker against a V8 commit and patch.
        Analyzes files in both buggy and fixed versions to compute TP/TN.
        """
        # Remove depot_tools from PATH to prevent gclient sync from changing V8 dependencies
        original_path = os.environ.get("PATH", "")
        filtered_path = ":".join(
            [p for p in original_path.split(":") if "depot_tools" not in p]
        )
        os.environ["PATH"] = filtered_path

        logger.info(f"V8 validation: removed depot_tools from PATH")

        TP, TN = 0, 0
        if not skip_build_checker:
            self.build_checker(
                checker_code,
                Path("tmp"),
                attempt=1,
            )

        # Get source files from patch
        source_files = target.get_source_files_from_patch(patch)
        logger.info(f"Source files to analyze from patch: {source_files}")

        # [DEBUG] Clear any existing debug log and create new one
        debug_log = "/tmp/v8_checker_debug.log"
        if os.path.exists(debug_log):
            os.remove(debug_log)

        # Write initial debug info
        with open(debug_log, "w") as f:
            f.write(f"=== V8 Checker Validation Started ===\n")
            f.write(f"Commit ID: {commit_id}\n")
            f.write(f"Source files: {source_files}\n")
            f.write(f"Skip build: {skip_build_checker}\n")
            f.write("=" * 50 + "\n")

        num_bug_files = {}

        # Create output directories for validation (consistent with Linux structure)
        # Use tmp directory for validation with timestamped subdirectories
        validation_base_dir = Path("tmp") / "v8_validation" / commit_id

        # Create timestamped directories for both buggy and fixed versions
        buggy_base_dir = validation_base_dir / "buggy"
        fixed_base_dir = validation_base_dir / "fixed"
        buggy_base_dir.mkdir(parents=True, exist_ok=True)
        fixed_base_dir.mkdir(parents=True, exist_ok=True)

        buggy_output_dir = self._create_timestamped_output_dir(buggy_base_dir)
        fixed_output_dir = self._create_timestamped_output_dir(fixed_base_dir)

        # Checkout buggy version
        llvm_build_dir = self.backend_path / "build"
        target.checkout_commit(
            commit_id,
            is_before=True,
            arch="x64",
            build_config="release",
            llvm_path=llvm_build_dir,
        )

        # Build the specific object files first
        env = os.environ.copy()
        env["PATH"] = f"{llvm_build_dir}/bin:" + env.get("PATH", "")

        # Get compile_commands.json to find exact entries for source files
        compile_commands_path = (
            Path(target.repo.working_dir) / "out/x64.release/compile_commands.json"
        )

        # Use helper function to get compile entries
        compile_entries = self._get_compile_entries_for_v8_sources(
            compile_commands_path, source_files
        )

        # Build and analyze buggy version
        for source_file in source_files:
            if source_file not in compile_entries:
                logger.warning(f"No compile command found for {source_file}")
                continue

            # Build the object file for this source
            obj_file = self._get_object_file_from_source(source_file, target)
            if obj_file:
                logger.info(f"Building object file: {obj_file}")
                build_result = sp.run(
                    ["ninja", "-C", "out/x64.release", obj_file],
                    cwd=target.repo.working_dir,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if build_result.returncode != 0:
                    logger.error(
                        f"Failed to build {obj_file}: {build_result.stderr[:500]}"
                    )
                    continue

            # Create file-specific output directory (validation always needs output)
            safe_filename = source_file.replace("/", "_").replace(".", "_")
            file_output_dir = buggy_output_dir / safe_filename
            file_output_dir.mkdir(parents=True, exist_ok=True)

            # Analyze using helper function
            success, num_bugs, error_msg = self._analyze_v8_source_file(
                compile_entries[source_file],
                file_output_dir,
                target=target,
                timeout=900,
            )

            if not success:
                logger.warning(f"Failed to analyze {source_file}: {error_msg}")
                continue

            # Append debug info about the analysis
            with open(debug_log, "a") as f:
                f.write(f"\n=== BUGGY VERSION - {source_file} ===\n")
                f.write(f"Analysis success: {success}\n")
                f.write(f"Number of bugs found: {num_bugs}\n")
                if error_msg:
                    f.write(f"Error: {error_msg}\n")
                f.write(f"Output directory: {file_output_dir}\n")

            num_bug_files[source_file] = num_bugs
            if num_bugs > 0:
                TP += 1
                logger.info(f"Buggy: {num_bugs} bugs found for file {source_file}")
            else:
                logger.info(f"Buggy: No bugs found for file {source_file}")

        # Checkout fixed version
        target.checkout_commit(
            commit_id,
            is_before=False,
            arch="x64",
            build_config="release",
            llvm_path=llvm_build_dir,
        )

        # Re-read compile_commands.json for fixed version (may have changed after checkout)
        compile_entries = self._get_compile_entries_for_v8_sources(
            compile_commands_path, source_files
        )

        # Build and analyze fixed version
        for source_file in source_files:
            if source_file not in compile_entries:
                logger.warning(f"No compile command found for {source_file}")
                continue

            # Build the object file for this source
            obj_file = self._get_object_file_from_source(source_file, target)
            if obj_file:
                logger.info(f"Building object file: {obj_file}")
                build_result = sp.run(
                    ["ninja", "-C", "out/x64.release", obj_file],
                    cwd=target.repo.working_dir,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if build_result.returncode != 0:
                    logger.error(
                        f"Failed to build {obj_file}: {build_result.stderr[:500]}"
                    )
                    continue

            # Create file-specific output directory (validation always needs output)
            safe_filename = source_file.replace("/", "_").replace(".", "_")
            file_output_dir = fixed_output_dir / safe_filename
            file_output_dir.mkdir(parents=True, exist_ok=True)

            # Analyze using helper function
            success, num_bugs, error_msg = self._analyze_v8_source_file(
                compile_entries[source_file],
                file_output_dir,
                target=target,
                timeout=900,
            )

            if not success:
                logger.warning(f"Failed to analyze fixed {source_file}: {error_msg}")
                continue

            logger.info(f"Fixed: {source_file} analysis complete")

            # Append debug info about the analysis
            with open(debug_log, "a") as f:
                f.write(f"\n=== FIXED VERSION - {source_file} ===\n")
                f.write(f"Analysis success: {success}\n")
                f.write(f"Number of bugs found: {num_bugs}\n")
                if error_msg:
                    f.write(f"Error: {error_msg}\n")
                f.write(f"Output directory: {file_output_dir}\n")

            if num_bugs == 0 or num_bugs < num_bug_files.get(source_file, 0):
                TN += 1
                logger.info(
                    f"Fixed: Fewer bugs ({num_bugs}) found for file {source_file}"
                )
            else:
                logger.info(
                    f"Fixed: Same/more bugs ({num_bugs}) found for file {source_file}"
                )

        logger.info(f"V8 Validation Result: TP={TP}, TN={TN}")

        # Create softlinks for both buggy and fixed directories
        self._create_v8_report_softlinks(buggy_output_dir, buggy_base_dir)
        self._create_v8_report_softlinks(fixed_output_dir, fixed_base_dir)

        # Write final summary to debug log
        with open(debug_log, "a") as f:
            f.write("\n" + "=" * 50 + "\n")
            f.write("=== VALIDATION SUMMARY ===\n")
            f.write(f"True Positives (TP): {TP}\n")
            f.write(f"True Negatives (TN): {TN}\n")
            f.write(f"Bug counts per file:\n")
            for src, count in num_bug_files.items():
                f.write(f"  {src}: {count} bugs\n")
            f.write(f"Expected: TP=1, TN=1\n")
            f.write(f"Success: {TP == 1 and TN == 1}\n")
            f.write("=" * 50 + "\n")

        return TP, TN
    
    def _create_v8_report_softlinks(
        self, timestamped_output_dir: Path, base_output_dir: Path
    ) -> None:
        """
        Create softlinks to make V8 report structure compatible with refinement process.
        """
        try:
            if timestamped_output_dir.exists():
                for subdir in timestamped_output_dir.iterdir():
                    if subdir.is_dir():
                        link_target = base_output_dir / subdir.name
                        if not link_target.exists():
                            link_target.symlink_to(subdir, target_is_directory=True)
                            logger.debug(f"Created softlink: {link_target} -> {subdir}")
        except Exception as e:
            logger.warning(f"Failed to create V8 report softlinks: {e}")

    def _get_object_file_from_source(self, source_file, target):
        """Convert source file path to corresponding object file path using compile_commands.json."""
        # Try to find the actual object file from compile_commands.json
        compile_commands_path = (
            Path(target.repo.working_dir) / "out/x64.release/compile_commands.json"
        )
        if compile_commands_path.exists():
            try:
                with open(compile_commands_path) as f:
                    commands = json.load(f)

                # Normalize the source file path (V8 uses ../../ prefix)
                normalized_source = f"../../{source_file}"

                # Find the command for this source file
                for cmd in commands:
                    if cmd.get("file") == normalized_source:
                        # Parse the command to find the -o flag
                        parts = shlex.split(cmd["command"])
                        for i, part in enumerate(parts):
                            if part == "-o" and i + 1 < len(parts):
                                logger.info(
                                    f"Found object file mapping: {source_file} -> {parts[i+1]}"
                                )
                                return parts[i + 1]

                logger.warning(
                    f"No compile command found for {source_file}, using fallback"
                )
            except Exception as e:
                logger.warning(
                    f"Error reading compile_commands.json: {e}, using fallback"
                )

        # Fallback: Use known V8 build patterns
        source_path = Path(source_file)

        # Special case for test/fuzzer/wasm files
        if source_path.parts[0] == "test" and len(source_path.parts) >= 4:
            if source_path.parts[1] == "fuzzer" and source_path.parts[2] == "wasm":
                filename = source_path.stem
                return f"obj/wasm_fuzzer_common/{filename}.o"

        # For src/ files, most go to v8_base_without_compiler
        if source_path.parts[0] == "src":
            filename = source_path.stem
            # Runtime, heap, builtins, etc. typically go to v8_base_without_compiler
            return f"obj/v8_base_without_compiler/{filename}.o"

        # Default fallback - just use the stem name
        filename = source_path.stem
        return f"obj/{filename}.o"

    def _generate_v8_analyzer_command(
        self, source_file, obj_file, target, output_dir: Path
    ):
        """
        Generate an analyzer command for V8 source files using compile_commands.json.
        Uses the exact compilation flags from the build system.
        """
        llvm_build_dir = self.backend_path / "build"
        plugin_path = f"{llvm_build_dir}/lib/SAGenTestPlugin.so"

        # Check for compile_commands.json and extract compilation command
        compile_commands_path = os.path.join(
            target.repo.working_dir, "out/x64.release/compile_commands.json"
        )
        compile_cmd = ""

        if os.path.exists(compile_commands_path):
            try:
                with open(compile_commands_path, "r") as f:
                    compile_commands = json.load(f)

                # Find the compilation command for this source file
                for entry in compile_commands:
                    if source_file in entry.get("file", ""):
                        compile_cmd = entry.get("command", "")
                        break

                if compile_cmd:
                    cmd_parts = shlex.split(compile_cmd)

                    # Create output directory
                    output_dir.mkdir(parents=True, exist_ok=True)

                    # Build command using clang++ driver with --analyze (the WORKING approach!)
                    def run_build_and_analysis():
                        # Step 1: Build the object file
                        env = os.environ.copy()
                        env["PATH"] = f"{llvm_build_dir}/bin:" + env.get("PATH", "")

                        logger.info(
                            f"Running ninja build: {['ninja', '-C', 'out/x64.release', obj_file]}"
                        )
                        build_result = sp.run(
                            ["ninja", "-C", "out/x64.release", obj_file],
                            cwd=target.repo.working_dir,
                            env=env,
                            capture_output=True,
                            text=True,
                        )

                        if build_result.returncode != 0:
                            logger.error(f"Ninja build failed: {build_result.stderr}")
                            return build_result

                        # Step 2: Use clang++ driver with --analyze and EXACT same flags as compilation
                        analyzer_cmd = [f"{llvm_build_dir}/bin/clang++", "--analyze"]

                        # Add plugin and checker flags
                        analyzer_cmd.extend(
                            [
                                "-Xanalyzer",
                                "-load",
                                "-Xanalyzer",
                                plugin_path,
                                "-Xanalyzer",
                                "-analyzer-checker",
                                "-Xanalyzer",
                                "custom.SAGenTestChecker",
                                "-Xanalyzer",
                                "-analyzer-disable-checker",
                                "-Xanalyzer",
                                "core",
                                "-Xanalyzer",
                                "-analyzer-disable-checker",
                                "-Xanalyzer",
                                "cplusplus",
                                "-Xanalyzer",
                                "-analyzer-disable-checker",
                                "-Xanalyzer",
                                "deadcode",
                                "-Xanalyzer",
                                "-analyzer-disable-checker",
                                "-Xanalyzer",
                                "unix",
                                "-Xanalyzer",
                                "-analyzer-disable-checker",
                                "-Xanalyzer",
                                "nullability",
                                "-Xanalyzer",
                                "-analyzer-disable-checker",
                                "-Xanalyzer",
                                "security",
                            ]
                        )

                        # Extract ALL flags from original compilation except output-related ones
                        build_dir = os.path.join(
                            target.repo.working_dir, "out/x64.release"
                        )
                        skip_next = False
                        for part in cmd_parts[1:]:  # Skip compiler name
                            if skip_next:
                                skip_next = False
                                continue

                            # Skip output-related and module-related flags
                            if part in ["-c", "-MMD", "-o", "-MF"]:
                                skip_next = True
                                continue
                            if (
                                part.endswith(".o")
                                or part.endswith(".o.d")
                                or part.startswith("-fmodule-file=")
                                or part.startswith("-fmodule-map-file=")
                                or part
                                in [
                                    "-fmodules",
                                    "-fno-implicit-module-maps",
                                    "-fno-implicit-modules",
                                    "-fbuiltin-module-map",
                                    "-DUSE_LIBCXX_MODULES",
                                ]
                            ):
                                continue

                            # Handle -Xclang pairs properly - skip -Xclang and the next argument if it's module-related
                            if part == "-Xclang":
                                skip_next = True  # Skip the next argument after -Xclang
                                continue

                            # Keep all other flags - they work for compilation, they should work for analysis
                            analyzer_cmd.append(part)

                        # Add output file with HTML format for cross-file diagnostics
                        analyzer_cmd.extend(
                            [
                                "-Xanalyzer",
                                "-analyzer-output=html",
                                "-o",
                                str(output_dir.absolute()),
                                f"../../{source_file}",  # Relative to build dir
                            ]
                        )

                        # Step 3: Run the analyzer from build directory (same as compilation)
                        logger.info(f"Running analyzer from: {build_dir}")
                        logger.info(f"Analyzer command: {' '.join(analyzer_cmd)}")

                        analyze_result = sp.run(
                            analyzer_cmd,
                            cwd=build_dir,  # Run from build directory
                            capture_output=True,
                            text=True,
                        )

                        if analyze_result.returncode != 0:
                            logger.error(
                                f"Analyzer failed: {analyze_result.stderr[:500]}"
                            )
                        else:
                            logger.info(f"Analyzer successful: {analyze_result.stdout}")

                        return analyze_result

                    cmd = run_build_and_analysis
                else:
                    cmd = f"echo 'No compilation command found for {source_file}'"
            except Exception as e:
                cmd = f"echo 'Error reading compile_commands.json: {str(e)}'"
        else:
            logger.error(f"compile_commands.json not found at {compile_commands_path}")
            raise RuntimeError(
                f"compile_commands.json not found at {compile_commands_path}"
            )

        return cmd

    def _extract_ninja_compile_command(self, source_file, target):
        """Extract the actual compilation command from ninja for a source file."""
        # Get the object file name for this source
        from targets.v8 import V8

        obj_file = V8.get_object_name(source_file)

        # Use ninja -t commands to get the compilation command
        try:
            result = sp.run(
                f"ninja -C out/x64.release -t commands {obj_file}",
                shell=True,
                capture_output=True,
                text=True,
                cwd=target.repo.working_dir,
                timeout=10,
            )
            Path("tmp/ninja_commands.txt").write_text(result.stdout)

            if result.returncode == 0 and result.stdout:
                # The output should contain the compilation command
                lines = result.stdout.strip().split("\n")

                # Look for the line that compiles this specific source file
                # The source file might be referenced as ../../path/to/file
                source_basename = Path(source_file).name
                for line in lines:
                    # Check if this line is compiling our source file
                    if source_basename in line and " -c " in line and "clang" in line:
                        # Make sure it's actually compiling this file, not just mentioning it
                        if (
                            f"-c ../../{source_file}" in line
                            or f"-c {source_file}" in line
                        ):
                            logger.info(f"Found ninja command for {source_file}")
                            return line.strip()

                # If exact match not found, try a less strict match
                for line in lines:
                    if source_basename in line and " -c " in line:
                        logger.info(
                            f"Found ninja command (relaxed match) for {source_file}"
                        )
                        return line.strip()

        except Exception as e:
            logger.warning(f"Failed to extract ninja command: {e}")

        return None

    def get_num_bugs_from_direct_analysis(self, output):
        """Parse bugs from direct clang analysis output."""
        # Count warning lines that match our checker
        bug_count = 0
        for line in output.split("\n"):
            if "warning:" in line and "custom.SAGenTestChecker" in line:
                bug_count += 1
        return bug_count

    def get_num_bugs_from_scan_build(self, scan_build_output_dir="/tmp/test-scan"):
        """Parse bugs from scan-build HTML or plist reports."""
        if not os.path.exists(scan_build_output_dir):
            return 0

        # First try HTML files (new format for cross-file diagnostics)
        html_files = glob.glob(
            os.path.join(scan_build_output_dir, "**/*.html"), recursive=True
        )
        if html_files:
            # Count HTML report files (each represents a bug)
            # Exclude index.html and scanview.html which are summaries
            bug_reports = [f for f in html_files if "report-" in os.path.basename(f)]
            return len(bug_reports)
        else:
            logger.warning(f"No HTML files found in {scan_build_output_dir}")
            return 0

    def _analyze_v8_source_file(
        self, compile_entry, output_dir, target=None, timeout=900
    ):
        """
        Helper function to analyze a single V8 source file using clang++ --analyze.

        Args:
            compile_entry: Entry from compile_commands.json containing:
                - file: source file path
                - command: original compilation command
                - directory: working directory for compilation
            output_dir: Directory to save HTML analysis reports
            target: Optional V8 target for fallback working directory
            timeout: Analysis timeout in seconds

        Returns:
            tuple: (success: bool, num_bugs: int, error_message: str or None)
        """
        source_file = compile_entry.get("file", "")
        compile_cmd = compile_entry.get("command", "")
        directory = compile_entry.get("directory", "")

        if not source_file or not compile_cmd:
            return False, 0, "Missing file or command in compile entry"

        # Clean up source file path for logging
        if source_file.startswith("../../"):
            clean_source = source_file[6:]
        else:
            clean_source = source_file

        # Build clang++ --analyze command
        llvm_build_dir = self.backend_path / "build"
        plugin_path = f"{llvm_build_dir}/lib/SAGenTestPlugin.so"

        cmd_parts = shlex.split(compile_cmd)
        analyzer_cmd = [f"{llvm_build_dir}/bin/clang++", "--analyze"]

        # Add plugin and checker configuration
        analyzer_cmd.extend(
            [
                "-Xanalyzer",
                "-load",
                "-Xanalyzer",
                plugin_path,
                "-Xanalyzer",
                "-analyzer-checker",
                "-Xanalyzer",
                "custom.SAGenTestChecker",
                "-Xanalyzer",
                "-analyzer-disable-checker",
                "-Xanalyzer",
                "core",
                "-Xanalyzer",
                "-analyzer-disable-checker",
                "-Xanalyzer",
                "cplusplus",
                "-Xanalyzer",
                "-analyzer-disable-checker",
                "-Xanalyzer",
                "deadcode",
                "-Xanalyzer",
                "-analyzer-disable-checker",
                "-Xanalyzer",
                "unix",
                "-Xanalyzer",
                "-analyzer-disable-checker",
                "-Xanalyzer",
                "nullability",
                "-Xanalyzer",
                "-analyzer-disable-checker",
                "-Xanalyzer",
                "security",
                "-Xanalyzer",
                "-analyzer-config",
                "-Xanalyzer",
                "max-loop=8",
                "-Xanalyzer",
                "-analyzer-output=html",
                "-o",
                str(output_dir.absolute())
                if hasattr(output_dir, "absolute")
                else str(output_dir),
            ]
        )

        # Extract compilation flags from original command (skip output and module-related flags)
        skip_next = False
        for part in cmd_parts[1:]:  # Skip compiler name
            if skip_next:
                skip_next = False
                continue

            # Skip output-related and module-related flags
            if part in ["-c", "-MMD", "-o", "-MF"]:
                skip_next = True
                continue
            if (
                part.endswith(".o")
                or part.endswith(".o.d")
                or part.startswith("-fmodule-file=")
                or part.startswith("-fmodule-map-file=")
                or part
                in [
                    "-fmodules",
                    "-fno-implicit-module-maps",
                    "-fno-implicit-modules",
                    "-fbuiltin-module-map",
                    "-DUSE_LIBCXX_MODULES",
                ]
            ):
                continue

            # Handle -Xclang pairs properly - skip -Xclang and the next argument if it's module-related
            if part == "-Xclang":
                skip_next = True  # Skip the next argument after -Xclang
                continue

            # Keep all other flags - they work for compilation, they should work for analysis
            analyzer_cmd.append(part)

        # Add output file with HTML format for cross-file diagnostics
        analyzer_cmd.extend(
            [
                "-Xanalyzer",
                "-analyzer-output=html",
                "-o",
                str(output_dir.absolute()),
                f"../../{source_file}",  # Relative to build dir
            ]
        )

        # Step 3: Run the analyzer from working directory
        work_dir = directory or (target.repo.working_dir if target else None)
        if not work_dir:
            return False, 0, "No working directory available"

        logger.info(f"Running analyzer from: {work_dir}")
        logger.info(f"Analyzer command: {' '.join(analyzer_cmd)}")

        try:
            analyze_result = sp.run(
                analyzer_cmd,
                cwd=work_dir,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            if analyze_result.returncode == 0 or analyze_result.returncode == 1:
                # Count bugs from stderr output or HTML files
                bug_count = self.get_num_bugs_from_direct_analysis(analyze_result.stderr)
                return True, bug_count, None
            else:
                error_msg = f"Analysis failed with return code {analyze_result.returncode}: {analyze_result.stderr}"
                logger.error(f"Analyzer failed: {error_msg}")
                return False, 0, error_msg

        except sp.TimeoutExpired:
            error_msg = f"Analysis timeout after {timeout} seconds"
            logger.warning(f"Analysis timeout")
            return False, 0, error_msg
        except Exception as e:
            error_msg = f"Unexpected error during analysis: {str(e)}"
            logger.error(f"Unexpected error during analysis: {e}")
            return False, 0, error_msg

    def _analyze_chromium_source_file(
        self, compile_entry, output_dir, target=None, timeout=900
    ):
        """
        Helper function to analyze a single Chromium source file using clang++ --analyze.

        Args:
            compile_entry: Entry from compile_commands.json containing:
                - file: source file path
                - command: original compilation command
                - directory: working directory for compilation
            output_dir: Directory to save HTML analysis reports
            target: Optional Chromium target for fallback working directory
            timeout: Analysis timeout in seconds

        Returns:
            tuple: (success: bool, num_bugs: int, error_message: str or None)
        """
        source_file = compile_entry.get("file", "")
        compile_cmd = compile_entry.get("command", "")
        directory = compile_entry.get("directory", "")

        if not source_file or not compile_cmd:
            return False, 0, "Missing file or command in compile entry"

        # Clean up source file path for logging
        if source_file.startswith("../../"):
            display_source = source_file[6:]
        else:
            display_source = source_file

        # Build clang++ --analyze command
        llvm_build_dir = self.backend_path / "build"
        plugin_path = f"{llvm_build_dir}/lib/SAGenTestPlugin.so"

        cmd_parts = shlex.split(compile_cmd)
        analyzer_cmd = [f"{llvm_build_dir}/bin/clang++", "--analyze"]

        # Add plugin and checker configuration
        analyzer_cmd.extend(
            [
                "-Xanalyzer",
                "-load",
                "-Xanalyzer",
                plugin_path,
                "-Xanalyzer",
                "-analyzer-checker",
                "-Xanalyzer",
                "custom.SAGenTestChecker",
                "-Xanalyzer",
                "-analyzer-disable-checker",
                "-Xanalyzer",
                "core",
                "-Xanalyzer",
                "-analyzer-disable-checker",
                "-Xanalyzer",
                "cplusplus",
                "-Xanalyzer",
                "-analyzer-disable-checker",
                "-Xanalyzer",
                "deadcode",
                "-Xanalyzer",
                "-analyzer-disable-checker",
                "-Xanalyzer",
                "unix",
                "-Xanalyzer",
                "-analyzer-disable-checker",
                "-Xanalyzer",
                "nullability",
                "-Xanalyzer",
                "-analyzer-disable-checker",
                "-Xanalyzer",
                "security",
                "-Xanalyzer",
                "-analyzer-config",
                "-Xanalyzer",
                "max-loop=8",
                "-Xanalyzer",
                "-analyzer-output=html",
                "-o",
                str(output_dir.absolute())
                if hasattr(output_dir, "absolute")
                else str(output_dir),
            ]
        )

        # Extract compilation flags from original command (skip output and module-related flags)
        skip_next = False
        for part in cmd_parts[1:]:
            if skip_next:
                skip_next = False
                continue
            if part in ['-o', '-MF', '-MT', '-MD']:
                skip_next = True
                continue
            if part.startswith('-o') or part.startswith('-MF') or part.startswith('-MT'):
                continue
            if not part.endswith('.o') and not part.endswith('.d'):
                analyzer_cmd.append(part)

        # Add the source file
        analyzer_cmd.append(source_file)

        # Determine working directory
        work_dir = directory or (target.repo.working_dir if target else None)
        if not work_dir:
            return False, 0, "No working directory available"

        # Run analysis
        try:
            logger.debug(f"Analyzing Chromium source: {display_source}")
            result = sp.run(
                analyzer_cmd,
                cwd=work_dir,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            if result.returncode == 0 or result.returncode == 1:  # 1 can indicate warnings/bugs found
                # Count bugs from stderr output
                bug_count = self.get_num_bugs_from_direct_analysis(result.stderr)
                return True, bug_count, None
            else:
                error_msg = f"Analysis failed with return code {result.returncode}: {result.stderr}"
                logger.error(f"Failed to analyze {display_source}: {error_msg}")
                return False, 0, error_msg

        except sp.TimeoutExpired:
            error_msg = f"Analysis timeout after {timeout} seconds"
            logger.warning(f"Timeout analyzing {display_source}")
            return False, 0, error_msg
        except Exception as e:
            error_msg = f"Analysis exception: {str(e)}"
            logger.error(f"Exception analyzing {display_source}: {error_msg}")
            return False, 0, error_msg

    def _generate_command(self, no_output=False, plugin_names=None):
        """
        Generate the command to run the analysis.

        Args:
            no_output (bool): If True, suppress the output file generation.
            plugin_names (list): List of plugin names to enable.
            target_type (str): The type of target ('v8' or None for default).
        Returns:
            str: The command to run the analysis.
        """
        llvm_build_dir = (self.backend_path / "build").absolute()
        comd = f"PATH={llvm_build_dir}/bin:$PATH "
        comd += f"{llvm_build_dir}/bin/scan-build --use-cc=clang "
        if plugin_names:
            for plugin_name in plugin_names:
                comd += f"-load-plugin {llvm_build_dir}/lib/{plugin_name}Plugin.so "
                comd += f"-enable-checker custom.{plugin_name}Checker "
        else:
            comd += f"-load-plugin {llvm_build_dir}/lib/SAGenTestPlugin.so "
            comd += "-enable-checker custom.SAGenTestChecker "

        # Use appropriate arguments based on target type
        args_to_use = self._default_args
        for arg_name, arg_value in args_to_use:
            if no_output and arg_name == "-o":
                continue
            comd += f"{arg_name} {arg_value} "

        return comd

    def _generate_command_group(
        self, no_output=False, plugin_names=None, output_dir=None
    ):
        """
        [WIP] Generate the command to run analysis with multiple checkers.

        Args:
            no_output (bool): If True, suppress the output file generation.
            plugin_names (list): List of plugin names to enable.
            output_dir (str): Custom output directory for reports.
        Returns:
            str: The command to run the analysis.
        """
        # FIXME: This is not implemented yet

        llvm_build_dir = (self.backend_path / "build").absolute()
        comd = f"PATH={llvm_build_dir}/bin:$PATH "
        comd += f"{llvm_build_dir}/bin/scan-build --use-cc=clang "

        # Load all checker plugins
        if plugin_names:
            for plugin_name in plugin_names:
                comd += f"-load-plugin {llvm_build_dir}/lib/{plugin_name}Plugin.so "
                comd += f"-enable-checker custom.{plugin_name}Checker "
        else:
            comd += f"-load-plugin {llvm_build_dir}/lib/SAGenTestPlugin.so "
            comd += "-enable-checker custom.SAGenTestChecker "

        # Add arguments, with custom output directory if specified
        for arg_name, arg_value in self._default_args:
            if no_output and arg_name == "-o":
                continue
            if arg_name == "-o" and output_dir:
                comd += f"{arg_name} {output_dir} "
            else:
                comd += f"{arg_name} {arg_value} "
        return comd

    @staticmethod
    def get_num_bugs(content: str) -> int:
        try:
            num_bugs = int(re.search(r": (\d+) bug(s?) found", content).group(1))
        except Exception:
            print("Error: Couldn't extract number of bugs from output.")
            num_bugs = 0
        return num_bugs

    @staticmethod
    def get_objects_from_report(report: str, target: TargetFactory):
        """
        Get the objects from the report.

        Args:
            report (str): The report to extract objects from.
            target (TargetFactory): The target to be tested.

        Returns:
            list: List of objects found in the report.
        """
        # Find `File:| XXX.c`
        pattern = r"File:\| (.*).c"
        matches = re.findall(pattern, report)
        # Filter out non-c files
        matches = [match + ".c" for match in matches]
        matches = [Path(match).absolute().resolve().as_posix() for match in matches]
        # Delete the prefix linux path
        # FIXME: This could be wrong
        target_path = Path(target.repo.working_dir).absolute().resolve().as_posix()
        target_path += "/"
        matches = [match.replace(target_path, "") for match in matches]

        # Replace .c with .o
        matches = [target.get_object_name(match) for match in matches]
        return matches

    @staticmethod
    def extract_reports(
        report_dir, output_dir, sampled_num=5, stop_num=5, max_num=100, seed=0
    ) -> Tuple[Optional[List[ReportData]], int]:
        """
        Extract reports from the report directory and process them into markdown files.
        """
        report_dir = Path(report_dir)
        stop_num = max(sampled_num, stop_num)

        # Sort the report dir by time
        report_dir_list = sorted(
            [x for x in report_dir.iterdir() if x.is_dir()],
            key=lambda x: x.stat().st_ctime,
        )
        if not report_dir_list:
            logger.error("No report found!")
            return None, 0
        clustered_report_dir = defaultdict(list)

        # The latest report dir
        report_dir = report_dir_list[-1]

        report_tmp_dir = Path(output_dir)
        report_tmp_dir.mkdir(parents=True, exist_ok=True)

        # Check if this is V8-style subdirectory structure or traditional flat structure
        report_html_list = list(report_dir.glob("*.html"))

        # If no HTML files directly in report_dir, check subdirectories (V8 structure)
        if not report_html_list:
            # Look for HTML files in subdirectories (e.g., src_objects_objects_cc/)
            report_html_list = list(report_dir.glob("*/*.html"))
            if report_html_list:
                logger.info(f"Found V8-style report structure with subdirectories")

        num_reports = len(report_html_list)
        if num_reports < stop_num:
            logger.warning(f"< {stop_num} reports!")
            return None, num_reports

        max_len = min(max_num, num_reports)
        # Filename pattern example: `File:| drivers/video/backlight/qcom-wled.c`
        filename_pattern = re.compile(r"File:\| (.+)")
        for report_html in report_html_list[:max_len]:
            html_content = report_html.read_text()
            md_content = html2text(html_content)
            # This is specific to the report format
            md_content = remove_text_section(md_content, html_content)
            filename = filename_pattern.search(md_content)
            if filename:
                filename = filename.group(1)
            else:
                filename = "default"

            filename = str(Path(filename).resolve())
            filename = (
                filename.replace("/", "_").replace(".c", "").replace(".h", "").strip()
            )
            id_name = f"{filename}-{report_html.stem}"
            report_md = report_tmp_dir / (id_name + ".md")
            report_md.write_text(md_content)

            report_data = ReportData(
                report_id=id_name,
                report_content=md_content,
                report_triage="",
                report_objects=[],
            )
            clustered_report_dir[filename].append(report_data)

        random.seed(seed)
        # Sample the reports
        filtered_keys = []
        sample_size = min(sampled_num, len(clustered_report_dir))
        logger.warning(f"Sample size: {sample_size} by seed {seed}")

        for key in clustered_report_dir.keys():
            if any(pattern in key for pattern in ["_include_"]):
                # We don't want to sample the include files
                continue
            filtered_keys.append(key)

        if len(filtered_keys) < sample_size:
            logger.warning(f"Not enough ({sample_size - len(filtered_keys)}) keys")
            other_keys = [
                key for key in clustered_report_dir.keys() if key not in filtered_keys
            ]
            filtered_keys.extend(
                random.sample(other_keys, sample_size - len(filtered_keys))
            )

        selected_keys = random.sample(filtered_keys, sample_size)
        reports = []
        for key in selected_keys:
            reports.append(clustered_report_dir[key][0])
        return reports, len(clustered_report_dir)

    @staticmethod
    def _generate_unique_checker_name_static(checker_id: str) -> str:
        """Static version of _generate_unique_checker_name for use in attribution."""
        name = checker_id.replace("KN-", "").replace("-", "_")
        name = re.sub(r"[^a-zA-Z0-9_]", "_", name)
        if name and not name[0].isalpha():
            name = f"Checker_{name}"
        if len(name) > 30:
            name = name[:30]
        return name or "SAGenTest"

    def _validate_checker_chromium(
        self,
        checker_code: str,
        commit_id,  # Can be str or List[str]
        patch: str,
        target,
        skip_build_checker=False,
    ):
        """
        Validate the checker against a Chromium commit(s) and patch.
        Analyzes files in both buggy and fixed versions to compute TP/TN.
        
        Args:
            commit_id: Can be a single commit ID (str) or list of commit IDs (List[str])
        """
        # Handle both single commit and multiple commits
        if isinstance(commit_id, str):
            commit_ids = [commit_id]
            main_commit_id = commit_id
        else:
            commit_ids = commit_id
            main_commit_id = commit_ids[0] if commit_ids else "unknown"
        
        logger.info(f"Chromium validation with commits: {commit_ids}")
        
        # Remove depot_tools from PATH to prevent gclient sync from changing Chromium dependencies
        original_path = os.environ.get("PATH", "")
        filtered_path = ":".join(
            [p for p in original_path.split(":") if "depot_tools" not in p]
        )
        os.environ["PATH"] = filtered_path

        logger.info(f"Chromium validation: removed depot_tools from PATH")

        TP, TN = 0, 0
        if not skip_build_checker:
            self.build_checker(checker_code, Path("tmp") / "build_logs")

        # Get source files from patch
        source_files = target.get_source_files_from_patch(patch)
        logger.info(f"Source files to analyze from patch: {source_files}")

        # Create debug log for troubleshooting
        debug_log = "/tmp/chromium_checker_debug.log"
        if os.path.exists(debug_log):
            os.remove(debug_log)

        # Write initial debug info
        with open(debug_log, "w") as f:
            f.write(f"Chromium Checker Validation Debug Log\n")
            f.write(f"Commit IDs: {commit_ids}\n")
            f.write(f"Main commit ID: {main_commit_id}\n")
            f.write(f"Source files from patch: {source_files}\n")
            f.write(f"Timestamp: {datetime.now()}\n\n")

        num_bug_files = {}

        # For multiple commits, sort by timestamp and get earliest for 'before' state
        if len(commit_ids) > 1:
            logger.info("Multiple commits detected, sorting by timestamp")
            # Import the function from checker_gen
            from checker_gen import sort_commits_by_timestamp
            sorted_commits = sort_commits_by_timestamp(commit_ids, target)
            before_commit = sorted_commits[0]  # Earliest commit
            after_commit = sorted_commits[-1]  # Latest commit
            logger.info(f"Using earliest commit {before_commit} for 'before' state")
            logger.info(f"Using latest commit {after_commit} for 'after' state")
        else:
            before_commit = commit_ids[0]
            after_commit = commit_ids[0]

        # Create output directories for validation (consistent with V8 structure)
        validation_base_dir = Path("tmp") / "chromium_validation" / main_commit_id

        # Create timestamped directories for both buggy and fixed versions
        buggy_base_dir = validation_base_dir / "buggy"
        fixed_base_dir = validation_base_dir / "fixed"
        buggy_base_dir.mkdir(parents=True, exist_ok=True)
        fixed_base_dir.mkdir(parents=True, exist_ok=True)

        buggy_output_dir = self._create_timestamped_output_dir(buggy_base_dir)
        fixed_output_dir = self._create_timestamped_output_dir(fixed_base_dir)

        # Checkout buggy version (earliest commit's parent for multi-commit case)
        llvm_build_dir = self.backend_path / "build"
        target.checkout_commit(
            before_commit,
            is_before=True,
            arch="x64",
            build_config="release",
            llvm_path=llvm_build_dir,
            skip_gclient_sync=True,  # Skip gclient sync for faster validation
        )

        # Build the specific object files first
        env = os.environ.copy()
        env["PATH"] = f"{llvm_build_dir}/bin:" + env.get("PATH", "")

        # Get compile_commands.json to find exact entries for source files
        compile_commands_path = (
            Path(target.repo.working_dir) / "out/x64_release/compile_commands.json"
        )

        # Use helper function to get compile entries
        compile_entries = self._get_compile_entries_for_chromium_sources(
            compile_commands_path, source_files
        )

        # Build and analyze buggy version
        for source_file in source_files:
            if source_file in compile_entries:
                # Create file-specific output directory
                safe_filename = source_file.replace("/", "_").replace(".", "_")
                file_output_dir = buggy_output_dir / safe_filename
                file_output_dir.mkdir(parents=True, exist_ok=True)
                
                success, bugs, error = self._analyze_chromium_source_file(
                    compile_entries[source_file], file_output_dir, target
                )
                if success:
                    num_bug_files[source_file] = bugs
                    with open(debug_log, "a") as f:
                        f.write(f"Buggy version - {source_file}: {bugs} bugs\n")
                else:
                    with open(debug_log, "a") as f:
                        f.write(f"Buggy version - {source_file}: Analysis failed - {error}\n")
            else:
                logger.warning(f"No compile entry found for {source_file} in buggy version")

        # Checkout fixed version
        target.checkout_commit(
            after_commit,
            is_before=False,
            arch="x64",
            build_config="release",
            llvm_path=llvm_build_dir,
            skip_gclient_sync=True,  # Skip gclient sync for faster validation
        )

        # Re-read compile_commands.json for fixed version (may have changed after checkout)
        compile_entries = self._get_compile_entries_for_chromium_sources(
            compile_commands_path, source_files
        )

        # Build and analyze fixed version
        for source_file in source_files:
            if source_file in compile_entries:
                # Create file-specific output directory
                safe_filename = source_file.replace("/", "_").replace(".", "_")
                file_output_dir = fixed_output_dir / safe_filename
                file_output_dir.mkdir(parents=True, exist_ok=True)
                
                success, bugs, error = self._analyze_chromium_source_file(
                    compile_entries[source_file], file_output_dir, target
                )
                if success:
                    buggy_bugs = num_bug_files.get(source_file, 0)
                    if buggy_bugs > 0 and bugs == 0:
                        TP += 1  # True positive: bug found in buggy version, not in fixed
                    elif buggy_bugs == 0 and bugs == 0:
                        TN += 1  # True negative: no bug in either version
                    
                    with open(debug_log, "a") as f:
                        f.write(f"Fixed version - {source_file}: {bugs} bugs (was {buggy_bugs})\n")
                else:
                    with open(debug_log, "a") as f:
                        f.write(f"Fixed version - {source_file}: Analysis failed - {error}\n")
            else:
                logger.warning(f"No compile entry found for {source_file} in fixed version")

        logger.info(f"Chromium Validation Result: TP={TP}, TN={TN}")

        # Create softlinks for both buggy and fixed directories
        self._create_chromium_report_softlinks(buggy_output_dir, buggy_base_dir)
        self._create_chromium_report_softlinks(fixed_output_dir, fixed_base_dir)

        # Write final summary to debug log
        with open(debug_log, "a") as f:
            f.write(f"\nFinal Results:\n")
            f.write(f"True Positives: {TP}\n")
            f.write(f"True Negatives: {TN}\n")

        return TP, TN

    def _get_compile_entries_for_chromium_sources(
        self, compile_commands_path: Path, source_files: List[str]
    ) -> dict:
        """
        Extract compile entries for specific source files from compile_commands.json.

        Args:
            compile_commands_path: Path to compile_commands.json
            source_files: List of source files to find entries for

        Returns:
            dict: Mapping of source file to compile command entry
        """
        compile_entries = {}

        if not compile_commands_path.exists():
            logger.warning(f"compile_commands.json not found at {compile_commands_path}")
            return compile_entries

        try:
            with open(compile_commands_path, 'r') as f:
                commands = json.load(f)

            for entry in commands:
                file_path = entry.get('file', '')
                # Normalize paths for comparison
                if file_path.startswith('../../'):
                    normalized_file = file_path[6:]  # Remove ../../
                else:
                    normalized_file = file_path

                for source_file in source_files:
                    if normalized_file == source_file or file_path.endswith(source_file):
                        compile_entries[source_file] = entry
                        logger.debug(f"Found compile entry for {source_file}")
                        break

        except Exception as e:
            logger.error(f"Failed to read compile_commands.json: {e}")

        return compile_entries

    def _analyze_chromium_source_file(self, compile_entry, output_dir, target=None, timeout=900):
        """
        Analyze a single source file for Chromium using clang++ --analyze.

        Args:
            compile_entry: Entry from compile_commands.json for the source file
            output_dir: Directory to save analysis reports
            target: The Chromium target

        Returns:
            tuple: (success: bool, num_bugs: int, error_message: str or None)
        """
        source_file = compile_entry.get("file", "")
        compile_cmd = compile_entry.get("command", "")
        directory = compile_entry.get("directory", "")

        if not source_file or not compile_cmd:
            return False, 0, "Missing file or command in compile entry"

        # Clean up source file path for logging
        if source_file.startswith("../../"):
            clean_source = source_file[6:]
        else:
            clean_source = source_file

        # Build clang++ --analyze command
        llvm_build_dir = self.backend_path / "build"
        plugin_path = f"{llvm_build_dir}/lib/SAGenTestPlugin.so"

        cmd_parts = shlex.split(compile_cmd)
        analyzer_cmd = [f"{llvm_build_dir}/bin/clang++", "--analyze"]

        # Add plugin and checker configuration
        analyzer_cmd.extend(
            [
                "-Xanalyzer",
                "-load",
                "-Xanalyzer",
                plugin_path,
                "-Xanalyzer",
                "-analyzer-checker",
                "-Xanalyzer",
                "custom.SAGenTestChecker",
                "-Xanalyzer",
                "-analyzer-disable-checker",
                "-Xanalyzer",
                "core",
                "-Xanalyzer",
                "-analyzer-disable-checker",
                "-Xanalyzer",
                "cplusplus",
                "-Xanalyzer",
                "-analyzer-disable-checker",
                "-Xanalyzer",
                "deadcode",
                "-Xanalyzer",
                "-analyzer-disable-checker",
                "-Xanalyzer",
                "unix",
                "-Xanalyzer",
                "-analyzer-disable-checker",
                "-Xanalyzer",
                "nullability",
                "-Xanalyzer",
                "-analyzer-disable-checker",
                "-Xanalyzer",
                "security",
                "-Xanalyzer",
                "-analyzer-config",
                "-Xanalyzer",
                "max-loop=8",
                "-Xanalyzer",
                "-analyzer-output=html",
                "-o",
                str(output_dir.absolute())
                if hasattr(output_dir, "absolute")
                else str(output_dir),
            ]
        )

        # Extract compilation flags from original command (skip output and module-related flags)
        skip_next = False
        for part in cmd_parts[1:]:
            if skip_next:
                skip_next = False
                continue
            if part in ['-o', '-MF', '-MT', '-MD']:
                skip_next = True
                continue
            if part.startswith('-o') or part.startswith('-MF') or part.startswith('-MT'):
                continue
            if not part.endswith('.o') and not part.endswith('.d'):
                analyzer_cmd.append(part)

        # Add the source file
        analyzer_cmd.append(source_file)

        # Determine working directory
        work_dir = directory or (target.repo.working_dir if target else None)
        if not work_dir:
            return False, 0, "No working directory available"

        # Run analysis
        try:
            logger.debug(f"Analyzing Chromium source: {clean_source}")
            result = sp.run(
                analyzer_cmd,
                cwd=work_dir,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            logger.info(f"Analysis completed for {clean_source} with return code {result.returncode}")

            if result.returncode == 0 or result.returncode == 1:  # 1 can indicate warnings/bugs found
                # Count bugs from stderr output
                bug_count = self.get_num_bugs_from_direct_analysis(result.stderr)
                return True, bug_count, None
            else:
                error_msg = f"Analysis failed with return code {result.returncode}: {result.stderr}"
                logger.error(f"Failed to analyze {clean_source}: {error_msg}")
                return False, 0, error_msg

        except sp.TimeoutExpired:
            error_msg = f"Analysis timeout after {timeout} seconds"
            logger.warning(f"Timeout analyzing {clean_source}")
            return False, 0, error_msg
        except Exception as e:
            error_msg = f"Analysis exception: {str(e)}"
            logger.error(f"Exception analyzing {clean_source}: {error_msg}")
            return False, 0, error_msg

    def _discover_chromium_source_entries(self, all_entries) -> List[dict]:
        """
        Discover Chromium source files that can be analyzed from compile_commands.json.

        Args:
            all_entries: All entries from compile_commands.json

        Returns:
            List[dict]: List of compile command entries for Chromium source files
        """
        source_entries = []
        
        # Define patterns for Chromium source directories to include
        include_patterns = [
            "base/", "net/", "content/", "chrome/", "components/",
            "ui/", "media/", "gpu/", "services/", "third_party/blink/"
        ]
        
        # Define patterns to exclude
        exclude_patterns = [
            "test", "_test", "_unittest", "mock", "fake", "generated",
            "third_party/", "build/", "tools/", "out/", ".pb.cc"
        ]

        logger.info(f"Filtering {len(all_entries)} compile entries for Chromium analysis")

        for entry in all_entries:
            file_path = entry.get('file', '')
            
            # Normalize file path
            if file_path.startswith('../../'):
                normalized_path = file_path[6:]  # Remove ../../
            else:
                normalized_path = file_path
            
            # Check if it's a C++ source file
            if not normalized_path.endswith(('.cc', '.cpp', '.c')):
                continue
            
            # Check include patterns
            include_match = any(pattern in normalized_path for pattern in include_patterns)
            if not include_match:
                continue
            
            # Check exclude patterns
            exclude_match = any(pattern in normalized_path for pattern in exclude_patterns)
            if exclude_match:
                continue
            
            source_entries.append(entry)

        logger.info(f"Found {len(source_entries)} Chromium source files to analyze")
        
        # Limit the number of files to avoid overwhelming analysis
        max_files = 500  # Reasonable limit for Chromium analysis
        if len(source_entries) > max_files:
            logger.warning(f"Limiting analysis to {max_files} files (from {len(source_entries)})")
            source_entries = source_entries[:max_files]

        return source_entries

    def _analyze_chromium_files_parallel(
        self, source_entries_list, unique_output_dir, target, max_workers=32
    ):
        """
        Analyze Chromium source files in parallel.

        Args:
            source_entries_list: List of compile_commands.json entries to analyze
            unique_output_dir: Base output directory for reports
            target: Chromium target
            max_workers: Number of parallel workers

        Returns:
            tuple: (total_bugs, analyzed_files, failed_files)
        """
        # Thread-safe counters
        total_bugs = 0
        analyzed_files = 0
        failed_files = 0
        lock = threading.Lock()

        def analyze_single_file(entry_with_index):
            nonlocal total_bugs, analyzed_files, failed_files
            
            entry, index = entry_with_index
            file_path = entry.get('file', 'unknown')
            
            try:
                success, bugs, error = self._analyze_chromium_source_file(
                    entry, unique_output_dir, target
                )
                
                with lock:
                    if success:
                        total_bugs += bugs
                        analyzed_files += 1
                        if bugs > 0:
                            logger.info(f"File {index}: {file_path} - {bugs} bugs found")
                    else:
                        failed_files += 1
                        logger.warning(f"File {index}: {file_path} - Analysis failed: {error}")
                        
            except Exception as e:
                with lock:
                    failed_files += 1
                    logger.error(f"File {index}: {file_path} - Exception: {e}")

        # Execute analysis in parallel
        logger.info(f"Starting parallel Chromium analysis with {max_workers} workers")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(analyze_single_file, (entry, i)): i 
                for i, entry in enumerate(source_entries_list)
            }
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Parallel analysis task failed: {e}")

        logger.info(f"Parallel Chromium analysis completed")
        return total_bugs, analyzed_files, failed_files

    def _create_chromium_report_softlinks(
        self, timestamped_output_dir: Path, base_output_dir: Path
    ) -> None:
        """
        Create softlinks to make Chromium report structure compatible with refinement process.
        """
        try:
            if timestamped_output_dir.exists():
                for subdir in timestamped_output_dir.iterdir():
                    if subdir.is_dir():
                        link_target = base_output_dir / subdir.name
                        if not link_target.exists():
                            link_target.symlink_to(subdir, target_is_directory=True)
                            logger.debug(f"Created softlink: {link_target} -> {subdir}")
        except Exception as e:
            logger.warning(f"Failed to create Chromium report softlinks: {e}")

    def _create_timestamped_output_dir(self, base_output_dir: Path) -> Path:
        """
        Create a timestamped output directory similar to scan-build's behavior.

        This creates a directory with format: YYYY-MM-DD-HHMMSS-PID-N
        consistent with Linux scan-build timestamps.

        Args:
            base_output_dir: The base output directory

        Returns:
            Path: The timestamped output directory
        """
        # Create timestamp similar to scan-build format
        timestamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
        pid = os.getpid()
        rand_suffix = random.randint(1, 9999)

        # Create directory name: YYYY-MM-DD-HHMMSS-PID-N
        timestamped_name = f"{timestamp}-{pid}-{rand_suffix}"
        timestamped_dir = Path(base_output_dir) / timestamped_name

        # Create the directory
        timestamped_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Created timestamped output directory: {timestamped_dir}")
        return timestamped_dir
