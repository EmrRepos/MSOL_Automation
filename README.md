# MSOL Automation

## Setup

Install Python 3.14 x64 for the combined Windows USB and EtherNet/IP
environment. From the repository root, run:

```powershell
py -3.14 setup_environment.py
```

This creates `.venv` if needed, installs both frameworks' dependencies from
the root [requirements.txt](requirements.txt), and runs `pip check`. An existing
valid `.venv` with the same Python major/minor version is reused, not replaced.
Rerun the command after dependency changes. Python and internet access are
required; the script does not install Python itself. A requirements file is a
pip dependency list and cannot create an environment by itself.

## Run

Select one USB or EtherNet/IP framework from the repository root:

```powershell
.\.venv\Scripts\python.exe launcher.py --list
.\.venv\Scripts\python.exe launcher.py usb
.\.venv\Scripts\python.exe launcher.py ethernetip
.\.venv\Scripts\python.exe launcher.py ethernetip assess
.\.venv\Scripts\python.exe launcher.py ethernetip coverage
```

With no plugin name, the launcher lists the available plugins. The selected
application runs in a separate process with the same Python interpreter and
working directory. Its exit code is returned by the launcher. USB opens the
existing desktop UI; EtherNet/IP opens its UI by default or receives the
remaining command-line arguments. Tests are started by the operator in the UI;
USB automatically scans for COM ports, but opening a UI does not start tests or
send EtherNet/IP traffic.

After setup, see
the [USB](plugins/usb/README.md) and [EtherNet/IP](plugins/ethernetip/README.md)
documentation for prerequisites, test workflows, and authorization and safety
requirements. EtherNet/IP CLI authorization checks remain in effect. USB
automated reports and its Report Center use `reports/usb` under the launcher's
current working directory; `usb_tests.db` remains in that working directory.
The EtherNet/IP GUI export dialog defaults to `reports/ethernetip`. Exporting
is still manual, and EtherNet/IP CLI reports are saved only with `--output`
(for example, `--output reports\ethernetip\assessment.json`). Both applications
allow a custom destination for manually exported reports. Existing reports are
not moved. USB device profiles remain under `plugins/usb/device_profiles`.

## Architecture and refactoring decisions

```text
MSOL_Automation/
|-- launcher.py
|-- setup_environment.py
|-- requirements.txt         # Dependencies for both frameworks
|-- framework/
|   |-- plugin_loader/       # Contract, discovery and process isolation
|   |-- logging/             # Reserved for verified shared implementations
|   |-- reporting/           # Reserved for verified shared implementations
|   |-- configuration/       # Reserved for verified shared implementations
|   `-- common_utils/        # Reserved for verified shared implementations
|-- plugins/
|   |-- usb/
|   |   |-- plugin.py        # Top-level adapter
|   |   `-- main.py, core/, ui/, plugins/, device_profiles/, tests/
|   `-- ethernetip/
|       |-- plugin.py        # Top-level adapter
|       `-- main.py, core/, modules/, reports/, ui.py, tests/
`-- tests/                   # Launcher and lifecycle tests
```

The adapters implement `FrameworkPlugin.initialize()`, `execute_tests()` and
`shutdown()`. Here `execute_tests()` runs the selected application's existing
workflow; in GUI mode it waits for the operator to close the application.
`shutdown()` is called even if initialization or execution fails. The process
boundary keeps the applications' conflicting legacy imports (`core`, `ui`, and
USB's nested `plugins`) and their GUI event loops isolated. It also preserves
their existing standalone entry points. Those internal imports have not yet
been converted to root-qualified imports, so directly importing their internal
modules as `plugins.usb.*` or `plugins.ethernetip.*` is not a supported API.

Discovery scans `plugins` for packages containing `plugin.py`, without importing
unselected plugins. A new plugin exports a `Plugin` subclass of
`framework.plugin_loader.FrameworkPlugin` from that file. Its constructor accepts
the forwarded argument sequence, and `execute_tests()` returns an integer exit
code. Failures must be raised or returned as a nonzero exit code.

### What was moved, kept, or removed

- [launcher.py](launcher.py) lists and launches the chosen plugin, forwards
  arguments, and ensures shutdown.
- [base.py](framework/plugin_loader/base.py) defines the shared lifecycle;
  [loader.py](framework/plugin_loader/loader.py) discovers and loads plugins;
  [isolated.py](framework/plugin_loader/isolated.py) runs existing applications
  in separate processes.
- [USB plugin.py](plugins/usb/plugin.py) and
  [EtherNet/IP plugin.py](plugins/ethernetip/plugin.py) adapt the existing
  entry points without moving protocol-specific logic.
- [test_launcher.py](tests/test_launcher.py) checks discovery, lifecycle,
  argument forwarding, authorization and exit codes.
  [test_project_layout.py](plugins/usb/tests/test_project_layout.py) reflects
  the new USB package and adapter.
- This README and the two plugin READMEs describe the launcher and adjusted
  working-directory and test commands.
- `plugins/usb/core/plugin_loader.py` is a separate legacy loader for USB test
  modules, not the top-level framework loader; it remains in place. The active
  USB test runner currently uses its own explicit test registry.
- `plugins/usb/core/report_generator.py` produces USB PDF/CSV reports, while
  `plugins/ethernetip/reports/report.py` builds scoped EtherNet/IP JSON evidence.
  Their schemas and dependencies differ, so neither was moved into shared
  reporting. USB device profiles and both applications' GUI logging also remain
  protocol-specific. The other shared folders are intentionally empty until a
  real common implementation is identified.
- The empty, misspelled `plugins/usb/plugins/_init_.py` and
  `plugins/usb/ui/_init_.py` were replaced with standard `__init__.py` files.
  Package initializers were added for the new framework and plugin adapters
  and existing source folders that lacked one.
- All original protocol modules, test suites, dependencies, and standalone
  entry points are retained. The EtherNet/IP `dos/` and `fuzzing/` skeletons
  remain disconnected and are not enabled by discovery.

## Verification

Run the new offline launcher tests from the repository root:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

Run each application's existing tests from its own directory, as described in
its README. No test in the launcher suite connects to a physical device.
