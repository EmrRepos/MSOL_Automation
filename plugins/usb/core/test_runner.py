# test_runner.py

import threading
import time

from datetime import datetime

from core.database import TestHistoryDB
from core.report_generator import ReportGenerator

from plugins.descriptor_test import DescriptorTest
from plugins.enumeration_test import EnumerationTest
from plugins.cdc_test import CDCValidationTest
from plugins.hid_test import HIDValidationTest
from plugins.storage_test import StorageValidationTest
from plugins.reconnect_test import ReconnectValidationTest
from plugins.stability_test import StabilityValidationTest
from plugins.endpoint_test import EndpointValidationTest
from plugins.enumeration_stress_test import EnumerationStressTest
from plugins.descriptor_robustness_test import DescriptorRobustnessTest
from plugins.cdc_security_review import CDCSecurityReview
from plugins.hid_attack_surface_review import HIDAttackSurfaceReview
from plugins.storage_exposure_review import StorageExposureReview
from plugins.serial_comm_test import SerialCommunicationTest
from core.test_suite import ApplicableSuite, SUITE_NAME

AUTO_FINISH_DELAY_SECONDS = 10


class TestRunner:

    def __init__(self):

        self.running = False
        self._stop_requested = threading.Event()
        self.last_suite = None
        self.worker_thread: threading.Thread | None = None

        self.dashboard = None

        self.db = TestHistoryDB()

        self.reporter = ReportGenerator()

        self.plugins = {

            "Descriptor Validation": DescriptorTest,

            "Enumeration Validation": EnumerationTest,

            "CDC Validation": CDCValidationTest,

            "HID Validation": HIDValidationTest,

            "Storage Validation": StorageValidationTest,

            "Reconnect Validation": ReconnectValidationTest,

            "Stability Validation": StabilityValidationTest,

            "Endpoint Validation": EndpointValidationTest,

            "Enumeration Stress Test": EnumerationStressTest,

            "Descriptor Robustness Test": DescriptorRobustnessTest,

            "CDC Security Review": CDCSecurityReview,

            "HID Attack Surface Review" : HIDAttackSurfaceReview,

            "Storage Exposure Review" : StorageExposureReview,

            "Serial Communication Validation Test": SerialCommunicationTest,

        }

    def start(
        self,
        profile,
        device,
        logger,
        progress_callback,
        use_hardware=False,
        pass_callback=None,
        suite_update=None,
        suite_finished=None,
        finished_callback=None,
        phase_callback=None,
    ):

        if self.running:

            logger(
                "[WARN] Test already running"
            )

            return

        self.running = True
        self._stop_requested.clear()
        if profile == SUITE_NAME:
            self.last_suite = None
            selected = dict(device)

            def suite_worker():
                result = None
                logger(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] START RUN: {profile}")
                try:
                    result = ApplicableSuite(self.plugins).run(
                        selected, use_hardware, self._stop_requested,
                        logger, progress_callback, suite_update or (lambda row: None),
                    )
                    completed_at = time.monotonic()
                    if phase_callback:
                        phase_callback("Checks complete; saving history and reports.")
                    try:
                        self.db.save_result(
                            result["started"], selected.get("name", "Unknown Device"),
                            f"{SUITE_NAME} [{result['run_id']}]", result["status"],
                        )
                    except Exception as error:
                        result["report_errors"].append(f"History save failed: {error}")
                        result["status"] = "ERROR"
                        logger(f"[ERROR] History save failed: {error}")
                    self.reporter.export_suite(result, logger)
                    self.last_suite = result
                    if result["status"] == "PASS" and pass_callback:
                        pass_callback()
                    logger(f"[{result['status']}] Suite {result['run_id']} completed.")
                    if phase_callback:
                        phase_callback("Checks complete; finishing automatically after 10 seconds.")
                    self._wait_after_completion(completed_at, logger)
                except Exception as error:
                    logger(f"[ERROR] Suite execution failed: {error}")
                    result = result or {
                        "status": "ERROR", "results": [], "report_errors": [str(error)]
                    }
                    result["status"] = "ERROR"
                    self.last_suite = result
                finally:
                    logger(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] STOP RUN: {profile}")
                    logger("--------------------")
                    self.running = False
                    if suite_finished:
                        suite_finished(result)
                    if finished_callback:
                        finished_callback(result["status"] if result else "ERROR")

            self.worker_thread = threading.Thread(target=suite_worker, daemon=True)
            self.worker_thread.start()
            return

        def worker():

            logger(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] START TEST: {profile}")
            status = "ERROR"
            try:

                logger(
                    f"[INFO] Starting Profile : {profile}"
                )

                progress_callback(0)

                #
                # Initial Progress
                #

                for i in range(1, 31):

                    if self._stop_requested.is_set():

                        status = "CANCELLED"
                        logger(
                            "[WARN] Test Stopped By User"
                        )

                        progress_callback(0)

                        return

                    progress_callback(i)

                    if self._stop_requested.wait(0.03):
                        status = "CANCELLED"
                        logger("[WARN] Test Stopped By User")
                        progress_callback(0)
                        return

                #
                # Device Validation
                #

                if not device:

                    logger(
                        "[FAIL] No Device Selected"
                    )

                    progress_callback(0)

                    return

                #
                # Load Plugin
                #

                plugin_class = self.plugins.get(
                    profile
                )

                if not plugin_class:

                    logger(
                        f"[FAIL] Unknown Profile : {profile}"
                    )

                    progress_callback(0)

                    return

                plugin = plugin_class()

                logger(
                    f"[INFO] Executing : {plugin.name}"
                )

                #
                # Execute Plugin
                #

                result = plugin.execute(
                    device,
                    logger,
                    use_hardware
                )
                completed_at = time.monotonic()
                if self._stop_requested.is_set():
                    status = "CANCELLED"
                    logger("[WARN] Test stopped while the plugin was executing.")
                    progress_callback(0)
                    return

                #
                # Final Progress
                #

                for i in range(31, 101):

                    if self._stop_requested.is_set():

                        logger(
                            "[INFO] Stop requested after checks completed; saving the result."
                        )
                        break

                    progress_callback(i)

                    self._stop_requested.wait(0.02)

                progress_callback(100)

                if phase_callback:
                    phase_callback("Checks complete; saving history and reports.")

                #
                # Save History
                #

                self.db.save_result(

                    datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),

                    device.get(
                        "name",
                        "Unknown Device"
                    ),

                    profile,

                    result.get(
                        "status",
                        "UNKNOWN"
                    )
                )

                #
                # Generate Reports
                #

                try:

                    report_pdf = self.reporter.export_pdf(

                        device,
                        profile,
                        result
                    )

                    logger(
                        f"[INFO] PDF Report Generated : {report_pdf}"
                    )

                except Exception as ex:

                    logger(
                        f"[WARN] PDF Export Failed : {str(ex)}"
                    )

                try:

                    report_csv = self.reporter.export_csv(

                        device,
                        profile,
                        result
                    )

                    logger(
                        f"[INFO] CSV Report Generated : {report_csv}"
                    )

                except Exception as ex:

                    logger(
                        f"[WARN] CSV Export Failed : {str(ex)}"
                    )

                #
                # Final Status
                #

                status = result.get("status", "UNKNOWN")
                if status == "PASS":

                    if pass_callback:

                        pass_callback()

                    logger(
                        "[PASS] Test Completed Successfully"
                    )

                else:

                    logger(f"[{status}] Test completed: {status}")

                if phase_callback:
                    phase_callback("Checks complete; finishing automatically after 10 seconds.")
                self._wait_after_completion(completed_at, logger)

            except Exception as ex:

                logger(
                    f"[FAIL] {str(ex)}"
                )

            finally:

                logger(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] STOP TEST: {profile}")
                logger("--------------------")
                self.running = False
                if finished_callback:
                    finished_callback(status)

        self.worker_thread = threading.Thread(
            target=worker,
            daemon=True
        )
        self.worker_thread.start()

    def _wait_after_completion(self, completed_at, logger):
        remaining = max(0, AUTO_FINISH_DELAY_SECONDS - (time.monotonic() - completed_at))
        if remaining and not self._stop_requested.is_set():
            logger("[INFO] Checks complete; finishing automatically after 10 seconds.")
            self._stop_requested.wait(remaining)

    def stop(self):

        self._stop_requested.set()

        print(
            "[INFO] Stop Requested"
        )