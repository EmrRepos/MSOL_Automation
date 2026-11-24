import json
import queue
import threading
import tkinter as tk
from dataclasses import asdict
from datetime import datetime, timezone
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from modules.discovery import Discovery, Identity, validate_target
from modules.fuzz_tests import FuzzTestRunner
from modules.live_tests import LiveTestRunner, SelectedTestRunner, coverage_matrix
from modules.security import REVIEW_STATUSES, SURFACES, SecurityAssessment
from reports.report import ReportGenerator


class AssessmentApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title('EtherNet/IP | Security Assessment Workbench')
        root.geometry('1180x820')
        root.minsize(820, 650)
        root.configure(bg='#eef1f3')
        self.events = queue.Queue()
        self.busy = False
        self.live_run = None
        self.cancel_run = threading.Event()
        self.closing = False
        self.poll_id = None
        root.protocol('WM_DELETE_WINDOW', self.close_window)
        root.bind('<Destroy>', self._on_destroy, add='+')
        self.assessment = SecurityAssessment()
        self.identities: list[Identity] = []
        self.mode = 'manual'
        self.outcome = 'No active probe performed.'
        self.observed_at = None
        self.scope_target = None
        self.scope_operator = None
        self.scope_authorized = False
        self.selected = None
        self.target = tk.StringVar(value='192.0.2.10')
        self.operator = tk.StringVar()
        self.authorized = tk.BooleanVar()
        self.status = tk.StringVar(value='Ready | No network traffic sent')
        self.scope_text = tk.StringVar(value='Unscoped manual assessment')
        self.counts = tk.StringVar()
        self.review_status = tk.StringVar(value=REVIEW_STATUSES[0])
        self._style()
        self._build()
        self._refresh_catalog()
        self.poll_id = self.root.after(100, self._poll)

    def _style(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use('clam')
        style.configure('.', font=('Segoe UI', 10), background='#eef1f3', foreground='#20282c')
        style.configure('Title.TLabel', font=('Segoe UI Semibold', 24), foreground='#146c59')
        style.configure('Subtitle.TLabel', foreground='#505d64')
        style.configure('Scope.TLabel', font=('Segoe UI Semibold', 10))
        style.configure('TButton', padding=(12, 7))
        style.configure('Toolbar.TButton', padding=(5, 7))
        style.configure('Primary.TButton', background='#146c59', foreground='white')
        style.map('Primary.TButton', background=[('active', '#0d5646'), ('disabled', '#c5cdd0')])
        style.configure('Treeview', background='white', fieldbackground='white', rowheight=29)
        style.configure('Treeview.Heading', font=('Segoe UI Semibold', 10), padding=6)
        style.map('Treeview', background=[('selected', '#d2e8e2')], foreground=[('selected', '#133c31')])
        style.configure('TNotebook.Tab', padding=(16, 8))

    def _build(self) -> None:
        shell = ttk.Frame(self.root, padding=20)
        shell.pack(fill='both', expand=True)
        ttk.Label(shell, text='EtherNet/IP', style='Title.TLabel').pack(anchor='w')
        ttk.Label(shell, text='ICS / OT   |   Security Assessment Workbench',
                  style='Subtitle.TLabel').pack(anchor='w', pady=(0, 15))

        scope = ttk.Frame(shell)
        scope.pack(fill='x')
        scope.columnconfigure(1, weight=1)
        scope.columnconfigure(3, weight=3)
        ttk.Label(scope, text='Target IPv4').grid(row=0, column=0, sticky='w', padx=(0, 8))
        self.target_entry = ttk.Entry(scope, textvariable=self.target, width=18)
        self.target_entry.grid(row=0, column=1, sticky='ew', padx=(0, 16))
        ttk.Label(scope, text='Operator / scope reference').grid(row=0, column=2, padx=(0, 8))
        self.operator_entry = ttk.Entry(scope, textvariable=self.operator)
        self.operator_entry.grid(row=0, column=3, sticky='ew')
        self.auth_check = ttk.Checkbutton(shell, text='I am authorized to assess this target within an approved maintenance window.',
                                          variable=self.authorized)
        self.auth_check.pack(anchor='w', pady=10)

        toolbar = ttk.Frame(shell)
        toolbar.pack(fill='x', pady=(0, 12))
        self.probe_button = ttk.Button(toolbar, text='Probe identity', style='Toolbar.TButton', command=self.start_probe)
        self.probe_button.pack(side='left')
        self.suite_button = ttk.Button(toolbar, text='Run live suite', style='Toolbar.TButton', command=self.start_suite)
        self.suite_button.pack(side='left', padx=(4, 0))
        self.stop_button = ttk.Button(toolbar, text='Stop', style='Toolbar.TButton', command=self.stop_suite, state='disabled')
        self.stop_button.pack(side='left', padx=(4, 0))
        self.new_button = ttk.Button(toolbar, text='New assessment', style='Toolbar.TButton', command=self.new_assessment)
        self.new_button.pack(side='left', padx=4)
        self.sample_button = ttk.Button(toolbar, text='Load sample', style='Toolbar.TButton', command=self.load_sample)
        self.sample_button.pack(side='left')
        self.surface_button = ttk.Button(toolbar, text='Attack surface', style='Toolbar.TButton', command=self.show_surface)
        self.surface_button.pack(side='left', padx=(4, 0))
        self.export_button = ttk.Button(toolbar, text='Export JSON', style='Toolbar.TButton', command=self.export_report)
        self.export_button.pack(side='right')

        ttk.Separator(shell).pack(fill='x', pady=(0, 10))
        ttk.Label(shell, textvariable=self.scope_text, style='Scope.TLabel', wraplength=760).pack(anchor='w')
        ttk.Label(shell, textvariable=self.counts, style='Subtitle.TLabel').pack(anchor='w', pady=(4, 10))
        panes = ttk.Panedwindow(shell, orient='horizontal')
        panes.pack(fill='both', expand=True)
        self.live_tab = ttk.Frame(panes, padding=10)
        log_panel = ttk.Frame(panes, padding=10)
        panes.add(self.live_tab, weight=1)
        panes.add(log_panel, weight=1)
        self.live_tab.columnconfigure(0, weight=1)
        self.live_tab.rowconfigure(1, weight=1)
        live_heading = ttk.Frame(self.live_tab)
        live_heading.grid(row=0, column=0, sticky='ew', pady=(0, 8))
        ttk.Label(live_heading, text='Live tests & coverage', style='Scope.TLabel').pack(anchor='w')
        ttk.Label(live_heading, text='Ctrl+click or Shift+click to select multiple tests',
                  style='Subtitle.TLabel').pack(anchor='w')
        live_actions = ttk.Frame(live_heading)
        live_actions.pack(fill='x', pady=(6, 0))
        self.selected_button = ttk.Button(live_actions, text='Run selected', command=self.start_selected)
        self.selected_button.pack(side='left')
        self.fuzz_button = ttk.Button(live_actions, text='Run fuzz tests', command=self.start_fuzz)
        self.fuzz_button.pack(side='left', padx=(6, 0))
        self.live_tree = ttk.Treeview(self.live_tab, columns=('title', 'status'), show='headings',
                                      height=9, selectmode='extended')
        self.live_tree.heading('title', text='Test / coverage area')
        self.live_tree.heading('status', text='Execution status')
        self.live_tree.column('title', width=190, minwidth=100)
        self.live_tree.column('status', width=135, minwidth=95, stretch=False)
        self.live_tree.grid(row=1, column=0, sticky='nsew')
        live_scroll = ttk.Scrollbar(self.live_tab, command=self.live_tree.yview)
        live_scroll.grid(row=1, column=1, sticky='ns')
        self.live_tree.configure(yscrollcommand=live_scroll.set)
        self.live_details = ScrolledText(self.live_tab, width=35, height=10, wrap='word', font=('Consolas', 10), relief='flat')
        self.live_details.grid(row=2, column=0, columnspan=2, sticky='ew', pady=(10, 0))
        self.live_tree.bind('<<TreeviewSelect>>', self._select_live_test)
        self._render_live()

        log_panel.columnconfigure(0, weight=1)
        log_panel.rowconfigure(1, weight=1)
        ttk.Label(log_panel, text='Live Logs', style='Scope.TLabel').grid(row=0, column=0, sticky='w', pady=(0, 8))
        self.inventory = ScrolledText(log_panel, width=35, wrap='word', font=('Consolas', 10),
                                     relief='flat', padx=12, pady=12)
        self.inventory.grid(row=1, column=0, sticky='nsew')
        self._set_text(self.inventory, 'Ready | No network traffic sent.')

        self.surface_window = tk.Toplevel(self.root)
        self.surface_window.title('Attack surface')
        self.surface_window.geometry('900x650')
        self.surface_window.minsize(700, 500)
        self.surface_window.protocol('WM_DELETE_WINDOW', self.surface_window.withdraw)
        self.surface_window.withdraw()
        surface_tab = ttk.Frame(self.surface_window, padding=10)
        surface_tab.pack(fill='both', expand=True)
        surface_tab.columnconfigure(0, weight=1)
        surface_tab.rowconfigure(0, weight=3)
        self.catalog = ttk.Treeview(surface_tab, columns=('title', 'risk', 'review'), show='headings', height=7)
        for column, heading, width in (('title', 'Assessment area', 430), ('risk', 'Potential impact', 115),
                                       ('review', 'Review status', 150)):
            self.catalog.heading(column, text=heading)
            self.catalog.column(column, width=width, minwidth=90, stretch=column == 'title')
        self.catalog.grid(row=0, column=0, sticky='nsew')
        catalog_scroll = ttk.Scrollbar(surface_tab, command=self.catalog.yview)
        catalog_scroll.grid(row=0, column=1, sticky='ns')
        self.catalog.configure(yscrollcommand=catalog_scroll.set)
        self.catalog.bind('<<TreeviewSelect>>', self._select_surface)
        self.details = ScrolledText(surface_tab, height=7, wrap='word', font=('Segoe UI', 10),
                                    relief='flat', background='#f6f8f9', padx=10, pady=8)
        self.details.grid(row=1, column=0, columnspan=2, sticky='nsew', pady=8)
        self.details.configure(state='disabled')
        review_bar = ttk.Frame(surface_tab)
        review_bar.grid(row=2, column=0, columnspan=2, sticky='ew')
        ttk.Label(review_bar, text='Operator decision').pack(side='left', padx=(0, 8))
        self.review_combo = ttk.Combobox(review_bar, textvariable=self.review_status, values=REVIEW_STATUSES,
                                         state='readonly', width=20)
        self.review_combo.pack(side='left')
        self.save_button = ttk.Button(review_bar, text='Save review', command=self.save_review)
        self.save_button.pack(side='right')
        ttk.Label(surface_tab, text='Evidence / rationale').grid(row=3, column=0, sticky='w', pady=(8, 3))
        self.notes = ScrolledText(surface_tab, height=3, wrap='word', font=('Segoe UI', 10), relief='flat')
        self.notes.grid(row=4, column=0, columnspan=2, sticky='ew')
        ttk.Label(shell, textvariable=self.status, style='Subtitle.TLabel', wraplength=760).pack(anchor='w', pady=(10, 0))
        self.controls = (self.target_entry, self.operator_entry, self.auth_check, self.probe_button,
                         self.new_button, self.sample_button, self.export_button, self.save_button, self.suite_button,
                         self.fuzz_button, self.selected_button)

    def show_surface(self) -> None:
        self.surface_window.deiconify()
        self.surface_window.lift()

    def _render_live(self) -> None:
        results = {item['id']: item for item in self.live_run['test_results']} if self.live_run else {}
        for item in coverage_matrix():
            result = results.get(item['id'])
            status = result['status'] if result else ('not_run' if item['coverage'] in ('implemented_live_read_only', 'implemented_live_fuzz') else item['coverage'])
            values = (f"{item['id']}  {item['area']}", status)
            if self.live_tree.exists(item['id']):
                self.live_tree.item(item['id'], values=values)
            else:
                self.live_tree.insert('', 'end', iid=item['id'], values=values)
        self._set_text(self.live_details, 'No live suite run in this assessment.' if not self.live_run else
                       f"Suite: {self.live_run['outcome']}\nRequests: {len(self.live_run['exchanges'])} / {self.live_run['limits']['max_requests']}\n"
                       f"Stop reason: {self.live_run['stop_reason']}\nEvidence SHA-256: {self.live_run['evidence_sha256']}")
        if self.live_run and self.live_tree.selection():
            self._select_live_test()

    def _select_live_test(self, _event=None) -> None:
        selected = self.live_tree.selection()
        if not selected:
            return
        focused = self.live_tree.focus()
        identifier = focused if focused in selected else selected[0]
        item = next(item for item in coverage_matrix() if item['id'] == identifier)
        detail = {'coverage': item}
        if self.live_run:
            result = next((result for result in self.live_run['test_results'] if result['id'] == identifier), None)
            if result:
                detail['result'] = result
                detail['exchanges'] = [self.live_run['exchanges'][index] for index in result['exchange_indices']]
        self._set_text(self.live_details, json.dumps(detail, indent=2))

    @staticmethod
    def _set_text(widget: ScrolledText, text: str) -> None:
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        widget.insert('1.0', text)
        widget.configure(state='disabled')

    def _append_log(self, text: str) -> None:
        self.inventory.configure(state='normal')
        if self.inventory.get('1.0', 'end-1c'):
            self.inventory.insert('end', '\n\n')
        self.inventory.insert('end', text)
        self.inventory.see('end')
        self.inventory.configure(state='disabled')

    def _refresh_catalog(self) -> None:
        for entry in self.assessment.catalog():
            values = (f"{entry['identifier']}  {entry['title']}", entry['potential_impact'], entry['status'])
            if self.catalog.exists(entry['identifier']):
                self.catalog.item(entry['identifier'], values=values)
            else:
                self.catalog.insert('', 'end', iid=entry['identifier'], values=values)
        reviews = list(self.assessment.reviews.values())
        reviewed = sum(review['status'] != 'Not assessed' for review in reviews)
        findings = sum(review['status'] == 'Finding recorded' for review in reviews)
        self.counts.set(f'{len(self.identities)} identity items    |    {reviewed} / {len(SURFACES)} areas reviewed'
                        f'    |    {findings} operator-recorded findings')

    def _select_surface(self, _event=None) -> None:
        selection = self.catalog.selection()
        if not selection:
            return
        if selection[0] == self.selected:
            return
        if self.selected and self._has_unsaved_review():
            if not messagebox.askyesno('Unsaved review',
                                      'Discard the unsaved review and switch areas?', parent=self.root):
                self.catalog.selection_set(self.selected)
                return
        self.selected = selection[0]
        surface = next(item for item in SURFACES if item.identifier == self.selected)
        self._set_text(self.details, f'{surface.plane}\n{surface.method}\n\n'
                       f'Exposure: {surface.exposure}\n\nVerification: {surface.verification}\n\n'
                       f'Mitigation: {surface.mitigation}')
        review = self.assessment.reviews.get(self.selected, {'status': 'Not assessed', 'evidence': ''})
        self.review_status.set(review['status'])
        self.notes.delete('1.0', 'end')
        self.notes.insert('1.0', review['evidence'])

    def _has_unsaved_review(self) -> bool:
        if not self.selected:
            return False
        saved = self.assessment.reviews.get(self.selected, {'status': 'Not assessed', 'evidence': ''})
        return (self.review_status.get(), self.notes.get('1.0', 'end').strip()) != (saved['status'], saved['evidence'])

    def _read_scope(self) -> tuple[str, str]:
        target = validate_target(self.target.get())
        operator = self.operator.get().strip()
        if not operator:
            raise ValueError('Enter an operator name and scope/ticket reference.')
        return target, operator

    def _ensure_scope(self) -> None:
        target, operator = self._read_scope()
        if self.scope_target is None:
            self.scope_target, self.scope_operator = target, operator
            self.scope_text.set(f'MANUAL | {target} | {operator}')
        elif (target, operator) != (self.scope_target, self.scope_operator):
            raise ValueError('Scope changed. Start a new assessment before saving or exporting evidence.')

    def _confirm_replace(self) -> bool:
        if self.live_run or self.assessment.reviews or self.identities or self.notes.get('1.0', 'end').strip():
            return messagebox.askyesno('Replace assessment',
                                      'Replace the current evidence and reviews? Export or save any needed notes first.', parent=self.root)
        return True

    def _reset(self, target: str, operator: str, mode: str, outcome: str, authorized: bool = False) -> None:
        self.assessment = SecurityAssessment()
        self.identities = []
        self.live_run = None
        self._render_live()
        self.scope_target, self.scope_operator = target, operator
        self.scope_authorized = authorized
        self.mode, self.outcome = mode, outcome
        self.observed_at = None
        self.selected = None
        self.scope_text.set(f'{mode.upper()} | {target} | {operator}')
        self._set_text(self.inventory, f'{mode.upper()} | {target}\n{outcome}')
        self.notes.delete('1.0', 'end')
        self.review_status.set('Not assessed')
        self._refresh_catalog()
        self._select_surface()

    def new_assessment(self) -> None:
        if self.busy:
            return
        try:
            target, operator = self._read_scope()
        except ValueError as exc:
            messagebox.showerror('Scope required', str(exc), parent=self.root)
            return
        if self._confirm_replace():
            self._reset(target, operator, 'manual', 'No active probe performed.')
            self.status.set('New manual assessment | No network traffic sent')

    def load_sample(self) -> None:
        if self.busy or not self._confirm_replace():
            return
        self.target.set('192.0.2.10')
        self.operator.set('SAMPLE / synthetic training dataset')
        self.authorized.set(False)
        self._reset(self.target.get(), self.operator.get(), 'sample', 'Synthetic data; no network request sent.')
        self.identities = [Identity('192.0.2.10', 44818, 1, 0, 14, 0, '1.0', 0,
                                    '00000000', 'SAMPLE - training controller', 3)]
        self._refresh_catalog()
        self._render_inventory()
        self.status.set('SAMPLE DATA | Not evidence from a real device')

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        for control in self.controls:
            control.configure(state='disabled' if busy else 'normal')
        if not busy:
            self.stop_button.configure(state='disabled')

    def start_selected(self) -> None:
        if self.busy:
            return
        selected = self.live_tree.selection()
        if not selected:
            messagebox.showinfo('Select a test', 'Select one or more executable tests from the list first.', parent=self.root)
            return
        matrix = {item['id']: item for item in coverage_matrix()}
        invalid = [identifier for identifier in selected
                   if matrix[identifier]['coverage'] not in ('implemented_live_read_only', 'implemented_live_fuzz')]
        if invalid:
            messagebox.showinfo('Tests not executable',
                                'Deselect coverage, manual-review or excluded rows before running: '
                                + ', '.join(invalid), parent=self.root)
            return
        kinds = {matrix[identifier]['coverage'] for identifier in selected}
        if len(kinds) == 2:
            self.start_mixed(selected)
        elif 'implemented_live_read_only' in kinds:
            self.start_suite(selected)
        else:
            self.start_fuzz(selected)

    def start_suite(self, case_ids: tuple[str, ...] | None = None) -> None:
        if self.busy:
            return
        try:
            target, operator = self._read_scope()
            if not self.authorized.get():
                raise ValueError('Authorization attestation is required before live testing.')
        except ValueError as exc:
            messagebox.showerror('Live tests blocked', str(exc), parent=self.root)
            return
        description = (f'Run selected tests {", ".join(case_ids)}' if case_ids else 'Run the bounded baseline')
        limits = 'Up to 12 requests, one session, Identity attributes 1-7; no writes. '
        if not messagebox.askyesno('Confirm live device tests',
                                  f'{description} against {target}:44818/TCP?\n\n'
                                  f'{limits}'
                                  'Read-only traffic can still disrupt fragile devices. Confirm approved '
                                  'maintenance conditions and recovery arrangements. Current evidence is replaced.', parent=self.root):
            return
        self._reset(target, operator, 'live', f'{"Selected tests" if case_ids else "Live suite"} in progress.', authorized=True)
        self.cancel_run = threading.Event()
        self.observed_at = datetime.now(timezone.utc).isoformat()
        self._set_busy(True)
        self.stop_button.configure(state='normal')
        self.status.set(f'{"Selected tests" if case_ids else "Live suite"} running | No automatic retries')
        threading.Thread(target=self._suite_worker, args=(target, operator, self.cancel_run, False, case_ids),
                         daemon=True).start()

    def start_fuzz(self, case_ids: tuple[str, ...] | None = None) -> None:
        if self.busy:
            return
        try:
            target, operator = self._read_scope()
            if not self.authorized.get():
                raise ValueError('Authorization attestation is required before fuzz testing.')
        except ValueError as exc:
            messagebox.showerror('Fuzz tests blocked', str(exc), parent=self.root)
            return
        if not messagebox.askyesno(
            'Confirm active fuzz testing',
            f'Send {"fuzz cases " + ", ".join(case_ids) if case_ids else "malformed and boundary CIP requests"} '
            f'to {target}:44818/TCP?\n\n'
            'Fuzzing can crash a device or affect the physical process. Confirm this exact test is authorized, '
            'the maintenance window and recovery plan are in place, and the target is safe to test. '
            'Up to 30 requests including session setup and cleanup, '
            'at least 1 second apart; no retries. Current evidence is replaced.',
            parent=self.root,
        ):
            return
        self._reset(target, operator, 'live', f'{"Selected fuzz tests" if case_ids else "Fuzz suite"} in progress.', authorized=True)
        self.cancel_run = threading.Event()
        self.observed_at = datetime.now(timezone.utc).isoformat()
        self._set_busy(True)
        self.stop_button.configure(state='normal')
        self.status.set(f'{"Selected fuzz tests" if case_ids else "Fuzz suite"} running | No automatic retries')
        threading.Thread(target=self._suite_worker, args=(target, operator, self.cancel_run, True, case_ids),
                         daemon=True).start()

    def start_mixed(self, case_ids: tuple[str, ...]) -> None:
        if self.busy:
            return
        try:
            target, operator = self._read_scope()
            if not self.authorized.get():
                raise ValueError('Authorization attestation is required before live testing.')
        except ValueError as exc:
            messagebox.showerror('Live tests blocked', str(exc), parent=self.root)
            return
        if not messagebox.askyesno(
            'Confirm selected tests',
            f'Run {", ".join(case_ids)} against {target}:44818/TCP?\n\n'
            'The read-only phase runs first, followed by fuzzing only if it completes. '
            'Up to 42 requests and two sessions; no retries. Current evidence is replaced.',
            parent=self.root,
        ):
            return
        if not messagebox.askyesno(
            'Confirm active fuzz testing',
            'The selection includes fuzz tests. Fuzzing can crash a device or affect the physical process. '
            'Confirm the selected fuzz tests are authorized and the maintenance window and recovery plan are in place.',
            parent=self.root,
        ):
            return
        self._reset(target, operator, 'live', 'Selected mixed tests in progress.', authorized=True)
        self.cancel_run = threading.Event()
        self.observed_at = datetime.now(timezone.utc).isoformat()
        self._set_busy(True)
        self.stop_button.configure(state='normal')
        self.status.set('Selected mixed tests running | Read-only phase first; no automatic retries')
        threading.Thread(target=self._suite_worker, args=(target, operator, self.cancel_run, False, case_ids, True),
                         daemon=True).start()

    def stop_suite(self) -> None:
        self.cancel_run.set()
        self.stop_button.configure(state='disabled')
        self.status.set('Stop requested | Current request may finish; session cleanup is still attempted')
        self._append_log(self.status.get())

    def close_window(self) -> None:
        if self.busy:
            if not self.closing and messagebox.askyesno('Active request',
                                                       'Stop the active operation and close after cleanup? '
                                                       'The current assessment will be discarded.', parent=self.root):
                self.closing = True
                self.stop_suite()
            return
        if self.live_run or self.assessment.reviews or self.identities or self._has_unsaved_review():
            if not messagebox.askyesno('Close assessment', 'Close and discard the current in-memory assessment?', parent=self.root):
                return
        self.root.destroy()

    def _suite_worker(self, target: str, operator: str, cancel: threading.Event,
                      fuzz: bool = False, case_ids: tuple[str, ...] | None = None,
                      mixed: bool = False) -> None:
        try:
            progress = lambda message: self.events.put(('progress', message))
            if mixed:
                if case_ids is None:
                    raise ValueError('Mixed runs require selected test IDs.')
                run = SelectedTestRunner().run(target, operator, True, case_ids, cancel,
                                               fuzz_authorized=True, progress=progress)
            elif fuzz:
                run = FuzzTestRunner().run(target, operator, True, cancel, fuzz_authorized=True,
                                           progress=progress, case_ids=case_ids)
            else:
                run = LiveTestRunner().run(target, operator, True, cancel, progress=progress, case_ids=case_ids)
            self.events.put(('suite', run))
        except Exception as exc:
            self.events.put(('suite_error', str(exc)))

    def _cancel_poll(self) -> None:
        if self.poll_id is not None:
            self.root.after_cancel(self.poll_id)
            self.poll_id = None

    def _on_destroy(self, event) -> None:
        if event.widget is self.root:
            self._cancel_poll()

    def start_probe(self) -> None:
        if self.busy:
            return
        try:
            target, operator = self._read_scope()
            if not self.authorized.get():
                raise ValueError('Authorization attestation is required before sending traffic.')
        except ValueError as exc:
            messagebox.showerror('Probe blocked', str(exc), parent=self.root)
            return
        if not messagebox.askyesno('Confirm authorized ICS request',
                                  f'Send one ListIdentity request to {target}:44818/TCP?\n\n'
                                  'Read-only traffic is not risk-free for fragile ICS devices. '
                                  'Confirm the approved scope, maintenance window and recovery plan. '
                                  'This replaces the current evidence and reviews.', parent=self.root):
            return
        self._reset(target, operator, 'live', 'Probe in progress.', authorized=True)
        self.observed_at = datetime.now(timezone.utc).isoformat()
        self._set_busy(True)
        self.status.set(f'Awaiting {target}:44818 | One request, no retries, 3-second deadline')
        threading.Thread(target=self._probe_worker, args=(target,), daemon=True).start()

    def _probe_worker(self, target: str) -> None:
        try:
            self.events.put(('success', Discovery().discover(target)))
        except Exception as exc:
            self.events.put(('error', str(exc)))

    def _poll(self) -> None:
        self._cancel_poll()
        while True:
            try:
                kind, result = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == 'progress':
                self._append_log(result)
                continue
            self._set_busy(False)
            if kind == 'suite':
                self.live_run = result
                self.identities = [Identity(**item) for item in result['identities']]
                self.observed_at = result['started_at_utc']
                self.outcome = f"Live suite {result['outcome']} | {result['stop_reason'] or 'Review per-test results; no automatic vulnerability verdict.'}"
                self._render_live()
            elif kind == 'success':
                self.identities = result
                self.outcome = ('Identity response received.' if result else
                                'Response contained no identity items; inconclusive.')
            elif kind == 'suite_error':
                self.outcome = f'Suite failed; inconclusive: {result}'
            else:
                self.outcome = f'Probe failed; inconclusive: {result}'
            self.status.set(self.outcome)
            self._refresh_catalog()
            self._render_inventory()
            if self.closing:
                self.root.destroy()
                return
        self.poll_id = self.root.after(100, self._poll)

    def _render_inventory(self) -> None:
        lines = [f'{self.mode.upper()} | {self.scope_target}', self.outcome, '']
        if self.mode == 'sample':
            lines.append('SYNTHETIC DATA - not device evidence\n')
        for index, identity in enumerate(self.identities, 1):
            lines.append(f'Identity item {index}')
            for name, value in asdict(identity).items():
                lines.append(f'  {name.replace("_", " "):20} {value!s}')
            lines.append('')
        for observation in self.assessment.observations(self.identities):
            lines.extend([observation['classification'], observation['summary'], observation['limits'], ''])
        if not self.identities:
            lines.append('No identity evidence. This does not establish that the target is secure.')
        self._append_log('\n'.join(lines))

    def save_review(self) -> None:
        if self.busy:
            return
        if not self.selected:
            messagebox.showinfo('Select an area', 'Select an assessment area first.', parent=self.root)
            return
        try:
            self._ensure_scope()
            self.assessment.record_review(self.selected, self.review_status.get(), self.notes.get('1.0', 'end'))
        except ValueError as exc:
            messagebox.showerror('Review not saved', str(exc), parent=self.root)
            return
        self._refresh_catalog()
        self.status.set(f'{self.selected} review saved | Operator-supplied decision')

    def build_report(self) -> dict:
        self._ensure_scope()
        target, operator = self._read_scope()
        return ReportGenerator().build(target, operator, self.scope_authorized,
                                       self.mode, self.outcome, self.identities, self.assessment, self.observed_at,
                                       live_run=self.live_run)

    def export_report(self) -> None:
        if self.busy:
            return
        if self._has_unsaved_review():
            messagebox.showwarning('Unsaved review', 'Save the current review before exporting.', parent=self.root)
            return
        try:
            report = self.build_report()
        except ValueError as exc:
            messagebox.showerror('Export blocked', str(exc), parent=self.root)
            return
        path = filedialog.asksaveasfilename(parent=self.root, defaultextension='.json',
                                          filetypes=[('JSON report', '*.json')],
                                          initialfile=f'ethernet-ip-{self.mode}-{self.scope_target}.json')
        if path:
            try:
                ReportGenerator().save(path, report)
            except OSError as exc:
                messagebox.showerror('Export failed', str(exc), parent=self.root)
                return
            self.status.set(f'Report exported | {path}')


def launch() -> None:
    root = tk.Tk()
    AssessmentApp(root)
    root.mainloop()