"""Tkinter 대화상자: 계정 설정, 최근 사건, 정보. 모두 UI(메인) 스레드에서만 생성한다."""

from __future__ import annotations

import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable

from .. import APP_DISPLAY_NAME, VERSION
from .. import autostart, providers
from ..auth import AuthError, Authenticator, CredentialStore, GoogleOAuth
from ..monitor import FetchedMessage, test_connection
from ..scanner import Evidence, local_timestamp, local_timezone_label
from ..store import AUTH_APP_PASSWORD, AUTH_OAUTH, FOLDER_AUTO_SENT, AccountSettings, IncidentLog, Settings

Dispatch = Callable[[Callable[[], None]], None]  # 워커 스레드 → UI 스레드
# (폴더, UID) -> (원본 메일, 지금 규칙 근거, 당시 규칙 재현 근거). 워커 스레드에서 호출한다.
EvidenceResult = tuple[FetchedMessage, list[Evidence], list[Evidence]]
EvidenceSource = Callable[[str, int], EvidenceResult]


class _OverrideStore(CredentialStore):
    """연결 테스트용: 입력란의 비밀번호를 우선 사용하고 없으면 저장된 값을 쓴다."""

    def __init__(self, password: str) -> None:
        self._password = password.strip()

    def get_app_password(self, email: str) -> str | None:
        if self._password:
            return self._password.replace(" ", "").replace("-", "")
        return super().get_app_password(email)


class AccountDialog(tk.Toplevel):
    def __init__(
        self,
        master: tk.Misc,
        settings: Settings,
        store: CredentialStore,
        oauth: GoogleOAuth,
        dispatch: Dispatch,
        on_saved: Callable[[Settings], None],
    ) -> None:
        super().__init__(master)
        self.title(f"{APP_DISPLAY_NAME} - 계정 설정")
        self.resizable(False, False)
        self.attributes("-topmost", True)
        self._settings = settings
        self._store = store
        self._oauth = oauth
        self._dispatch = dispatch
        self._on_saved = on_saved
        account = settings.account

        self.var_email = tk.StringVar(value=account.email)
        self.var_provider = tk.StringVar(value="")
        self.var_auth = tk.StringVar(value=account.auth_method)
        self.var_password = tk.StringVar(value="")
        self.var_host = tk.StringVar(value=account.imap_host)
        self.var_port = tk.StringVar(value=str(account.imap_port))
        self.var_inbox = tk.BooleanVar(value="INBOX" in account.folders)
        self.var_sent = tk.BooleanVar(value=FOLDER_AUTO_SENT in account.folders)
        self.var_extra = tk.StringVar(value=", ".join(f for f in account.folders if f not in ("INBOX", FOLDER_AUTO_SENT)))
        self.var_autostart = tk.BooleanVar(value=settings.autostart)
        self.var_notify_safe = tk.BooleanVar(value=settings.notify_safe_mail)
        self.var_notify_medium = tk.BooleanVar(value=settings.notify_medium_mail)
        self.var_oauth_status = tk.StringVar(value="")
        self.var_message = tk.StringVar(value="")

        self._build()
        self._on_email_changed()
        self._refresh_oauth_status()
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.after(50, self._center)

    # --- 레이아웃 ---
    def _build(self) -> None:
        pad = {"padx": 8, "pady": 4}
        frame = ttk.Frame(self, padding=12)
        frame.grid(row=0, column=0, sticky="nsew")

        ttk.Label(frame, text="이메일 주소").grid(row=0, column=0, sticky="w", **pad)
        email_entry = ttk.Entry(frame, textvariable=self.var_email, width=40)
        email_entry.grid(row=0, column=1, columnspan=2, sticky="we", **pad)
        email_entry.bind("<KeyRelease>", lambda _e: self._on_email_changed())
        ttk.Label(frame, textvariable=self.var_provider, foreground="#555").grid(row=1, column=1, columnspan=2, sticky="w", padx=8)

        ttk.Label(frame, text="인증 방식").grid(row=2, column=0, sticky="nw", **pad)
        auth_box = ttk.Frame(frame)
        auth_box.grid(row=2, column=1, columnspan=2, sticky="we", **pad)
        self.radio_oauth = ttk.Radiobutton(auth_box, text="Google 로그인 (OAuth, 권장)", value=AUTH_OAUTH, variable=self.var_auth, command=self._on_auth_changed)
        self.radio_oauth.grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(auth_box, text="앱 비밀번호", value=AUTH_APP_PASSWORD, variable=self.var_auth, command=self._on_auth_changed).grid(row=1, column=0, sticky="w")

        # OAuth 영역
        self.oauth_frame = ttk.LabelFrame(frame, text="Google 로그인", padding=8)
        self.oauth_frame.grid(row=3, column=0, columnspan=3, sticky="we", **pad)
        ttk.Label(self.oauth_frame, textvariable=self.var_oauth_status).grid(row=0, column=0, sticky="w")
        self.btn_oauth = ttk.Button(self.oauth_frame, text="Google 로그인...", command=self._start_oauth)
        self.btn_oauth.grid(row=0, column=1, padx=6)
        self.btn_client = ttk.Button(self.oauth_frame, text="OAuth 클라이언트 파일 선택...", command=self._pick_client_file)
        self.btn_client.grid(row=0, column=2, padx=6)

        # 앱 비밀번호 영역
        self.password_frame = ttk.LabelFrame(frame, text="앱 비밀번호", padding=8)
        self.password_frame.grid(row=4, column=0, columnspan=3, sticky="we", **pad)
        ttk.Entry(self.password_frame, textvariable=self.var_password, show="•", width=32).grid(row=0, column=0, sticky="w")
        self.lbl_password_hint = ttk.Label(self.password_frame, text="", foreground="#1a73e8", cursor="hand2")
        self.lbl_password_hint.grid(row=0, column=1, sticky="w", padx=8)
        ttk.Label(self.password_frame, text="비워 두면 저장된 값을 유지합니다. 일반 계정 비밀번호는 입력하지 마십시오.", foreground="#555").grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))

        ttk.Label(frame, text="IMAP 서버").grid(row=5, column=0, sticky="w", **pad)
        ttk.Entry(frame, textvariable=self.var_host, width=28).grid(row=5, column=1, sticky="w", **pad)
        port_box = ttk.Frame(frame)
        port_box.grid(row=5, column=2, sticky="w")
        ttk.Label(port_box, text="포트").pack(side="left")
        ttk.Entry(port_box, textvariable=self.var_port, width=6).pack(side="left", padx=4)

        ttk.Label(frame, text="감시 폴더").grid(row=6, column=0, sticky="nw", **pad)
        folder_box = ttk.Frame(frame)
        folder_box.grid(row=6, column=1, columnspan=2, sticky="we", **pad)
        ttk.Checkbutton(folder_box, text="받은편지함 (INBOX)", variable=self.var_inbox).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(folder_box, text="보낸편지함 (자동 탐색)", variable=self.var_sent).grid(row=1, column=0, sticky="w")
        extra_box = ttk.Frame(folder_box)
        extra_box.grid(row=2, column=0, sticky="we", pady=(4, 0))
        ttk.Label(extra_box, text="추가 폴더(쉼표 구분)").pack(side="left")
        ttk.Entry(extra_box, textvariable=self.var_extra, width=28).pack(side="left", padx=4)

        ttk.Label(frame, text="옵션").grid(row=7, column=0, sticky="nw", **pad)
        option_box = ttk.Frame(frame)
        option_box.grid(row=7, column=1, columnspan=2, sticky="we", **pad)
        ttk.Checkbutton(option_box, text="Windows 시작 시 자동 실행", variable=self.var_autostart).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(option_box, text="'주의' 등급(연락처·주소·실명 등) 알림 표시", variable=self.var_notify_medium).grid(row=1, column=0, sticky="w")
        ttk.Checkbutton(option_box, text="정상 메일도 알림 표시", variable=self.var_notify_safe).grid(row=2, column=0, sticky="w")

        ttk.Label(frame, textvariable=self.var_message, foreground="#B3261E", wraplength=440, justify="left").grid(row=8, column=0, columnspan=3, sticky="w", **pad)

        buttons = ttk.Frame(frame)
        buttons.grid(row=9, column=0, columnspan=3, sticky="e", pady=(8, 0))
        self.btn_test = ttk.Button(buttons, text="연결 테스트", command=self._test)
        self.btn_test.pack(side="left", padx=4)
        self.btn_save = ttk.Button(buttons, text="저장", command=self._save)
        self.btn_save.pack(side="left", padx=4)
        ttk.Button(buttons, text="취소", command=self.destroy).pack(side="left", padx=4)

        self._on_auth_changed()

    def _center(self) -> None:
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"+{x}+{y}")
        self.lift()
        self.focus_force()

    # --- 이벤트 ---
    def _on_email_changed(self) -> None:
        email = self.var_email.get().strip()
        provider = providers.detect(email)
        if provider:
            self.var_provider.set(f"공급자: {provider.display}")
            if not self.var_host.get().strip() or self.var_host.get().strip() != provider.imap_host:
                self.var_host.set(provider.imap_host)
                self.var_port.set(str(provider.imap_port))
            self.radio_oauth.configure(state="normal" if provider.supports_oauth else "disabled")
            if not provider.supports_oauth and self.var_auth.get() == AUTH_OAUTH:
                self.var_auth.set(AUTH_APP_PASSWORD)
            if provider.help_url:
                self.lbl_password_hint.configure(text="앱 비밀번호 발급 안내")
                self.lbl_password_hint.bind("<Button-1>", lambda _e, url=provider.help_url: webbrowser.open(url))
            else:
                self.lbl_password_hint.configure(text="")
        else:
            self.var_provider.set("공급자: 알 수 없음 (IMAP 서버를 직접 확인하십시오)" if "@" in email else "")
            if "@" in email and not self.var_host.get().strip():
                self.var_host.set(providers.guess_host(email))
            self.radio_oauth.configure(state="disabled")
            if self.var_auth.get() == AUTH_OAUTH:
                self.var_auth.set(AUTH_APP_PASSWORD)
            self.lbl_password_hint.configure(text="")
        self._on_auth_changed()

    def _on_auth_changed(self) -> None:
        oauth = self.var_auth.get() == AUTH_OAUTH
        for child in self.oauth_frame.winfo_children():
            child.configure(state="normal" if oauth else "disabled")
        for child in self.password_frame.winfo_children():
            if isinstance(child, ttk.Entry):
                child.configure(state="disabled" if oauth else "normal")
        self._refresh_oauth_status()

    def _refresh_oauth_status(self) -> None:
        email = self.var_email.get().strip()
        if not self._oauth.has_client():
            self.var_oauth_status.set("OAuth 클라이언트 파일이 없습니다.")
            self.btn_client.grid()
        else:
            self.btn_client.grid_remove()
            creds = self._oauth.load(email) if email else None
            self.var_oauth_status.set("로그인됨" if creds and creds.refresh_token else "로그인이 필요합니다.")

    def _pick_client_file(self) -> None:
        path = filedialog.askopenfilename(parent=self, title="Google OAuth 클라이언트 JSON 선택", filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            self._oauth.install_client_file(Path(path))
        except (AuthError, ValueError, OSError) as exception:
            self.var_message.set(str(exception))
            return
        self.var_message.set("")
        self._refresh_oauth_status()

    def _start_oauth(self) -> None:
        email = self.var_email.get().strip()
        if "@" not in email:
            self.var_message.set("이메일 주소를 먼저 입력하십시오.")
            return
        self.var_message.set("브라우저에서 Google 로그인을 완료하십시오...")
        self.btn_oauth.configure(state="disabled")

        def worker() -> None:
            try:
                self._oauth.authorize_interactive(email)
                self._dispatch(lambda: self._oauth_done(None))
            except Exception as exception:  # 사용자 취소, 네트워크, 동의 거부 등
                self._dispatch(lambda: self._oauth_done(str(exception)))

        threading.Thread(target=worker, name="oauth-flow", daemon=True).start()

    def _oauth_done(self, error: str | None) -> None:
        if not self.winfo_exists():
            return
        self.btn_oauth.configure(state="normal")
        self.var_message.set(f"Google 로그인 실패: {error}" if error else "Google 로그인 완료")
        self._refresh_oauth_status()

    def _collect(self) -> Settings | None:
        email = self.var_email.get().strip()
        host = self.var_host.get().strip()
        try:
            port = int(self.var_port.get().strip() or "993")
        except ValueError:
            self.var_message.set("포트는 숫자여야 합니다.")
            return None
        if "@" not in email or not host:
            self.var_message.set("이메일 주소와 IMAP 서버를 입력하십시오.")
            return None
        folders: list[str] = []
        if self.var_inbox.get():
            folders.append("INBOX")
        if self.var_sent.get():
            folders.append(FOLDER_AUTO_SENT)
        folders.extend(f.strip() for f in self.var_extra.get().split(",") if f.strip())
        if not folders:
            self.var_message.set("감시할 폴더를 하나 이상 선택하십시오.")
            return None
        provider = providers.detect(email)
        account = AccountSettings(
            email=email,
            imap_host=host,
            imap_port=port,
            auth_method=self.var_auth.get(),
            folders=folders,
            provider=provider.key if provider else "",
        )
        settings = Settings(
            account=account,
            autostart=self.var_autostart.get(),
            notify_safe_mail=self.var_notify_safe.get(),
            notify_medium_mail=self.var_notify_medium.get(),
            idle_timeout_seconds=self._settings.idle_timeout_seconds,
            catch_up_limit=self._settings.catch_up_limit,
        )
        if account.auth_method == AUTH_APP_PASSWORD and not self.var_password.get().strip() and not self._store.get_app_password(email):
            self.var_message.set("앱 비밀번호를 입력하십시오.")
            return None
        return settings

    def _test(self) -> None:
        settings = self._collect()
        if settings is None:
            return
        self.var_message.set("연결 확인 중...")
        self.btn_test.configure(state="disabled")
        store = _OverrideStore(self.var_password.get())
        authenticator = Authenticator(settings.account, store, self._oauth)

        def worker() -> None:
            report = test_connection(settings, authenticator)
            self._dispatch(lambda: self._test_done(report.ok, report.message))

        threading.Thread(target=worker, name="imap-test", daemon=True).start()

    def _test_done(self, ok: bool, message: str) -> None:
        if not self.winfo_exists():
            return
        self.btn_test.configure(state="normal")
        self.var_message.set(("✔ " if ok else "✘ ") + message)

    def _save(self) -> None:
        settings = self._collect()
        if settings is None:
            return
        email = settings.account.email
        try:
            if settings.account.auth_method == AUTH_APP_PASSWORD and self.var_password.get().strip():
                self._store.set_app_password(email, self.var_password.get())
        except Exception as exception:
            self.var_message.set(f"자격증명 저장 실패: {exception}")
            return
        settings.save()
        try:
            autostart.apply(settings.autostart)
        except OSError as exception:
            messagebox.showwarning(APP_DISPLAY_NAME, f"자동 시작 설정을 변경하지 못했습니다: {exception}", parent=self)
        self._on_saved(settings)
        self.destroy()


class IncidentsWindow(tk.Toplevel):
    def __init__(
        self,
        master: tk.Misc,
        incidents: IncidentLog,
        evidence_source: EvidenceSource | None = None,
        dispatch: Dispatch | None = None,
    ) -> None:
        super().__init__(master)
        self.title(f"{APP_DISPLAY_NAME} - 최근 위험 메일")
        self.geometry("760x400")
        self.attributes("-topmost", True)
        self._incidents = incidents
        self._evidence_source = evidence_source
        self._dispatch = dispatch or (lambda func: func())
        self._rows: dict[str, dict] = {}
        self._detail: IncidentDetailWindow | None = None
        columns = ("time", "folder", "risk", "subject", "findings")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")
        headings = {"time": (f"시각({local_timezone_label()})", 150), "folder": ("폴더", 120), "risk": ("위험", 50), "subject": ("제목(마스킹)", 160), "findings": ("탐지 내용", 260)}
        for key, (text, width) in headings.items():
            self.tree.heading(key, text=text)
            self.tree.column(key, width=width, anchor="w")
        scroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        self.tree.bind("<Double-1>", lambda _e: self.open_detail())
        self.tree.bind("<Return>", lambda _e: self.open_detail())
        hint = ttk.Label(self, text="행을 두 번 누르면 탐지 근거를 원본 메일에서 확인할 수 있습니다.", foreground="#555", padding=(8, 2))
        hint.grid(row=1, column=0, columnspan=2, sticky="w")
        buttons = ttk.Frame(self, padding=6)
        buttons.grid(row=2, column=0, columnspan=2, sticky="e")
        self.var_all = tk.BooleanVar(value=False)
        ttk.Checkbutton(buttons, text="정상 메일 포함", variable=self.var_all, command=self.refresh).pack(side="left", padx=8)
        ttk.Button(buttons, text="탐지 근거 보기", command=self.open_detail).pack(side="left", padx=4)
        ttk.Button(buttons, text="새로 고침", command=self.refresh).pack(side="left", padx=4)
        ttk.Button(buttons, text="기록 지우기", command=self._clear).pack(side="left", padx=4)
        ttk.Button(buttons, text="닫기", command=self.destroy).pack(side="left", padx=4)
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.refresh()

    def open_detail(self) -> None:
        selection = self.tree.selection() or self.tree.focus()
        row_id = selection[0] if isinstance(selection, tuple) and selection else (selection if isinstance(selection, str) else "")
        record = self._rows.get(row_id)
        if record is None:
            messagebox.showinfo(APP_DISPLAY_NAME, "근거를 볼 사건을 목록에서 먼저 선택하십시오.", parent=self)
            return
        if self._detail is not None and self._detail.winfo_exists():
            self._detail.destroy()
        self._detail = IncidentDetailWindow(self, record, self._evidence_source, self._dispatch)

    def refresh(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self._rows.clear()
        for item in self._incidents.recent(limit=200, risky_only=not self.var_all.get()):
            row_id = self.tree.insert(
                "",
                "end",
                values=(
                    local_timestamp(str(item.get("scanned_at", ""))),
                    item.get("folder", ""),
                    {"high": "높음", "medium": "주의"}.get(item.get("risk"), "정상"),
                    item.get("subject", ""),
                    ", ".join(item.get("findings", [])) or "-",
                ),
            )
            self._rows[row_id] = item

    def _clear(self) -> None:
        if messagebox.askyesno(APP_DISPLAY_NAME, "최근 사건 기록을 모두 지우시겠습니까?", parent=self):
            self._incidents.clear()
            self.refresh()


class IncidentDetailWindow(tk.Toplevel):
    """사건 한 건의 상세. 저장된 요약을 먼저 보여 주고, 원본 메일에서 근거를 읽어 온다."""

    RISK_LABELS = {"high": "높음", "medium": "주의", "safe": "정상"}

    def __init__(self, master: tk.Misc, record: dict, evidence_source: EvidenceSource | None, dispatch: Dispatch) -> None:
        super().__init__(master)
        self.title(f"{APP_DISPLAY_NAME} - 탐지 상세")
        self.geometry("820x560")
        self.attributes("-topmost", True)
        self._record = record
        self._source = evidence_source
        self._dispatch = dispatch
        self._loading = False

        frame = ttk.Frame(self, padding=10)
        frame.grid(row=0, column=0, sticky="nsew")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)

        summary = ttk.LabelFrame(frame, text="사건 요약(저장된 정보)", padding=8)
        summary.grid(row=0, column=0, sticky="we")
        summary.columnconfigure(1, weight=1)
        risk = self.RISK_LABELS.get(str(record.get("risk")), "정상")
        counts = record.get("counts") or {}
        rows = [
            ("탐지 시각", local_timestamp(str(record.get("scanned_at", "")))),
            ("폴더 / UID", f"{record.get('folder', '')} / {record.get('uid', '')}"),
            ("위험 등급", risk),
            ("제목(마스킹)", str(record.get("subject", ""))),
            ("발신자(마스킹)", str(record.get("sender", ""))),
            ("탐지 항목", ", ".join(record.get("findings") or []) or "없음"),
        ]
        if counts:
            rows.append(("항목별 건수", ", ".join(f"{k}={v}" for k, v in counts.items())))
        for index, (name, value) in enumerate(rows):
            ttk.Label(summary, text=name, width=14).grid(row=index, column=0, sticky="w", pady=1)
            ttk.Label(summary, text=value, wraplength=640, justify="left").grid(row=index, column=1, sticky="w", pady=1)

        attachments = record.get("attachments") or []
        if attachments:
            box = ttk.LabelFrame(frame, text=f"첨부파일 {len(attachments)}개", padding=8)
            box.grid(row=2, column=0, sticky="we", pady=(8, 0))
            for index, item in enumerate(attachments[:5]):
                digest = str(item.get("sha256") or "")
                text = f"{item.get('name', '')}  ({item.get('size', 0):,} bytes)  SHA-256 {digest[:16]}…" if digest else f"{item.get('name', '')}  ({item.get('size', 0):,} bytes)"
                ttk.Label(box, text=text).grid(row=index, column=0, sticky="w")

        evidence = ttk.LabelFrame(frame, text="원본 근거", padding=8)
        evidence.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        evidence.rowconfigure(1, weight=1)
        evidence.columnconfigure(0, weight=1)
        self.var_status = tk.StringVar(value="'원본에서 근거 확인'을 누르면 메일 서버에서 원본을 읽어 근거를 표시합니다. 원본과 근거는 저장하지 않습니다.")
        ttk.Label(evidence, textvariable=self.var_status, wraplength=760, justify="left").grid(row=0, column=0, sticky="w")
        self.text = tk.Text(evidence, wrap="word", height=12, state="disabled")
        text_scroll = ttk.Scrollbar(evidence, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=text_scroll.set)
        self.text.grid(row=1, column=0, sticky="nsew", pady=(6, 0))
        text_scroll.grid(row=1, column=1, sticky="ns", pady=(6, 0))

        buttons = ttk.Frame(frame)
        buttons.grid(row=3, column=0, sticky="e", pady=(10, 0))
        self.btn_load = ttk.Button(buttons, text="원본에서 근거 확인", command=self._load)
        self.btn_load.pack(side="left", padx=4)
        if self._source is None:
            self.btn_load.configure(state="disabled")
            self.var_status.set("계정이 연결되어 있지 않아 원본을 읽을 수 없습니다.")
        ttk.Button(buttons, text="닫기", command=self.destroy).pack(side="left", padx=4)
        self.after(50, self._center)

    def _center(self) -> None:
        self.update_idletasks()
        x = (self.winfo_screenwidth() - self.winfo_width()) // 2
        y = (self.winfo_screenheight() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")
        self.lift()

    def _write(self, body: str) -> None:
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", body)
        self.text.configure(state="disabled")

    def _load(self) -> None:
        if self._loading or self._source is None:
            return
        self._loading = True
        self.btn_load.configure(state="disabled")
        self.var_status.set("메일 서버에서 원본을 읽는 중...")
        folder = str(self._record.get("folder", ""))
        uid = int(self._record.get("uid", 0))
        source = self._source

        def worker() -> None:
            try:
                result = source(folder, uid)
                self._dispatch(lambda: self._loaded(result, None))
            except Exception as exception:
                message = str(exception) or exception.__class__.__name__
                self._dispatch(lambda: self._loaded(None, message))

        threading.Thread(target=worker, name="incident-evidence", daemon=True).start()

    def _loaded(self, result: "EvidenceResult | None", error: str | None) -> None:
        if not self.winfo_exists():
            return
        self._loading = False
        self.btn_load.configure(state="normal")
        if error is not None or result is None:
            self.var_status.set(f"원본을 읽지 못했습니다: {error}")
            return
        message, evidence, legacy = result
        lines = [
            f"제목   : {message.subject}",
            f"발신자 : {message.sender}",
            f"날짜   : {message.date}",
        ]
        if message.category:
            lines.append(f"위치   : 받은편지함 '{message.category}' 탭  (다른 탭을 보고 있으면 목록에 안 보입니다)")
        if message.labels:
            lines.append(f"라벨   : {', '.join(message.labels)}")
        lines.append(f"크기   : {len(message.raw):,} bytes")
        lines.append("")
        if not evidence:
            lines.append("지금 규칙으로 다시 검사하니 탐지 항목이 없습니다.")
            lines.append("규칙이 개선되어 과거의 오탐이 해소된 경우입니다.")
            if legacy:
                in_link = sum(1 for item in legacy if item.in_url)
                lines.append("")
                lines.append(f"당시 판정 재현(0.1.6 이전 규칙) {len(legacy)}건, 그중 링크 안 {in_link}건")
                lines.append("당시에는 링크 안 문자열도 검사했고 영문 키워드에 단어 경계가 없었습니다.")
                for index, item in enumerate(legacy, 1):
                    where = " [링크 안]" if item.in_url else ""
                    lines.append("")
                    lines.append(f"{index}. {item.label} · {self.RISK_LABELS.get(item.risk, item.risk)}{where}")
                    lines.append(f"   값   : {item.masked_value}")
                    lines.append(f"   문맥 : ...{item.context}...")
        else:
            lines.append(f"탐지 근거 {len(evidence)}건 (값은 가려서 표시합니다)")
            for index, item in enumerate(evidence, 1):
                lines.append("")
                lines.append(f"{index}. {item.label} · {self.RISK_LABELS.get(item.risk, item.risk)}")
                lines.append(f"   값   : {item.masked_value}")
                lines.append(f"   문맥 : ...{item.context}...")
        self._write("\n".join(lines))
        self.var_status.set("원본에서 읽은 결과입니다. 이 내용은 저장되지 않습니다.")


def show_about(master: tk.Misc) -> None:
    messagebox.showinfo(
        APP_DISPLAY_NAME,
        f"{APP_DISPLAY_NAME} {VERSION}\n\n"
        "IMAP IDLE 기반 실시간 이메일 감시 (개인·파일럿용 1단계)\n"
        "본문·첨부파일은 분석 후 폐기되며 탐지 값 원문은 저장하지 않습니다.\n\n"
        "설계 문서: docs/02.개발계획서.md 18장",
        parent=master,
    )
