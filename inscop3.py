#!/usr/bin/env python3
"""InScop3 Recon v3 — Comprehensive Reconnaissance Tool
Arch Linux | PyQt6 | subfinder + httpx + dnsx + dig + nmap + nuclei + naabu + curl + wget
"""

import sys, subprocess, re, os, tempfile, json, shlex, threading, ipaddress
import html as _html
from datetime import datetime
from collections import defaultdict
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed

# Globális lista: minden megnyitott tool ablak referenciáját itt tároljuk.
# Ez megakadályozza, hogy a Python GC megsemmisítse az objektumot futó QThread
# mellett (ami SIGABRT-ot okozna: "QThread destroyed while still running").
_OPEN_DIALOGS = []

class _AppSettings:
    """Globális beállítások singleton — elérhetők parent nélkül is (parent=None ablakok)."""
    _rate = None        # QSpinBox referencia
    _user_agent = None  # QLineEdit referencia
    _req_header = None  # QLineEdit referencia
    _sudo_pw = None     # str

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QProgressBar, QTextEdit, QDialog, QSplitter,
    QFrame, QComboBox, QCheckBox, QMessageBox, QStatusBar,
    QAbstractItemView, QSpinBox, QScrollArea, QMenu, QFileDialog, QToolTip,
    QRadioButton, QButtonGroup, QStyledItemDelegate, QStyle, QSizePolicy,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QPoint, QSize
from PyQt6.QtGui import (
    QFont, QColor, QPalette, QFontDatabase, QAction,
    QCursor, QGuiApplication, QTextCharFormat, QTextCursor,
    QTextDocument, QKeySequence, QShortcut,
)

# ─── Language / Translation system ───────────────────────────────────────────
class Lang:
    """Singleton — active language ('hu' or 'en'), T(key) returns translated string."""
    _inst = None
    def __new__(cls):
        if cls._inst is None:
            cls._inst = super().__new__(cls)
            cls._inst.lang = "hu"
        return cls._inst

    def set(self, lang: str):
        self.lang = lang

    def __call__(self, key: str, **kw) -> str:
        d = _TRANSLATIONS.get(key, {})
        text = d.get(self.lang, d.get("en", key))
        return text.format(**kw) if kw else text

# Global translation function shortcut
_LANG = Lang()
def T(key, **kw): return _LANG(key, **kw)

# ─── Translations dictionary ──────────────────────────────────────────────────
_TRANSLATIONS = {
    # ── General buttons ───────────────────────────────────────────────────────
    "btn.start":         {"hu": "▶  Indítás",           "en": "▶  Start"},
    "btn.stop":          {"hu": "⏹  Leállítás",         "en": "⏹  Stop"},
    "btn.close":         {"hu": "Bezárás",               "en": "Close"},
    "btn.save":          {"hu": "💾  Mentés",            "en": "💾  Save"},
    "btn.save_as":       {"hu": "💾  Mentés másként…",   "en": "💾  Save as…"},
    "btn.cancel":        {"hu": "Mégse",                 "en": "Cancel"},
    "btn.continue":      {"hu": "Folytatás →",           "en": "Continue →"},
    "btn.continue_warn": {"hu": "Folytatás (hiányos) →", "en": "Continue (incomplete) →"},
    "btn.all_ready":     {"hu": "✅  Minden kész!",      "en": "✅  All ready!"},
    "btn.quit":          {"hu": "Kilépés",               "en": "Quit"},
    "btn.clear_filters": {"hu": "✕   Szűrők törlése",   "en": "✕   Clear filters"},
    "btn.clear_table":   {"hu": "🗑   Táblázat törlése", "en": "🗑   Clear table"},
    "btn.export":        {"hu": "⬇   Mentés (pipe .txt)","en": "⬇   Export (pipe .txt)"},
    "btn.scan_start":    {"hu": "▶   Scan indítása",     "en": "▶   Start scan"},
    "btn.scan_stop":     {"hu": "⏹   Leállítás",        "en": "⏹   Stop"},
    "btn.run_start":     {"hu": "▶ Indítás",             "en": "▶ Start"},
    "btn.clear_log":     {"hu": "törlés",                "en": "clear"},
    "btn.note":          {"hu": "📝  Jegyzet",           "en": "📝  Notes"},
    # ── SearchableOutput ──────────────────────────────────────────────────────
    "search.placeholder":{"hu": "🔍 Keresés a kimenetben...","en": "🔍 Search in output..."},
    "search.prev":       {"hu": "⬆ Előző",              "en": "⬆ Prev"},
    "search.next":       {"hu": "⬇ Következő",          "en": "⬇ Next"},
    "search.prev_tip":   {"hu": "Előző találat",        "en": "Previous match"},
    "search.next_tip":   {"hu": "Következő találat",    "en": "Next match"},
    "search.results":    {"hu": "{n} találat",          "en": "{n} matches"},
    "search.none":       {"hu": "Nincs",                "en": "None"},
    # ── Notes ─────────────────────────────────────────────────────────────────
    "notes.title":       {"hu": "📝 Jegyzet — InScop3 Recon","en": "📝 Notes — InScop3 Recon"},
    "notes.save_title":  {"hu": "Jegyzet mentése",      "en": "Save notes"},
    "notes.save_filter": {"hu": "HTML fájlok (*.html);;Szöveg fájlok (*.txt);;Minden fájl (*)","en": "HTML files (*.html);;Text files (*.txt);;All files (*)"},
    "notes.toggle_tip":  {"hu": "Jegyzet megnyitása / bezárása","en": "Open / close notes"},
    "notes.bold":        {"hu": "Félkövér",             "en": "Bold"},
    "notes.italic":      {"hu": "Dőlt",                 "en": "Italic"},
    "notes.underline":   {"hu": "Aláhúzott",            "en": "Underline"},
    "notes.undo":        {"hu": "Visszavonás (Ctrl+Z)", "en": "Undo (Ctrl+Z)"},
    "notes.redo":        {"hu": "Újra (Ctrl+Y)",        "en": "Redo (Ctrl+Y)"},
    # ── Tool scaffold ─────────────────────────────────────────────────────────
    "tool.cmd_tip":      {"hu": "Szerkeszthető — közvetlenül módosíthatod a parancsot","en": "Editable — you can modify the command directly"},
    "tool.output_saved": {"hu": "✓ Mentve: {path}",     "en": "✓ Saved: {path}"},
    "tool.output_err":   {"hu": "✗ Hiba: {err}",        "en": "✗ Error: {err}"},
    "tool.export_title": {"hu": "{name} kimenet exportálása","en": "Export {name} output"},
    "tool.export_filter":{"hu": "Log fájlok (*.log);;Szöveg fájlok (*.txt);;Minden fájl (*)","en": "Log files (*.log);;Text files (*.txt);;All files (*)"},
    "tool.done_ok":      {"hu": "✓ Kész",               "en": "✓ Done"},
    "tool.done_err":     {"hu": "✗ Megszakítva/Hiba",   "en": "✗ Stopped/Error"},
    "tool.target_label": {"hu": "Vizsgálandó host:",    "en": "Target host:"},
    "tool.file_browse":  {"hu": "Fájl tallózása",       "en": "Browse file"},
    "tool.file_filter":  {"hu": "Minden fájl (*)",      "en": "All files (*)"},
    "tool.flags":        {"hu": "KAPCSOLÓK (-flags)",   "en": "FLAGS (-flags)"},
    "tool.query_opts":   {"hu": "LEKÉRDEZÉSI OPCIÓK (+opts)","en": "QUERY OPTIONS (+opts)"},
    # ── Scan status ───────────────────────────────────────────────────────────
    "scan.stopped":      {"hu": "⏹ Leállítva",         "en": "⏹ Stopped"},
    "scan.done":         {"hu": "Scan kész — {n} subdomain","en": "Scan done — {n} subdomains"},
    "scan.batch_done":   {"hu": "Batch scan kész — {n} host összesen","en": "Batch scan done — {n} hosts total"},
    "scan.batch_stopped":{"hu": "Leállítva — {n} host feldolgozva","en": "Stopped — {n} hosts processed"},
    "scan.db_building":  {"hu": "DB összeállítás...",   "en": "Building DB..."},
    "scan.ready_label":  {"hu": "Kész!",                "en": "Done!"},
    "scan.status_ready": {"hu": "  Kész — add meg a domain-t","en": "  Ready — enter a domain"},
    "scan.status_bar":   {"hu": "Kész",                 "en": "Ready"},
    "scan.no_subfinder": {"hu": "subfinder nem talált semmit: {d}","en": "subfinder found nothing: {d}"},
    "scan.direct_url":   {"hu": "Subfinder kihagyva (direkt URL mód): {d}","en": "Subfinder skipped (direct URL mode): {d}"},
    "scan.batch_header": {"hu": "Batch scan: {total} domain","en": "Batch scan: {total} domains"},
    "scan.batch_prog":   {"hu": "[{i}/{t}] kész: {d} ({n} host)","en": "[{i}/{t}] done: {d} ({n} hosts)"},
    "scan.nxdomain":     {"hu": "⚠ NXDOMAIN — Takeover LEHETSÉGES!","en": "⚠ NXDOMAIN — Takeover POSSIBLE!"},
    "scan.sudo_title":   {"hu": "<b>sudo jelszó szükséges</b>","en": "<b>sudo password required</b>"},
    "scan.sudo_hint":    {"hu": "subfinder -all futtatásához","en": "to run subfinder -all"},
    "scan.sudo_ph":      {"hu": "Jelszó...",            "en": "Password..."},
    "scan.sudo_warn":    {"hu": "⚠ Root flag aktív — lehet, hogy sudo jelszót kér a terminálban","en": "⚠ Root flag active — sudo password may be requested in terminal"},
    "scan.0hosts":       {"hu": "0 host",               "en": "0 hosts"},
    "scan.n_hosts":      {"hu": "{n} host",             "en": "{n} hosts"},
    "scan.n_sub":        {"hu": "{n} subdomain",        "en": "{n} subdomains"},
    # ── MainWindow UI ─────────────────────────────────────────────────────────
    "main.title":        {"hu": "InScop3 Recon — Comprehensive Reconnaissance Tool","en": "InScop3 Recon — Comprehensive Reconnaissance Tool"},
    "main.rate_label":   {"hu": "Rate Limit (kérés/mp) — 0 = nincs limit","en": "Rate Limit (req/s) — 0 = no limit"},
    "main.ua_label":     {"hu": "User-Agent (-H) — opcionális","en": "User-Agent (-H) — optional"},
    "main.hdr_label":    {"hu": "Request Header (-H) — opcionális","en": "Request Header (-H) — optional"},
    "main.filters":      {"hu": "SZŰRŐK",               "en": "FILTERS"},
    "main.f_subdomain":  {"hu": "Subdomain",            "en": "Subdomain"},
    "main.f_sub_ph":     {"hu": "keresés...",           "en": "search..."},
    "main.f_http":       {"hu": "HTTP státusz",         "en": "HTTP status"},
    "main.f_all":        {"hu": "Minden",               "en": "All"},
    "main.f_ws":         {"hu": "Webszerver",           "en": "Web server"},
    "main.f_tech":       {"hu": "Technológia",          "en": "Technology"},
    "main.f_tech_ph":    {"hu": "Cloudflare, PHP...",   "en": "Cloudflare, PHP..."},
    "main.f_dns_type":   {"hu": "DNS típus",            "en": "DNS type"},
    "main.f_dns_val":    {"hu": "IP / CNAME érték",     "en": "IP / CNAME value"},
    "main.f_dns_val_ph": {"hu": "10.0.0., amazonaws...","en": "10.0.0., amazonaws..."},
    "main.f_takeover":   {"hu": "  Csak takeover jelöltek","en": "  Takeover candidates only"},
    "main.scope_tip":    {"hu": "Scope lista importálása (bug bounty txt fájl)","en": "Import scope list (bug bounty txt file)"},
    "main.export_log":   {"hu": "EXPORTÁLÁS / NAPLÓ",   "en": "EXPORT / LOG"},
    # ── Table columns ─────────────────────────────────────────────────────────
    "col.expand":        {"hu": "▶",                    "en": "▶"},
    "col.subdomain":     {"hu": "Subdomain",            "en": "Subdomain"},
    "col.title":         {"hu": "Title",                "en": "Title"},
    "col.http":          {"hu": "HTTP",                 "en": "HTTP"},
    "col.webserver":     {"hu": "Webszerver",           "en": "Web server"},
    "col.tech":          {"hu": "Tech",                 "en": "Tech"},
    "col.dns_type":      {"hu": "DNS típus",            "en": "DNS type"},
    "col.dns_val":       {"hu": "DNS érték",            "en": "DNS value"},
    "col.takeover":      {"hu": "Takeover",             "en": "Takeover"},
    "col.last_mod":      {"hu": "Utolsó módosítás",     "en": "Last modified"},
    # ── Table tooltips ────────────────────────────────────────────────────────
    "tbl.dns_tip":       {"hu": "Kattints a DNS rekordok megtekintéséhez","en": "Click to show DNS records"},
    "tbl.sub_tip":       {"hu": "Bal klikk: vágólapra | Jobb klikk: eszközök | ▶: DNS rekordok","en": "Left click: copy | Right click: tools | ▶: DNS records"},
    "tbl.http_tip":      {"hu": "<b>HTTP státusz kódok:</b>","en": "<b>HTTP status codes:</b>"},
    "tbl.copied":        {"hu": "📋 Vágólapra másolva\n{val}","en": "📋 Copied to clipboard\n{val}"},
    # ── Context menu ──────────────────────────────────────────────────────────
    "ctx.open_browser":  {"hu": "🌐  Megnyitás böngészőben","en": "🌐  Open in browser"},
    "ctx.copy":          {"hu": "📋  Vágólapra",        "en": "📋  Copy"},
    # ── Scope / batch ─────────────────────────────────────────────────────────
    "scope.open_title":  {"hu": "Scope fájl megnyitása","en": "Open scope file"},
    "scope.open_filter": {"hu": "Szöveges fájl (*.txt);;Minden (*)","en": "Text file (*.txt);;All (*)"},
    "scope.empty_title": {"hu": "Üres lista",           "en": "Empty list"},
    "scope.empty_msg":   {"hu": "Nem találtam domain-t a fájlban.","en": "No domains found in the file."},
    "scope.more":        {"hu": "  ... és még {n} domain","en": "  ... and {n} more"},
    "scope.confirm_msg": {"hu": "Talált {n} domain:\n{preview}\n\nElindítod a batch scant?","en": "Found {n} domains:\n{preview}\n\nStart batch scan?"},
    "scope.start_btn":   {"hu": "▶ Indítás",            "en": "▶ Start"},
    # ── Dependency checker ────────────────────────────────────────────────────
    "dep.title":         {"hu": "Eszközök",             "en": "Tools"},
    "dep.header":        {"hu": "<b>🔍  Szükséges eszközök ellenőrzése</b>","en": "<b>🔍  Checking required tools</b>"},
    "dep.missing":       {"hu": "Hiányzó eszközök:\n{cmds}","en": "Missing tools:\n{cmds}"},
    "dep.system":        {"hu": "Rendszerrel jár",      "en": "Comes with system"},
    # ── File dialogs ──────────────────────────────────────────────────────────
    "file.pipe_save":    {"hu": "Munkamenet mentése","en": "Save session"},
    "file.pipe_filter":  {"hu": "InScop3 munkamenet (*.inscop3);;Minden fájl (*)","en": "InScop3 session (*.inscop3);;All files (*)"},
    "file.pipe_open":    {"hu": "Munkamenet megnyitása","en": "Open session"},
    "file.import_ok":    {"hu": "✓ Betöltve: {msg}",  "en": "✓ Loaded: {msg}"},
    "file.import_err":   {"hu": "✗ Betöltési hiba: {msg}", "en": "✗ Load error: {msg}"},
    "file.save_ok":      {"hu": "✓ Mentve: {path}",   "en": "✓ Saved: {path}"},
    "btn.session_save":  {"hu": "💾   Munkamenet mentése", "en": "💾   Save session"},
    "btn.session_load":  {"hu": "📂   Munkamenet betöltése", "en": "📂   Load session"},
    "tool.fs_expand":    {"hu": "Kimenet teljes képernyő / visszaállítás", "en": "Fullscreen output / restore"},
    "tool.fs_restore":   {"hu": "Visszaállítás", "en": "Restore"},
    # ── Missing domain warning ────────────────────────────────────────────────
    "warn.no_domain_title":{"hu": "Hiányzó adat",      "en": "Missing data"},
    "warn.no_domain_msg":  {"hu": "Add meg a domain nevet!","en": "Please enter a domain name!"},
    # ── Dig tool ──────────────────────────────────────────────────────────────
    "dig.flags":         {"hu": "KAPCSOLÓK (-flags)",   "en": "FLAGS (-flags)"},
    "dig.query_opts":    {"hu": "LEKÉRDEZÉSI OPCIÓK (+opts)","en": "QUERY OPTIONS (+opts)"},
    # ── Nmap specific ─────────────────────────────────────────────────────────
    "nmap.elapsed":      {"hu": "Eltelt idő: {t}s",    "en": "Elapsed: {t}s"},
    # ── Wget sections ─────────────────────────────────────────────────────────
    "wget.startup":      {"hu": "INDÍTÁS",              "en": "STARTUP"},
    "wget.logging":      {"hu": "NAPLÓZÁS",             "en": "LOGGING"},
    "wget.download":     {"hu": "LETÖLTÉS",             "en": "DOWNLOAD"},
    "wget.directories":  {"hu": "KÖNYVTÁRAK",           "en": "DIRECTORIES"},
    "wget.http":         {"hu": "HTTP beállítások",     "en": "HTTP options"},
    "wget.https":        {"hu": "HTTPS beállítások",    "en": "HTTPS options"},
    "wget.ftp":          {"hu": "FTP beállítások",      "en": "FTP options"},
    "wget.ftps":         {"hu": "FTPS beállítások",     "en": "FTPS options"},
    "wget.warc":         {"hu": "WARC archiválás",      "en": "WARC archiving"},
    "wget.recursive":    {"hu": "REKURZÍV LETÖLTÉS",    "en": "RECURSIVE"},
    "wget.accept":       {"hu": "SZŰRŐK",               "en": "FILTERS"},
    # ── Language dialog ───────────────────────────────────────────────────────
    "lang.title":        {"hu": "Nyelv / Language",     "en": "Language / Nyelv"},
    "lang.prompt":       {"hu": "Válassz nyelvet / Choose language","en": "Choose language / Válassz nyelvet"},
    "lang.hu":           {"hu": "🇭🇺  Magyar",          "en": "🇭🇺  Hungarian"},
    "lang.en":           {"hu": "🇬🇧  English",         "en": "🇬🇧  English"},
    "lang.ok":           {"hu": "Tovább",               "en": "Continue"},
}


# ─── Palette ──────────────────────────────────────────────────────────────────
D = {
    "bg":    "#0d1117", "surf":  "#161b22", "surf2": "#21262d",
    "border":"#30363d", "acc":   "#58a6ff", "green": "#3fb950",
    "red":   "#f85149", "orange":"#d29922", "muted": "#8b949e",
    "text":  "#e6edf3", "text2": "#c9d1d9", "dim":   "#484f58",
}

SS = f"""
QMainWindow,QDialog{{background:{D['bg']};}}
QWidget{{background:{D['bg']};color:{D['text']};font-family:'JetBrains Mono','Fira Code',monospace;font-size:13px;}}
QScrollArea{{background:{D['surf']};border:none;}}
QScrollArea>QWidget>QWidget{{background:{D['surf']};}}
QTableWidget{{background:{D['bg']};border:none;gridline-color:{D['border']};color:{D['text']};selection-background-color:{D['surf2']};selection-color:{D['text']};}}
QTableWidget::item{{padding:4px 8px;border-bottom:1px solid {D['border']};}}
QTableWidget::item:selected{{background:{D['surf2']};}}
QHeaderView::section{{background:#010409;color:{D['muted']};border:none;border-bottom:1px solid {D['border']};border-right:1px solid {D['border']};padding:7px 8px;font-size:11px;font-weight:bold;letter-spacing:1px;}}
QHeaderView::section:hover{{background:{D['surf2']};color:{D['text']};}}
QTextEdit{{background:{D['surf']};border:1px solid {D['border']};border-radius:5px;color:{D['text2']};font-family:'JetBrains Mono','Fira Code',monospace;font-size:12px;padding:6px;}}
QScrollBar:vertical{{background:{D['bg']};width:8px;border-radius:4px;}}
QScrollBar::handle:vertical{{background:{D['border']};border-radius:4px;min-height:20px;}}
QScrollBar::handle:vertical:hover{{background:{D['muted']};}}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{height:0;}}
QScrollBar:horizontal{{background:{D['bg']};height:8px;border-radius:4px;}}
QScrollBar::handle:horizontal{{background:{D['border']};border-radius:4px;}}
QStatusBar{{background:{D['surf']};border-top:1px solid {D['border']};color:{D['muted']};font-size:11px;}}
QToolTip{{background:{D['surf2']};color:{D['text']};border:1px solid {D['border']};border-radius:4px;padding:4px 8px;}}
QMenu{{background:{D['surf2']};border:1px solid {D['border']};color:{D['text']};padding:4px;border-radius:6px;}}
QMenu::item{{padding:7px 22px 7px 12px;border-radius:4px;}}
QMenu::item:selected{{background:{D['acc']};color:#000;}}
QMenu::separator{{background:{D['border']};height:1px;margin:3px 6px;}}
QCheckBox{{spacing:6px;color:{D['text2']};font-size:12px;}}
QCheckBox::indicator{{width:14px;height:14px;border:1px solid {D['border']};border-radius:3px;background:{D['surf2']};}}
QCheckBox::indicator:checked{{background:{D['acc']};border-color:{D['acc']};}}
QSplitter::handle:vertical{{background:{D['border']};height:6px;}}
QSplitter::handle:vertical:hover{{background:{D['acc']};}}
"""

INP = f"""QLineEdit{{background:{D['surf2']};border:1px solid {D['border']};border-radius:5px;padding:2px 10px;color:{D['text']};font-size:13px;min-height:32px;}}QLineEdit:focus{{border-color:{D['acc']};}}QLineEdit:hover{{border-color:{D['muted']};}}"""
CMB = f"""QComboBox{{background:{D['surf2']};border:1px solid {D['border']};border-radius:5px;padding:2px 10px;color:{D['text']};font-size:13px;min-height:32px;}}QComboBox:focus{{border-color:{D['acc']};}}QComboBox:hover{{border-color:{D['muted']};}}QComboBox::drop-down{{border:none;width:24px;subcontrol-origin:padding;subcontrol-position:center right;}}QComboBox::down-arrow{{border-left:5px solid transparent;border-right:5px solid transparent;border-top:6px solid {D['muted']};width:0;height:0;margin-right:4px;}}QComboBox QAbstractItemView{{background:{D['surf2']};border:1px solid {D['acc']};color:{D['text']};selection-background-color:{D['acc']};selection-color:#000;outline:none;padding:2px;}}QComboBox QAbstractItemView::item{{min-height:28px;padding:4px 10px;color:{D['text']};}}"""
SPN = f"""QSpinBox{{background:{D['surf2']};border:1px solid {D['border']};border-radius:5px;padding:2px 10px;color:{D['text']};font-size:13px;min-height:32px;}}QSpinBox:focus{{border-color:{D['acc']};}}QSpinBox:hover{{border-color:{D['muted']};}}QSpinBox::up-button{{background:{D['surf']};border:none;border-left:1px solid {D['border']};width:22px;border-top-right-radius:5px;subcontrol-origin:border;subcontrol-position:top right;}}QSpinBox::down-button{{background:{D['surf']};border:none;border-left:1px solid {D['border']};border-top:1px solid {D['border']};width:22px;border-bottom-right-radius:5px;subcontrol-origin:border;subcontrol-position:bottom right;}}QSpinBox::up-button:hover,QSpinBox::down-button:hover{{background:{D['border']};}}QSpinBox::up-arrow{{border-left:4px solid transparent;border-right:4px solid transparent;border-bottom:5px solid {D['text']};width:0;height:0;}}QSpinBox::down-arrow{{border-left:4px solid transparent;border-right:4px solid transparent;border-top:5px solid {D['text']};width:0;height:0;}}"""

BRUN  = f"QPushButton{{background:{D['acc']};color:#000;border:none;border-radius:5px;padding:8px 16px;font-weight:bold;font-size:13px;min-height:38px;}}QPushButton:hover{{background:#79c0ff;}}QPushButton:disabled{{background:{D['border']};color:{D['muted']};}}"
BSTOP = f"QPushButton{{background:transparent;color:{D['red']};border:1px solid {D['red']};border-radius:5px;padding:8px 16px;font-weight:bold;font-size:13px;min-height:36px;}}QPushButton:hover{{background:rgba(248,81,73,.15);}}"
BMUT  = f"QPushButton{{background:transparent;color:{D['muted']};border:1px solid {D['border']};border-radius:5px;padding:6px 14px;font-size:12px;min-height:30px;}}QPushButton:hover{{color:{D['text']};border-color:{D['muted']};}}"
BGRN  = f"QPushButton{{background:transparent;color:{D['green']};border:1px solid {D['green']};border-radius:5px;padding:6px 14px;font-size:12px;min-height:30px;}}QPushButton:hover{{background:rgba(63,185,80,.12);}}"

def fp(w):
    p=w.palette()
    p.setColor(QPalette.ColorRole.Text,QColor(D['text']))
    p.setColor(QPalette.ColorRole.Base,QColor(D['surf2']))
    p.setColor(QPalette.ColorRole.PlaceholderText,QColor(D['muted']))
    p.setColor(QPalette.ColorRole.Window,QColor(D['surf2']))
    p.setColor(QPalette.ColorRole.WindowText,QColor(D['text']))
    w.setPalette(p)

# ─── Takeover detection ───────────────────────────────────────────────────────
TAKEOVER_CNAME = {
    r'\.s3\.amazonaws\.com': "AWS S3",
    r'\.s3-website': "AWS S3 Website",
    r'\.elasticbeanstalk\.com': "AWS EB",
    r'\.cloudfront\.net': "AWS CloudFront",
    r'\.elb\.amazonaws\.com': "AWS ELB",
    r'\.execute-api\.[^.]+\.amazonaws\.com': "AWS API GW",
    r'\.azurewebsites\.net': "Azure App",
    r'\.blob\.core\.windows\.net': "Azure Blob",
    r'\.trafficmanager\.net': "Azure TM",
    r'\.github\.io': "GitHub Pages",
    r'\.netlify\.app': "Netlify",
    r'\.netlify\.com': "Netlify",
    r'\.vercel\.app': "Vercel",
    r'\.herokuapp\.com': "Heroku",
    r'\.myshopify\.com': "Shopify",
    r'\.tumblr\.com': "Tumblr",
    r'\.ghost\.io': "Ghost",
    r'\.fastly\.net': "Fastly",
    r'\.edgekey\.net': "Akamai",
    r'\.akamaiedge\.net': "Akamai",
    r'\.pages\.dev': "CF Pages",
    r'\.zendesk\.com': "Zendesk",
    r'\.surge\.sh': "Surge.sh",
    r'\.bitbucket\.io': "Bitbucket",
    r'\.webflow\.io': "Webflow",
    r'\.hubspot\.net': "HubSpot",
    r'\.recruitee\.com': "Recruitee",
    r'\.statuspage\.io': "Statuspage",
    r'\.readme\.io': "ReadMe.io",
    r'\.wpengine\.com': "WP Engine",
    r'\.pantheonsite\.io': "Pantheon",
    r'\.unbounce\.com': "Unbounce",
    r'\.strikingly\.com': "Strikingly",
    r'\.cargo\.site': "Cargo",
}
TAKEOVER_FP = [
    "nosuchbucket","the specified bucket does not exist","no such bucket",
    "there isn't a github pages site here","no such app",
    "there is no app configured at that hostname","fastly error: unknown domain",
    "sorry, this shop is currently unavailable","help center closed",
    "domain not configured","site not found","project not found",
    "azure web sites","the resource you are looking for has been removed",
    "404 blog not found","originconnectionerror",
]

def check_takeover(rec):
    status  = str(rec.get("status",""))
    title   = rec.get("title","").lower()
    webserv = rec.get("webserver","").lower()
    dns     = rec.get("dns",[])
    cnames  = [v for t,v in dns if t=="CNAME"]
    has_a   = any(t=="A" for t,v in dns)
    reasons = []
    for cv in cnames:
        for pat,svc in TAKEOVER_CNAME.items():
            if re.search(pat,cv,re.I):
                if status=="404": reasons.append(f"CNAME\u2192{svc}+404")
                elif not status: reasons.append(f"CNAME\u2192{svc}+no HTTP")
                else:
                    combined=title+" "+webserv
                    for fp2 in TAKEOVER_FP:
                        if fp2 in combined: reasons.append(f"CNAME\u2192{svc}+fp"); break
    if has_a and status=="404":
        for fp2 in TAKEOVER_FP:
            if fp2 in title+webserv: reasons.append("A+404+fp"); break
    return bool(reasons), " | ".join(reasons)

# ─── Global Notes Singleton ───────────────────────────────────────────────────
class GlobalNotes:
    """Egyetlen közös notes példány az összes ablakhoz (Singleton)."""
    _inst = None
    _lock = Lock()

    def __new__(cls):
        if cls._inst is None:
            with cls._lock:
                if cls._inst is None:
                    o = super().__new__(cls)
                    o._content = ""
                    o._html    = ""
                    o._custom_path = None
                    o._default_dir = os.path.expanduser("~/.local/share/inscop3")
                    o._observers = []
                    o._html_observers = []
                    o._timer = None
                    cls._inst = o
                    # NEM hívjuk _load()-ot — mindig üres induláskor
        return cls._inst

    @property
    def default_path(self):
        return os.path.join(self._default_dir, "notes.txt")

    @property
    def default_html_path(self):
        return os.path.join(self._default_dir, "notes.html")

    def _load(self):
        """HTML betöltés (előnyben), fallback plain txt."""
        try:
            if os.path.exists(self.default_html_path):
                with open(self.default_html_path, "r", encoding="utf-8") as f:
                    self._html = f.read()
                # Sima szöveg kinyerése
                self._content = re.sub(r'<[^>]+>', '', self._html)
                return
            if os.path.exists(self.default_path):
                with open(self.default_path, "r", encoding="utf-8") as f:
                    self._content = f.read()
                self._html = ""
        except Exception:
            pass

    def register(self, cb):
        if cb not in self._observers:
            self._observers.append(cb)

    def unregister(self, cb):
        if cb in self._observers:
            self._observers.remove(cb)

    def get(self):
        return self._content

    def get_html(self):
        return self._html

    def set(self, text, source=None):
        """Sima szöveges tartalom frissítése (visszafelé-kompatibilis)."""
        self._content = text
        for cb in self._observers:
            if cb is not source:
                try: cb(text)
                except Exception: pass
        self._schedule_save()

    def set_html(self, html, source=None):
        """HTML tartalom frissítése és broadcast."""
        self._html = html
        # Sima szöveg kinyerése is (mentéshez, export-hoz)
        import html as _h
        self._content = re.sub(r'<[^>]+>', '', html)
        for cb in self._html_observers:
            if cb is not source:
                try: cb(html)
                except Exception: pass
        self._schedule_save()

    def register_html(self, cb):
        if cb not in self._html_observers:
            self._html_observers.append(cb)

    def unregister_html(self, cb):
        self._html_observers = [x for x in self._html_observers if x is not cb]

    def _schedule_save(self):
        if self._timer:
            try: self._timer.stop()
            except Exception: pass
        self._timer = QTimer()
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._autosave)
        self._timer.start(1200)

    def _autosave(self):
        """A munkamenet-autosave csak a _custom_path-ba ír (ha van).
        A notes.html-t szándékosan NEM írja — induláskor üres a jegyzet,
        a tartalom csak session (.inscop3) fájlba kerül."""
        if self._custom_path:
            try:
                content = self._html if self._html else self._content
                with open(self._custom_path, "w", encoding="utf-8") as f:
                    f.write(content)
            except Exception: pass

    def save_as(self, path):
        self._custom_path = path
        try:
            if path.lower().endswith(".html"):
                content = self._html if self._html else self._content
            else:
                content = self._content
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            return True, f"Mentve: {path}"
        except Exception as e:
            return False, str(e)


# ─── Shared Notes Editor Widget ───────────────────────────────────────────────
class NotesEditor(QWidget):
    """Újrafelhasználható szövegszerkesztő widget — GlobalNotes-hoz kötve."""

    # Alap színpaletta — előtér és háttér színek
    FG_COLORS = [
        ("#f85149", "Piros"),    ("#ff9500", "Narancs"),  ("#ffd60a", "Sárga"),
        ("#7ee787", "Zöld"),     ("#79c0ff", "Kék"),       ("#d2a8ff", "Lila"),
        ("#f0f6fc", "Fehér"),    ("#8b949e", "Szürke"),
    ]
    BG_COLORS = [
        ("#3d1f1f", "Sötét piros bg"),  ("#3d2b00", "Sötét narancs bg"),
        ("#2d2a00", "Sötét sárga bg"),  ("#1a2e1a", "Sötét zöld bg"),
        ("#1a2535", "Sötét kék bg"),    ("#2a1f3d", "Sötét lila bg"),
        ("#21262d", "Sötét bg"),        ("#00000000","Nincs háttér"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._notes = GlobalNotes()
        self._updating = False
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # ── Toolbar ──────────────────────────────────────────────────────────
        tb = QFrame()
        tb.setStyleSheet(f"background:{D['surf2']};border-bottom:1px solid {D['border']};")
        tb.setFixedHeight(38)
        tbl = QHBoxLayout(tb)
        tbl.setContentsMargins(6, 4, 6, 4)
        tbl.setSpacing(4)

        # Font family
        self._font_cb = QComboBox()
        families = ["Arial", "Times New Roman", "Courier New", "Georgia",
                    "Verdana", "Helvetica", "Monospace", "JetBrains Mono"]
        self._font_cb.addItems(families)
        self._font_cb.setFixedWidth(130)
        self._font_cb.setStyleSheet(f"background:{D['surf']};color:{D['text2']};border:1px solid {D['border']};border-radius:3px;")
        self._font_cb.currentTextChanged.connect(self._apply_font_family)
        tbl.addWidget(self._font_cb)

        # Font size
        self._size_sp = QSpinBox()
        self._size_sp.setRange(7, 36)
        self._size_sp.setValue(11)
        self._size_sp.setFixedWidth(52)
        self._size_sp.setStyleSheet(f"background:{D['surf']};color:{D['text2']};border:1px solid {D['border']};border-radius:3px;")
        self._size_sp.valueChanged.connect(self._apply_font_size)
        tbl.addWidget(self._size_sp)

        tbl.addSpacing(4)

        def _tbtn(label, tip, fn, checkable=False):
            b = QPushButton(label)
            b.setToolTip(tip)
            b.setFixedSize(28, 26)
            b.setCheckable(checkable)
            b.setStyleSheet(
                f"QPushButton{{background:{D['surf']};color:{D['text2']};border:1px solid {D['border']};"
                f"border-radius:3px;font-weight:bold;}}"
                f"QPushButton:hover{{background:{D['surf2']};color:{D['text']};}}"
                f"QPushButton:checked{{background:{D['acc']};color:#fff;border-color:{D['acc']};}}"
            )
            b.clicked.connect(fn)
            tbl.addWidget(b)
            return b

        self._bold_btn      = _tbtn("B", T("notes.bold"),      self._toggle_bold,      True)
        self._italic_btn    = _tbtn("I", T("notes.italic"),     self._toggle_italic,    True)
        self._underline_btn = _tbtn("U", T("notes.underline"),  self._toggle_underline, True)
        tbl.addSpacing(4)
        _tbtn("↶", T("notes.undo"), self._undo)
        _tbtn("↷", T("notes.redo"), self._redo)

        tbl.addSpacing(8)

        # ── Szín-paletta: előtér (A◼) + háttér (◼) gombok ──────────────────
        def _color_swatch(color, tip, fn):
            """Kis négyzetgomb egy adott színnel."""
            b = QPushButton()
            b.setFixedSize(18, 18)
            b.setToolTip(tip)
            if color == "#00000000":
                # Átlátszó / nincs — X-szel jelöljük
                b.setText("✕")
                b.setStyleSheet(
                    f"QPushButton{{background:{D['surf']};color:{D['text2']};"
                    f"border:1px solid {D['border']};border-radius:2px;font-size:9px;}}"
                    f"QPushButton:hover{{border-color:{D['acc']};}}"
                )
            else:
                b.setStyleSheet(
                    f"QPushButton{{background:{color};border:1px solid rgba(255,255,255,0.15);"
                    f"border-radius:2px;}}"
                    f"QPushButton:hover{{border:2px solid #fff;}}"
                )
            b.clicked.connect(fn)
            tbl.addWidget(b)
            return b

        # Előtér szín label
        fg_lbl = QLabel("A")
        fg_lbl.setStyleSheet(f"color:{D['muted']};font-size:10px;font-weight:bold;")
        fg_lbl.setFixedWidth(12)
        tbl.addWidget(fg_lbl)

        for color, tip in self.FG_COLORS:
            _color_swatch(color, tip, lambda c=color: self._apply_fg_color(c))

        tbl.addSpacing(6)

        # Háttér szín label
        bg_lbl = QLabel("▣")
        bg_lbl.setStyleSheet(f"color:{D['muted']};font-size:10px;")
        bg_lbl.setFixedWidth(12)
        tbl.addWidget(bg_lbl)

        for color, tip in self.BG_COLORS:
            _color_swatch(color, tip, lambda c=color: self._apply_bg_color(c))

        tbl.addStretch()

        # ── Inline keresőmező a toolbar jobb oldalán ─────────────────────────
        self._tb_search = QLineEdit()
        self._tb_search.setPlaceholderText("🔍 Keresés…")
        self._tb_search.setFixedWidth(160)
        self._tb_search.setStyleSheet(
            f"QLineEdit{{background:{D['surf']};color:{D['text2']};border:1px solid {D['border']};"
            f"border-radius:3px;padding:2px 6px;font-size:11px;}}"
            f"QLineEdit:focus{{border-color:{D['acc']};}}"
        )
        self._tb_search.textChanged.connect(self._search_notes)
        self._tb_search.returnPressed.connect(self._search_next)
        tbl.addWidget(self._tb_search)

        self._tb_search_lbl = QLabel("")
        self._tb_search_lbl.setStyleSheet(f"color:{D['muted']};font-size:10px;min-width:44px;")
        tbl.addWidget(self._tb_search_lbl)

        tb_prev = QPushButton("↑"); tb_prev.setFixedSize(22,22); tb_prev.setToolTip("Előző (Shift+Enter)")
        tb_prev.setStyleSheet(
            f"QPushButton{{background:{D['surf']};color:{D['text2']};border:1px solid {D['border']};border-radius:3px;}}"
            f"QPushButton:hover{{background:{D['acc']};color:#fff;border-color:{D['acc']};}}"
        )
        tb_prev.clicked.connect(self._search_prev); tbl.addWidget(tb_prev)

        tb_next = QPushButton("↓"); tb_next.setFixedSize(22,22); tb_next.setToolTip("Következő (Enter)")
        tb_next.setStyleSheet(
            f"QPushButton{{background:{D['surf']};color:{D['text2']};border:1px solid {D['border']};border-radius:3px;}}"
            f"QPushButton:hover{{background:{D['acc']};color:#fff;border-color:{D['acc']};}}"
        )
        tb_next.clicked.connect(self._search_next); tbl.addWidget(tb_next)

        lay.addWidget(tb)

        # ── TextEdit ─────────────────────────────────────────────────────────
        self.edit = QTextEdit()
        self.edit.setAcceptRichText(True)
        self.edit.setStyleSheet(
            f"QTextEdit{{background:{D['surf']};color:{D['text2']};"
            f"border:none;font-family:'JetBrains Mono',monospace;"
            f"font-size:11px;padding:6px;}}"
        )
        # HTML betöltés ha van (színek megőrzésével), fallback plain text
        saved_html = self._notes.get_html()
        if saved_html and saved_html.strip():
            self.edit.setHtml(saved_html)
        elif self._notes.get().strip():
            self.edit.setPlainText(self._notes.get())
        # Ha mindkettő üres → üres editor
        self.edit.textChanged.connect(self._on_changed)
        self.edit.cursorPositionChanged.connect(self._sync_toolbar_state)
        lay.addWidget(self.edit)

        # ── Keresősáv (Ctrl+F, alapból rejtett) ──────────────────────────────
        self._search_bar = QFrame()
        self._search_bar.setStyleSheet(
            f"QFrame{{background:{D['surf2']};border-top:1px solid {D['border']};padding:0;}}"
        )
        self._search_bar.setFixedHeight(36)
        sbl = QHBoxLayout(self._search_bar)
        sbl.setContentsMargins(6, 4, 6, 4); sbl.setSpacing(6)

        self._search_inp = QLineEdit()
        self._search_inp.setPlaceholderText("Keresés a jegyzetben... (Enter: következő, Shift+Enter: előző)")
        self._search_inp.setStyleSheet(
            f"QLineEdit{{background:{D['surf']};color:{D['text2']};border:1px solid {D['border']};"
            f"border-radius:3px;padding:2px 6px;font-size:11px;}}"
            f"QLineEdit:focus{{border-color:{D['acc']};}}"
        )
        self._search_inp.textChanged.connect(self._search_notes)
        self._search_inp.returnPressed.connect(self._search_next)
        sbl.addWidget(self._search_inp)

        self._search_lbl = QLabel("")
        self._search_lbl.setStyleSheet(f"color:{D['muted']};font-size:10px;min-width:60px;")
        sbl.addWidget(self._search_lbl)

        def _snav_btn(icon, tip, fn):
            b = QPushButton(icon); b.setFixedSize(26, 26); b.setToolTip(tip)
            b.setStyleSheet(
                f"QPushButton{{background:{D['surf']};color:{D['text2']};border:1px solid {D['border']};"
                f"border-radius:3px;}}"
                f"QPushButton:hover{{background:{D['acc']};color:#fff;border-color:{D['acc']};}}"
            )
            b.clicked.connect(fn); sbl.addWidget(b); return b

        _snav_btn("↑", "Előző (Shift+Enter)", self._search_prev)
        _snav_btn("↓", "Következő (Enter)",   self._search_next)
        _snav_btn("✕", "Bezárás (Esc)",        self._close_search)

        self._search_bar.setVisible(False)
        lay.addWidget(self._search_bar)

        # Ctrl+F shortcut az editorra
        QShortcut(QKeySequence("Ctrl+F"), self.edit, activated=self._open_search)
        QShortcut(QKeySequence("Escape"), self._search_inp, activated=self._close_search)
        # Shift+Enter az inputon = előző találat
        QShortcut(QKeySequence("Shift+Return"), self._search_inp, activated=self._search_prev)

        self._search_matches = []
        self._search_idx     = -1
        self._search_last    = ""

        # HTML observer regisztrálás
        self._notes.register_html(self._on_notes_html_changed)

    def closeEvent(self, e):
        self._notes.unregister_html(self._on_notes_html_changed)
        super().closeEvent(e)

    # ── Sync ────────────────────────────────────────────────────────────────
    def _on_changed(self):
        if self._updating: return
        # HTML-t mentünk, nem sima szöveget → megőrzi a színeket
        self._notes.set_html(self.edit.toHtml(), source=self._on_notes_html_changed)

    def _on_notes_html_changed(self, html):
        if self.edit.toHtml() == html: return
        self._updating = True
        cur = self.edit.textCursor().position()
        self.edit.setHtml(html)
        c = self.edit.textCursor()
        c.setPosition(min(cur, len(self.edit.toPlainText())))
        self.edit.setTextCursor(c)
        self._updating = False

    # ── Format ──────────────────────────────────────────────────────────────
    def _apply_font_family(self, name):
        fmt = QTextCharFormat(); fmt.setFontFamily(name)
        self.edit.mergeCurrentCharFormat(fmt)

    def _apply_font_size(self, sz):
        fmt = QTextCharFormat(); fmt.setFontPointSize(sz)
        self.edit.mergeCurrentCharFormat(fmt)

    def _toggle_bold(self, checked):
        fmt = QTextCharFormat()
        fmt.setFontWeight(QFont.Weight.Bold if checked else QFont.Weight.Normal)
        self.edit.mergeCurrentCharFormat(fmt)

    def _toggle_italic(self, checked):
        fmt = QTextCharFormat(); fmt.setFontItalic(checked)
        self.edit.mergeCurrentCharFormat(fmt)

    def _toggle_underline(self, checked):
        fmt = QTextCharFormat(); fmt.setFontUnderline(checked)
        self.edit.mergeCurrentCharFormat(fmt)

    def _apply_fg_color(self, color):
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        self.edit.mergeCurrentCharFormat(fmt)

    def _apply_bg_color(self, color):
        fmt = QTextCharFormat()
        if color == "#00000000":
            fmt.setBackground(QColor(0, 0, 0, 0))
        else:
            fmt.setBackground(QColor(color))
        self.edit.mergeCurrentCharFormat(fmt)

    def _undo(self): self.edit.undo()
    def _redo(self): self.edit.redo()

    # ── Keresés ──────────────────────────────────────────────────────────────
    def _open_search(self):
        self._tb_search.setFocus()
        self._tb_search.selectAll()

    def _close_search(self):
        self._search_bar.setVisible(False)
        self._clear_highlights()
        self._search_matches = []
        self._search_idx = -1
        self._search_lbl.setText("")
        self._tb_search_lbl.setText("")
        self._tb_search.clear()
        self.edit.setFocus()

    def _clear_highlights(self):
        """Összes keresési kiemelés eltávolítása."""
        cur = self.edit.textCursor()
        cur.select(QTextCursor.SelectionType.Document)
        fmt = QTextCharFormat()
        fmt.setBackground(QColor(0, 0, 0, 0))
        cur.mergeCharFormat(fmt)
        cur.clearSelection()
        self.edit.setTextCursor(cur)

    def _search_notes(self, text):
        """Keresési találatok megkeresése és kiemelése. Mindkét keresőmezőt szinkronizálja."""
        # Szinkronizálás: ha a toolbar mezőből jött, frissítsük a lenti sávot is, és fordítva
        sender = self.sender()
        if sender is self._tb_search and self._search_inp.text() != text:
            self._search_inp.blockSignals(True)
            self._search_inp.setText(text)
            self._search_inp.blockSignals(False)
        elif sender is self._search_inp and self._tb_search.text() != text:
            self._tb_search.blockSignals(True)
            self._tb_search.setText(text)
            self._tb_search.blockSignals(False)

        self._clear_highlights()
        self._search_matches = []
        self._search_idx = -1

        if not text.strip():
            self._search_lbl.setText("")
            self._tb_search_lbl.setText("")
            return

        self._search_last = text
        doc = self.edit.document()
        highlight_fmt = QTextCharFormat()
        highlight_fmt.setBackground(QColor("#3d3000"))

        cur = QTextCursor(doc)
        flags = QTextDocument.FindFlag(0)
        while True:
            cur = doc.find(text, cur, flags)
            if cur.isNull(): break
            self._search_matches.append(cur.position())
            cur.mergeCharFormat(highlight_fmt)

        n = len(self._search_matches)
        lbl_style_ok  = f"color:{D['text2']};font-size:10px;min-width:44px;"
        lbl_style_err = f"color:{D['red']};font-size:10px;min-width:44px;"
        if n:
            self._search_idx = 0
            self._jump_to(0)
            self._search_lbl.setStyleSheet(f"color:{D['text2']};font-size:10px;min-width:60px;")
            self._tb_search_lbl.setStyleSheet(lbl_style_ok)
        else:
            self._search_lbl.setStyleSheet(f"color:{D['red']};font-size:10px;min-width:60px;")
            self._tb_search_lbl.setStyleSheet(lbl_style_err)
        label = f"{min(self._search_idx+1,n)}/{n}" if n else "0/0"
        self._search_lbl.setText(label)
        self._tb_search_lbl.setText(label)

    def _jump_to(self, idx):
        """Ugrás az idx-edik találathoz, aktív kiemelés."""
        if not self._search_matches: return
        n   = len(self._search_matches)
        idx = idx % n
        self._search_idx = idx

        # Minden kiemelés visszaállítása halványra
        doc = self.edit.document()
        dim_fmt  = QTextCharFormat(); dim_fmt.setBackground(QColor("#3d3000"))
        hi_fmt   = QTextCharFormat(); hi_fmt.setBackground(QColor("#b8860b"))

        term = self._search_last
        # Aktív találat erős kiemelése
        for i, pos in enumerate(self._search_matches):
            c = QTextCursor(doc)
            c.setPosition(pos - len(term))
            c.setPosition(pos, QTextCursor.MoveMode.KeepAnchor)
            c.mergeCharFormat(hi_fmt if i == idx else dim_fmt)

        # Görgetés az aktív találathoz
        c = QTextCursor(doc)
        c.setPosition(self._search_matches[idx])
        self.edit.setTextCursor(c)
        self.edit.ensureCursorVisible()

        n = len(self._search_matches)
        label = f"{idx+1}/{n}"
        self._search_lbl.setText(label)
        self._tb_search_lbl.setText(label)

    def _search_next(self):
        if self._search_matches:
            self._jump_to(self._search_idx + 1)

    def _search_prev(self):
        if self._search_matches:
            self._jump_to(self._search_idx - 1)

    def _sync_toolbar_state(self):
        fmt = self.edit.currentCharFormat()
        self._bold_btn.setChecked(fmt.fontWeight() == QFont.Weight.Bold)
        self._italic_btn.setChecked(fmt.fontItalic())
        self._underline_btn.setChecked(fmt.fontUnderline())


# ─── NotesDialog — standalone ablak ──────────────────────────────────────────
class NotesDialog(QMainWindow):
    """Önálló főablak a jegyzetszerkesztőhöz — saját tálcaikon."""
    def __init__(self, parent=None):
        super().__init__(None)   # parent=None → önálló ablak a tálcán
        self.setWindowTitle(T("notes.title"))
        self.setMinimumSize(680, 520)
        self.setStyleSheet(SS)
        self.setWindowFlags(Qt.WindowType.Window)

        cw = QWidget(); self.setCentralWidget(cw)
        lay = QVBoxLayout(cw); lay.setContentsMargins(0, 0, 0, 0); lay.setSpacing(0)

        self._editor = NotesEditor(self)
        lay.addWidget(self._editor)

        # Bottom bar — mentés
        bot = QFrame()
        bot.setStyleSheet(f"background:{D['surf']};border-top:1px solid {D['border']};")
        bot.setFixedHeight(46)
        bl = QHBoxLayout(bot); bl.setContentsMargins(10, 6, 10, 6); bl.setSpacing(8)
        bl.addStretch()
        save_btn = QPushButton(T("btn.save_as"))
        save_btn.setStyleSheet(BMUT); save_btn.setFixedWidth(160)
        save_btn.clicked.connect(self._save_as)
        bl.addWidget(save_btn)
        lay.addWidget(bot)

    def _save_as(self):
        path, _ = QFileDialog.getSaveFileName(
            self, T("notes.save_title"),
            f"inscop3_notes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
            T("notes.save_filter")
        )
        if path:
            ok, msg = GlobalNotes().save_as(path)
            self.setWindowTitle(f"📝 {msg}")
            QTimer.singleShot(3000, lambda: self.setWindowTitle(T("notes.title")))


class CmdWorker(QThread):
    output   = pyqtSignal(str)
    finished = pyqtSignal(bool)
    def __init__(self,cmd):
        super().__init__()
        self._cmd=cmd; self._proc=None; self._stop=False
    def stop(self):
        self._stop=True
        if self._proc:
            try: self._proc.terminate()
            except: pass
    def run(self):
        try:
            self._proc=subprocess.Popen(self._cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
            for line in self._proc.stdout:
                if self._stop: break
                self.output.emit(line.rstrip())
            self._proc.wait()
            self.finished.emit(not self._stop and self._proc.returncode==0)
        except Exception as e:
            self.output.emit(f"Hiba: {e}"); self.finished.emit(False)


class FfufCmdWorker(QThread):
    """Ffuf-specifikus worker: soronként bufferel, max 50ms-onként küld UI-ra.
    Megakadályozza a UI befagyását nagy sebességű ffuf kimenetnél."""
    batch_output = pyqtSignal(list)   # list of str sorok
    finished     = pyqtSignal(bool)

    FLUSH_INTERVAL_MS = 80   # ennyi ms-onként flush a UI-ra
    MAX_BATCH         = 200  # max ennyi sor egy batch-ben (maradék eldobva ha több)
    MAX_BUFFER        = 2000 # ha a buffer ennyi sor fölé nő, eldobjuk a legrégebbieket

    def __init__(self, cmd):
        super().__init__()
        self._cmd = cmd; self._proc = None; self._stop = False

    def stop(self):
        self._stop = True
        if self._proc:
            try: self._proc.terminate()
            except: pass

    def run(self):
        import time
        try:
            self._proc = subprocess.Popen(
                self._cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1)
            buf = []
            last_flush = time.monotonic()
            for line in self._proc.stdout:
                if self._stop: break
                buf.append(line.rstrip())
                # Ha a buffer túl nagy, eldobjuk a legrégebbieket
                if len(buf) > self.MAX_BUFFER:
                    buf = buf[-self.MAX_BUFFER:]
                now = time.monotonic()
                if (now - last_flush) * 1000 >= self.FLUSH_INTERVAL_MS:
                    if buf:
                        self.batch_output.emit(buf[:self.MAX_BATCH])
                        buf = buf[self.MAX_BATCH:]
                    last_flush = now
            # Utolsó maradék flush
            if buf:
                self.batch_output.emit(buf[:self.MAX_BATCH])
            self._proc.wait()
            self.finished.emit(not self._stop and self._proc.returncode == 0)
        except Exception as e:
            self.batch_output.emit([f"Hiba: {e}"]); self.finished.emit(False)

# ─── ANSI color → HTML converter ─────────────────────────────────────────────
import re as _re_ansi

_ANSI_COLORS = {
    # Regular foreground
    "30": "#484f58",  # black  → dim
    "31": "#f85149",  # red
    "32": "#3fb950",  # green
    "33": "#d29922",  # yellow/orange
    "34": "#58a6ff",  # blue
    "35": "#bc8cff",  # magenta
    "36": "#39c5cf",  # cyan
    "37": "#e6edf3",  # white
    # Bright foreground
    "90": "#6e7681",  # bright black
    "91": "#ff7b72",  # bright red
    "92": "#56d364",  # bright green
    "93": "#e3b341",  # bright yellow
    "94": "#79c0ff",  # bright blue
    "95": "#d2a8ff",  # bright magenta
    "96": "#56d8c8",  # bright cyan
    "97": "#f0f6fc",  # bright white
}

def ansi_to_html(text):
    """Convert ANSI escape sequences to HTML spans, strip unknown escapes."""
    import html as _h
    result = []
    open_spans = 0
    i = 0
    while i < len(text):
        # Match ESC[ ... m  (SGR sequence)
        m = _re_ansi.match(r'\x1b\[([0-9;]*)m', text[i:])
        if m:
            codes_str = m.group(1)
            codes = codes_str.split(";") if codes_str else ["0"]
            seq = m.group(0)
            i += len(seq)
            if codes == ["0"] or codes == [""]:
                # Reset: close all open spans
                result.append("</span>" * open_spans)
                open_spans = 0
            else:
                for code in codes:
                    color = _ANSI_COLORS.get(code)
                    bold  = code == "1"
                    if color:
                        result.append(f"<span style=\'color:{color}\'>")
                        open_spans += 1
                    elif bold:
                        result.append("<span style=\'font-weight:bold\'>")
                        open_spans += 1
        elif text[i] == "\x1b":
            # Other escape sequence — skip it
            # Find end of sequence
            j = i + 1
            while j < len(text) and text[j] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz@[\\]^_`{|}~":
                j += 1
            i = j + 1
        else:
            result.append(_h.escape(text[i]))
            i += 1
    # Close any remaining open spans
    result.append("</span>" * open_spans)
    return "".join(result)


# ─── SearchableOutput ─────────────────────────────────────────────────────────
class SearchableOutput(QWidget):
    def __init__(self,parent=None):
        super().__init__(parent)
        self._matches=[]; self._cur=-1
        self._output_lock=Lock()  # Thread-safe output synchronization
        lay=QVBoxLayout(self); lay.setContentsMargins(0,0,0,0); lay.setSpacing(3)
        self.edit=QTextEdit()
        self.edit.setReadOnly(True)
        self.edit.setStyleSheet(f"QTextEdit{{background:{D['surf']};border:1px solid {D['border']};border-radius:5px;color:{D['text2']};font-family:'JetBrains Mono',monospace;font-size:12px;padding:6px;}}")
        lay.addWidget(self.edit)
        sb=QHBoxLayout(); sb.setSpacing(4)
        self._si=QLineEdit(); self._si.setPlaceholderText(T("search.placeholder")); self._si.setStyleSheet(INP+"QLineEdit{min-height:26px;font-size:12px;}"); fp(self._si)
        self._si.textChanged.connect(self._search); sb.addWidget(self._si)
        self._cl=QLabel(""); self._cl.setStyleSheet(f"color:{D['muted']};font-size:11px;min-width:70px;"); sb.addWidget(self._cl)
        prev_b=QPushButton(T("search.prev")); prev_b.setFixedHeight(26); prev_b.setStyleSheet(BMUT); prev_b.setToolTip(T("search.prev_tip")); prev_b.clicked.connect(self._prev); sb.addWidget(prev_b)
        next_b=QPushButton(T("search.next")); next_b.setFixedHeight(26); next_b.setStyleSheet(BMUT); next_b.setToolTip(T("search.next_tip")); next_b.clicked.connect(self._next); sb.addWidget(next_b)
        lay.addLayout(sb)

    def insertHtml(self, h):
        with self._output_lock:
            e = self.edit
            tc = e.textCursor()
            has_selection = tc.hasSelection()
            # Ha van kijelölés, elmentjük és a végére ugrunk az insert előtt
            if has_selection:
                sel_start = tc.selectionStart()
                sel_end   = tc.selectionEnd()
                # Insert a dokumentum végére anélkül hogy a kijelölést elveszítenénk
                end_cur = e.textCursor()
                end_cur.movePosition(QTextCursor.MoveOperation.End)
                e.setTextCursor(end_cur)
                e.insertHtml(h)
                # Visszaállítjuk a kijelölést
                restore = e.textCursor()
                restore.setPosition(sel_start)
                restore.setPosition(sel_end, QTextCursor.MoveMode.KeepAnchor)
                e.setTextCursor(restore)
                # Nem scrollolunk — a felhasználó épp olvas/másol
            else:
                e.insertHtml(h)
                sb = e.verticalScrollBar()
                sb.setValue(sb.maximum())
    def append(self,t): self.edit.append(t)
    def clear(self):    self.edit.clear(); self._clear()
    def setPlaceholderText(self,t): self.edit.setPlaceholderText(t)
    def verticalScrollBar(self): return self.edit.verticalScrollBar()

    def _search(self):
        term=self._si.text(); doc=self.edit.document()
        cur=QTextCursor(doc); cur.select(QTextCursor.SelectionType.Document)
        cur.setCharFormat(QTextCharFormat()); self._matches=[]
        if not term: self._cl.setText(""); return
        fmt=QTextCharFormat(); fmt.setBackground(QColor(D['red'])); fmt.setForeground(QColor("#fff"))
        cur=QTextCursor(doc)
        while True:
            cur=doc.find(term,cur)
            if cur.isNull(): break
            self._matches.append(QTextCursor(cur)); cur.setCharFormat(fmt)
        n=len(self._matches); self._cl.setText(T("search.results",n=n) if n else T("search.none"))
        self._cur=0 if n else -1; self._jump()

    def _jump(self):
        if not self._matches or self._cur<0: return
        fmt=QTextCharFormat(); fmt.setBackground(QColor(D['orange'])); fmt.setForeground(QColor("#000"))
        tc=QTextCursor(self._matches[self._cur]); tc.setCharFormat(fmt)
        self.edit.setTextCursor(self._matches[self._cur]); self.edit.ensureCursorVisible()
        self._cl.setText(f"{self._cur+1}/{len(self._matches)}")

    def _next(self):
        if self._matches: self._cur=(self._cur+1)%len(self._matches); self._jump()
    def _prev(self):
        if self._matches: self._cur=(self._cur-1)%len(self._matches); self._jump()
    def _clear(self):
        self._si.clear(); self._matches=[]; self._cur=-1
    
    def export_text(self,path):
        """Export console output to file"""
        try:
            with open(path,'w',encoding='utf-8') as f:
                f.write(self.edit.toPlainText())
            return True,f"Mentve: {path}"
        except Exception as e:
            return False,f"Hiba: {e}"
    
    def get_text(self):
        """Get console output as plain text"""
        return self.edit.toPlainText()

# ─── BaseToolDialog ───────────────────────────────────────────────────────────
class BaseToolDialog(QDialog):
    TOOL_NAME="tool"; ICON="🔧"; SUBTITLE=""

    def __init__(self,host,dns_values,parent=None):
        # Nincs parent → teljesen önálló ablak, saját tálcaikon
        super().__init__(None)
        self.host=host; self.dns_values=dns_values
        self._flag_widgets=[]; self._tgts=[]; self._tgt_group=None
        self.setWindowTitle(f"{self.ICON}  {self.TOOL_NAME} — {host}")
        self.setMinimumSize(900,760); self.setStyleSheet(SS)
        # Önálló ablak: saját tálcaikon, nincs always-on-top
        self.setWindowFlags(Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose,False)
        self._scaffold(); self._build_flags(); self._update_cmd()

    def _scaffold(self):
        # Fő layout: az egész dialog = vízszintes splitter (tool | notes)
        dialog_lay = QHBoxLayout(self)
        dialog_lay.setContentsMargins(0, 0, 0, 0)
        dialog_lay.setSpacing(0)

        # ── Fő splitter: bal=tool, jobb=notes ────────────────────────────────
        self._main_splitter = QSplitter(Qt.Orientation.Horizontal)
        self._main_splitter.setHandleWidth(2)
        self._main_splitter.setStyleSheet(
            f"QSplitter::handle{{background:{D['border']};}}"
            f"QSplitter::handle:hover{{background:{D['acc']};}}"
        )

        # ── BAL OLDAL: tool panel (minden korábbi tartalom) ──────────────────
        tool_widget = QWidget()
        self._root = QVBoxLayout(tool_widget)
        self._root.setContentsMargins(14, 14, 14, 10)
        self._root.setSpacing(8)

        # Header
        hdr = QHBoxLayout()
        acc_c = D["acc"]
        t = QLabel(f"{self.ICON}  {self.TOOL_NAME}  "
                   f'<span style="color:{acc_c}">{self.host}</span>')
        t.setTextFormat(Qt.TextFormat.RichText)
        t.setStyleSheet(f"font-size:15px;font-weight:bold;color:{D['text']};")
        s = QLabel(self.SUBTITLE)
        s.setStyleSheet(f"color:{D['muted']};font-size:11px;")
        hdr.addWidget(t); hdr.addStretch(); hdr.addWidget(s)
        self._root.addLayout(hdr)

        # Target placeholder
        self._tgt_ph = QWidget(); self._tgt_ph.setFixedHeight(0)
        self._root.addWidget(self._tgt_ph)

        # Opts scroll
        self._osc = QScrollArea(); self._osc.setWidgetResizable(True); self._osc.setMaximumHeight(310)
        self._osc.setStyleSheet(f"QScrollArea{{background:{D['surf']};border:1px solid {D['border']};border-radius:5px;}}")
        self._oin = QWidget(); self._oin.setStyleSheet(f"background:{D['surf']};")
        self._ol = QVBoxLayout(self._oin); self._ol.setContentsMargins(8, 8, 8, 8); self._ol.setSpacing(2)
        self._osc.setWidget(self._oin); self._root.addWidget(self._osc)

        # Editable command preview
        pf = QFrame(); pf.setStyleSheet(f"background:{D['surf2']};border:1px solid {D['border']};border-radius:5px;")
        pl = QHBoxLayout(pf); pl.setContentsMargins(8, 4, 8, 4)
        dl = QLabel("$"); dl.setStyleSheet(f"color:{D['green']};font-size:12px;background:transparent;border:none;"); pl.addWidget(dl)
        self._cedit = QLineEdit()
        self._cedit.setStyleSheet(f"QLineEdit{{background:transparent;border:none;color:{D['text']};font-size:12px;font-family:monospace;padding:0;}}"); fp(self._cedit)
        self._cedit.setToolTip(T("tool.cmd_tip"))
        pl.addWidget(self._cedit, 1); self._root.addWidget(pf)

        # Output (SearchableOutput) + fullscreen gomb overlay a jobb alsó sarokba
        out_container = QWidget()
        out_container.setMinimumHeight(130)
        out_lay = QVBoxLayout(out_container); out_lay.setContentsMargins(0,0,0,0); out_lay.setSpacing(0)
        self._out = SearchableOutput(out_container)
        self._out.setPlaceholderText(f"{self.TOOL_NAME} kimenet...")
        out_lay.addWidget(self._out)

        # Fullscreen gomb — float overlay a jobb alsó sarokba
        self._fs_btn = QPushButton("⛶", out_container)
        self._fs_btn.setFixedSize(22, 22)
        self._fs_btn.setToolTip(T("tool.fs_expand"))
        self._fs_btn.setStyleSheet(
            f"QPushButton{{background:rgba(30,30,40,200);color:{D['muted']};border:1px solid {D['border']};"
            f"border-radius:4px;font-size:12px;padding:0;}}"
            f"QPushButton:hover{{background:{D['acc']};color:#fff;border-color:{D['acc']};}}"
        )
        self._fs_btn.clicked.connect(self._toggle_fullscreen_out)
        self._fs_mode = False

        # Pozicionálás: QTimer poll — elkerüli a resizeEvent override crash-t
        self._fs_pos_timer = QTimer(self)
        self._fs_pos_timer.setInterval(200)
        self._fs_pos_timer.timeout.connect(self._reposition_fs_btn)
        self._fs_pos_timer.start()

        self._root.addWidget(out_container)
        self._out_container = out_container

        # Buttons
        bl = QHBoxLayout()
        self._rbtn = QPushButton(T("btn.start")); self._rbtn.setStyleSheet(BRUN); self._rbtn.setFixedWidth(130); self._rbtn.clicked.connect(self._run)
        self._ebtn = QPushButton(T("btn.save")); self._ebtn.setStyleSheet(BMUT); self._ebtn.setFixedWidth(100); self._ebtn.clicked.connect(self._export_output)
        cb = QPushButton(T("btn.close")); cb.setStyleSheet(BMUT); cb.setFixedWidth(100); cb.clicked.connect(self.accept)
        bl.addStretch(); bl.addWidget(self._ebtn); bl.addWidget(cb); bl.addWidget(self._rbtn)
        self._root.addLayout(bl)

        self._main_splitter.addWidget(tool_widget)

        # ── JOBB OLDAL: Notes panel (kezdetben rejtve) ────────────────────────
        self._notes_panel_widget = QWidget()
        self._notes_panel_widget.setStyleSheet(
            f"background:{D['surf']};border-left:2px solid {D['border']};"
        )
        np_lay = QVBoxLayout(self._notes_panel_widget)
        np_lay.setContentsMargins(0, 0, 0, 0)
        self._notes_embed = NotesEditor(self._notes_panel_widget)
        np_lay.addWidget(self._notes_embed)
        self._main_splitter.addWidget(self._notes_panel_widget)

        # Kezdeti arányok: tool=100%, notes=0%
        self._main_splitter.setSizes([1, 0])
        self._main_splitter.setCollapsible(0, False)
        self._main_splitter.setCollapsible(1, True)
        self._notes_panel_open = False

        # Toggle gomb — a splitter jobb szélén, vékony függőleges sáv
        self._notes_toggle_btn = QPushButton("◀")
        self._notes_toggle_btn.setFixedWidth(18)
        self._notes_toggle_btn.setSizePolicy(
            QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding
        )
        self._notes_toggle_btn.setToolTip(T("notes.toggle_tip"))
        self._notes_toggle_btn.setStyleSheet(
            f"QPushButton{{background:{D['surf2']};color:{D['acc']};border:none;"
            f"border-left:1px solid {D['border']};font-size:10px;padding:0;}}"
            f"QPushButton:hover{{background:{D['acc']};color:#fff;}}"
        )
        self._notes_toggle_btn.clicked.connect(self._toggle_notes_panel)

        dialog_lay.addWidget(self._main_splitter, 1)
        dialog_lay.addWidget(self._notes_toggle_btn)

    def _sec(self,t):
        l=QLabel(t); l.setStyleSheet(f"color:{D['acc']};font-size:10px;font-weight:bold;letter-spacing:2px;background:transparent;padding:5px 0 2px 0;"); return l

    def _hbtn(self,tip):
        b=QPushButton("?"); b.setFixedSize(18,18)
        b.setStyleSheet(f"QPushButton{{background:{D['surf2']};color:{D['muted']};border:1px solid {D['border']};border-radius:9px;font-size:10px;font-weight:bold;padding:0;}}QPushButton:hover{{background:{D['acc']};color:#000;border-color:{D['acc']};}}")
        b.setToolTip(tip); b.clicked.connect(lambda _=False,t=tip: QToolTip.showText(QCursor.pos(),t)); return b

    def _brbtn(self,le):
        from PyQt6.QtGui import QIcon
        from PyQt6.QtCore import QSize
        b=QPushButton()
        b.setFixedSize(34,34)
        b.setToolTip(T("tool.file_browse"))
        b.setStyleSheet(f"""
            QPushButton {{
                background:{D['surf2']}; border:1px solid {D['border']};
                border-radius:5px; padding:0;
            }}
            QPushButton:hover {{ background:{D['border']}; border-color:{D['muted']}; }}
            QPushButton:pressed {{ background:{D['surf']}; }}
        """)
        # Try to load the SVG icon
        svg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "folder-activities.svg")
        if not os.path.exists(svg_path):
            # Fallback: look next to the script in common install dirs
            for d in [os.path.expanduser("~/.local/share/inscop3"),
                      os.path.dirname(os.path.abspath(__file__))]:
                candidate = os.path.join(d, "folder-activities.svg")
                if os.path.exists(candidate):
                    svg_path = candidate; break
        if os.path.exists(svg_path):
            icon = QIcon(svg_path)
            b.setIcon(icon)
            b.setIconSize(QSize(20, 20))
        else:
            b.setText("📂")
        def _br():
            p,_=QFileDialog.getOpenFileName(self,T("tool.file_browse"),"",T("tool.file_filter"))
            if p: le.setText(p)
        b.clicked.connect(_br); return b

    def _add_flag(self,layout,flag,help_,has_val,ph,defon=False,defval="",browse=False,quote=False):
        # help_ lehet string vagy {"hu":..., "en":...} dict
        h_text = help_.get(_LANG.lang, help_.get("en", "")) if isinstance(help_, dict) else help_
        row=QHBoxLayout(); row.setSpacing(5)
        cb=QCheckBox(flag); cb.setFixedWidth(180); cb.setStyleSheet(f"color:{D['text2']};font-size:12px;background:transparent;")
        if defon: cb.setChecked(True)
        row.addWidget(cb); row.addWidget(self._hbtn(h_text))
        le=None
        if has_val:
            le=QLineEdit(); le.setPlaceholderText(ph); le.setStyleSheet(INP+"QLineEdit{min-height:22px;font-size:12px;max-width:240px;}"); fp(le)
            if defval: le.setText(defval)
            le.setEnabled(cb.isChecked()); cb.toggled.connect(le.setEnabled)
            le.setProperty("quote",quote); le.textChanged.connect(self._update_cmd)
            row.addWidget(le)
            if browse: row.addWidget(self._brbtn(le))
        else:
            row.addStretch()
        row.addStretch(); cb.toggled.connect(self._update_cmd)
        layout.addLayout(row); self._flag_widgets.append((cb,le,flag)); return cb,le

    def _tgt_frame(self,prefixes=None):
        f=QFrame(); f.setStyleSheet(f"background:{D['surf']};border:1px solid {D['border']};border-radius:5px;")
        lay=QVBoxLayout(f); lay.setContentsMargins(10,8,10,8); lay.setSpacing(4)
        lay.addWidget(QLabel(T("tool.target_label")))
        self._tgt_group=QButtonGroup(self)
        seen=set()
        if prefixes:
            for pfx in prefixes:
                k=f"{pfx}{self.host}"
                if k not in seen: self._tgts.append(("HOST",k)); seen.add(k)
        else:
            self._tgts.append(("HOST",self.host)); seen.add(self.host)
        for rt,rv in self.dns_values:
            if rv and rv not in seen:
                if prefixes:
                    for pfx in prefixes:
                        k=f"{pfx}{rv}"
                        if k not in seen: self._tgts.append((rt,k)); seen.add(k); break
                else:
                    self._tgts.append((rt,rv)); seen.add(rv)
        for i,(rt,rv) in enumerate(self._tgts):
            rb=QRadioButton(f"  {rt}  {rv}"); rb.setStyleSheet(f"color:{D['text']};font-size:12px;background:transparent;border:none;")
            if i==0: rb.setChecked(True)
            self._tgt_group.addButton(rb,i); rb.toggled.connect(self._update_cmd); lay.addWidget(rb)
        return f

    def _ins_tgt(self,frame):
        self._root.insertWidget(1,frame)

    def _get_tgt(self):
        bid=self._tgt_group.checkedId() if self._tgt_group else -1
        return self._tgts[bid][1] if 0<=bid<len(self._tgts) else self.host

    def _build_flags(self): pass

    def _build_cmd(self): return self.TOOL_NAME

    def _update_cmd(self,*_):
        self._cedit.setText(self._build_cmd())

    def _colorize(self,line):
        safe=_html.escape(line); low=line.lower(); color=D['text2']
        if re.search(r'\bopen\b',line,re.I): color=D['green']
        elif re.search(r'\bclosed\b|\bfiltered\b',line,re.I): color=D['red']
        elif any(s in low for s in ["critical","[critical]"]): color="#ff4444"
        elif any(s in low for s in ["[high]"]): color=D['red']
        elif any(s in low for s in ["[medium]"]): color=D['orange']
        elif line.startswith(";"): color=D['dim']
        return safe,color

    def _on_out(self,line):
        # Strip ANSI and convert to colored HTML
        html_line = ansi_to_html(line)
        safe      = _html.escape(line)   # plain escaped for status checks
        low       = line.lower()

        # Special: dig STATUS line
        if "status:" in low:
            m=re.search(r'status:\s*(\w+)',line,re.I)
            if m:
                sv=m.group(1).upper()
                if sv=="NXDOMAIN":
                    self._out.insertHtml(
                        f"<div style='background:#2d1114;border:1px solid {D['red']};border-radius:4px;padding:5px 10px;margin:4px 0;'>"
                        f"<span style='color:{D['red']};font-weight:bold;'>{safe}</span><br>"
                        f"<span style='color:{D['red']};font-size:13pt;font-weight:bold;'>⚠ {T('scan.nxdomain')}</span></div>"); return
                elif sv=="NOERROR":
                    self._out.insertHtml(
                        f"<div style='background:#0d2114;border:1px solid {D['green']};border-radius:4px;padding:5px 10px;margin:4px 0;'>"
                        f"<span style='color:{D['green']};font-weight:bold;'>{safe}</span><br>"
                        f"<span style='color:{D['green']};font-size:13pt;font-weight:bold;'>✓ NOERROR</span></div>"); return

        if not line.strip(): self._out.insertHtml("<br>"); return

        # If ANSI codes were present, html_line differs from safe → use it directly
        raw_stripped = _re_ansi.sub(r'\x1b\[[0-9;]*m', '', line)
        if raw_stripped != line:
            # Had ANSI — use converted HTML
            self._out.insertHtml(f"{html_line}<br>")
        else:
            # No ANSI — use semantic colorizer
            _,color = self._colorize(line)
            self._out.insertHtml(f"<span style='color:{color}'>{safe}</span><br>")

    def _on_done(self,ok):
        self._rbtn.setText(T("btn.start")); self._rbtn.setStyleSheet(BRUN)
        c=D['green'] if ok else D['red']
        self._out.insertHtml(f"<br><span style='color:{c};font-weight:bold;'>{T('tool.done_ok') if ok else T('tool.done_err')}</span>")

    def _run(self):
        if self._rbtn.text().startswith("⏹"):
            if hasattr(self,'_worker') and self._worker: self._worker.stop()
            self._rbtn.setText(T("btn.start")); self._rbtn.setStyleSheet(BRUN); return
        cmd=self._cedit.text().strip() or self._build_cmd()
        self._out.clear()
        self._out.insertHtml(f"<span style='color:{D['muted']}'>$ {_html.escape(cmd)}</span><br><br>")
        self._rbtn.setText(T("btn.stop")); self._rbtn.setStyleSheet(BSTOP)
        try: parts=shlex.split(cmd)
        except: parts=cmd.split()
        self._worker=CmdWorker(parts); self._worker.output.connect(self._on_out); self._worker.finished.connect(self._on_done); self._worker.start()
    
    def _export_output(self):
        """Export console output to file"""
        from PyQt6.QtWidgets import QFileDialog
        path,_=QFileDialog.getSaveFileName(self,T("tool.export_title",name=self.TOOL_NAME),
            f"{self.TOOL_NAME}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
            T("tool.export_filter"))
        if path:
            ok,msg=self._out.export_text(path)
            if ok:
                self._out.insertHtml(f"<br><span style='color:{D['green']}'>✓ {msg}</span>")
            else:
                self._out.insertHtml(f"<br><span style='color:{D['red']}'>✗ {msg}</span>")

    def _reposition_fs_btn(self):
        """Fullscreen gomb pozicionálása a szövegterület (edit) jobb alsó sarkába."""
        if not hasattr(self, '_fs_btn') or not hasattr(self, '_out'): return
        edit = getattr(self._out, 'edit', None)
        if not edit: return
        # edit jobb alsó sarka, out_container koordináta-rendszerében
        bottom_right = self._out.mapTo(self._out_container, edit.rect().bottomRight())
        bw = self._fs_btn.width()
        bh = self._fs_btn.height()
        self._fs_btn.move(bottom_right.x() - bw - 6, bottom_right.y() - bh - 6)
        self._fs_btn.raise_()

    def _toggle_fullscreen_out(self):
        """Kimenet-panel teljes ablakra nagyítása / visszaállítása."""
        self._fs_mode = not self._fs_mode
        # Megkeressük az összes widgetet a tool panelen és elrejtjük/megjelenítjük
        for i in range(self._root.count()):
            item = self._root.itemAt(i)
            if item and item.widget():
                w = item.widget()
                if w is self._out_container:
                    continue  # az output mindig látható
                w.setVisible(not self._fs_mode)
            elif item and item.layout():
                # header layout: elrejtjük az egész sort
                for j in range(item.layout().count()):
                    sub = item.layout().itemAt(j)
                    if sub and sub.widget():
                        sub.widget().setVisible(not self._fs_mode)
        self._fs_btn.setText("✕" if self._fs_mode else "⛶")
        self._fs_btn.setToolTip(T("tool.fs_restore") if self._fs_mode else T("tool.fs_expand"))
        # Scroll area max magasság eltávolítása/visszaállítása
        if hasattr(self, '_osc'):
            self._osc.setMaximumHeight(16777215 if self._fs_mode else 310)

    def _toggle_notes_panel(self):
        """Jobb oldali notes panel — az EGÉSZ ablak felét nyitja/zárja."""
        total = self._main_splitter.width()
        if self._notes_panel_open:
            # Bezárás: tool=100%, notes=0%
            self._main_splitter.setSizes([total, 0])
            self._notes_toggle_btn.setText("◀")
            self._notes_panel_open = False
        else:
            # Megnyitás: pontosan 50-50%
            half = max(total // 2, 250)
            self._main_splitter.setSizes([half, half])
            self._notes_toggle_btn.setText("▶")
            self._notes_panel_open = True

# ─── Dig ─────────────────────────────────────────────────────────────────────
class DigDialog(BaseToolDialog):
    TOOL_NAME="dig"; ICON="⛏"; SUBTITLE="DNS lookup tool"
    FLAGS_BASIC=[
        # flag, help, has_value, placeholder
        ("-4",  "Use IPv4 query transport only",              False, ""),
        ("-6",  "Use IPv6 query transport only",              False, ""),
        ("-b",  "Bind to source address/port",                True,  "addr#port"),
        ("-c",  "Specify query class",                        True,  "in"),
        ("-k",  "Specify TSIG key file",                      True,  "/path/key.tsig"),
        ("-m",  "Enable memory usage debugging",              False, ""),
        ("-p",  "Specify port number",                        True,  "53"),
        ("-q",  "Specify query name",                         True,  "example.com"),
        ("-r",  "Do not read ~/.digrc",                       False, ""),
        ("-t",  "Specify query type (a,mx,ns,txt,soa,axfr…)", True,  "a"),
        ("-u",  "Display times in usec instead of msec",      False, ""),
        ("-x",  "Shortcut for reverse lookups (dot-notation)",True,  "1.2.3.4"),
        ("-y",  "Named base64 TSIG key ([hmac:]name:key)",    True,  "hmac-sha256:mykey:base64=="),
    ]
    FLAGS_DOPTS=[
        ("+aaflag",        "Set AA flag in query",                          False, ""),
        ("+additional",    "Control display of additional section",         False, ""),
        ("+adflag",        "Set AD flag in query (default on)",             False, ""),
        ("+all",           "Set or clear all display flags",                False, ""),
        ("+answer",        "Control display of answer section",             False, ""),
        ("+authority",     "Control display of authority section",          False, ""),
        ("+badcookie",     "Retry BADCOOKIE responses",                     False, ""),
        ("+besteffort",    "Try to parse even illegal messages",            False, ""),
        ("+bufsize",       "Set EDNS0 Max UDP packet size",                 True,  "512"),
        ("+cdflag",        "Set checking disabled flag in query",           False, ""),
        ("+class",         "Control display of class in records",           False, ""),
        ("+cmd",           "Control display of command line (global opt)",  False, ""),
        ("+comments",      "Control display of packet header/section names",False, ""),
        ("+cookie",        "Add a COOKIE option to the request",            False, ""),
        ("+crypto",        "Control display of cryptographic fields",       False, ""),
        ("+defname",       "Use search list (+search)",                     False, ""),
        ("+dns64prefix",   "Get DNS64 prefixes from ipv4only.arpa",        False, ""),
        ("+dnssec",        "Request DNSSEC records",                        False, ""),
        ("+domain",        "Set default domainname",                        True,  "example.com"),
        ("+edns",          "Set EDNS version",                              True,  "0"),
        ("+ednsflags",     "Set undefined EDNS flag bits",                  True,  "0x0"),
        ("+ednsnegotiation","Set EDNS version negotiation",                 False, ""),
        ("+ednsopt",       "Send specified EDNS option (code[:value])",     True,  "100:deadbeef"),
        ("+expandaaaa",    "Expand AAAA records",                           False, ""),
        ("+expire",        "Request time to expire",                        False, ""),
        ("+fail",          "Don't try next server on SERVFAIL",             False, ""),
        ("+header-only",   "Send query without a question section",         False, ""),
        ("+https",         "DNS-over-HTTPS mode",                           True,  "/dns-query"),
        ("+https-get",     "Use GET instead of POST for HTTPS",             False, ""),
        ("+http-plain",    "DNS over plain HTTP mode",                      True,  "/dns-query"),
        ("+http-plain-get","Use GET instead of POST for plain HTTP",        False, ""),
        ("+identify",      "ID responders in short answers",                False, ""),
        ("+idn",           "Convert international domain names",            False, ""),
        ("+ignore",        "Don't revert to TCP for TC responses",          False, ""),
        ("+keepalive",     "Request EDNS TCP keepalive",                    False, ""),
        ("+keepopen",      "Keep TCP socket open between queries",          False, ""),
        ("+multiline",     "Print records in an expanded format",           False, ""),
        ("+ndots",         "Set search NDOTS value",                        True,  "1"),
        ("+noall",         "Clear all display flags",                       False, ""),
        ("+nsid",          "Request Name Server ID",                        False, ""),
        ("+nssearch",      "Search all authoritative nameservers",          False, ""),
        ("+onesoa",        "AXFR prints only one SOA record",               False, ""),
        ("+opcode",        "Set the opcode of the request",                 True,  "0"),
        ("+padding",       "Set padding block size",                        True,  "0"),
        ("+proxy",         "Add PROXYv2 headers (src#port-dst#port)",       True,  ""),
        ("+qid",           "Specify the query ID",                          True,  "1234"),
        ("+qr",            "Print question before sending",                 False, ""),
        ("+question",      "Control display of question section",           False, ""),
        ("+recurse",       "Recursive mode (default on)",                   False, ""),
        ("+norecurse",     "Non-recursive query",                           False, ""),
        ("+retry",         "Set number of UDP retries",                     True,  "2"),
        ("+rrcomments",    "Control display of per-record comments",        False, ""),
        ("+search",        "Use searchlist",                                False, ""),
        ("+short",         "Display only short form of answers",            False, ""),
        ("+split",         "Split hex/base64 fields into chunks",           True,  "56"),
        ("+stats",         "Control display of statistics",                 False, ""),
        ("+nostats",       "Hide statistics",                               False, ""),
        ("+subnet",        "Set edns-client-subnet",                        True,  "0.0.0.0/0"),
        ("+tcp",           "Use TCP mode",                                  False, ""),
        ("+timeout",       "Set query timeout (seconds)",                   True,  "5"),
        ("+tls",           "DNS-over-TLS mode",                             False, ""),
        ("+tls-ca",        "Enable TLS cert validation (optionally: file)", True,  "/etc/ssl/certs/ca-bundle.crt"),
        ("+tls-hostname",  "Explicitly set expected TLS hostname",          True,  "dns.example.com"),
        ("+tls-certfile",  "Load client TLS certificate chain from file",   True,  "/path/client.crt"),
        ("+tls-keyfile",   "Load client TLS private key from file",         True,  "/path/client.key"),
        ("+trace",         "Trace delegation down from root (+dnssec)",     False, ""),
        ("+tries",         "Set number of UDP attempts",                    True,  "3"),
        ("+ttlid",         "Control display of TTLs in records",            False, ""),
        ("+ttlunits",      "Display TTLs in human-readable units",          False, ""),
        ("+unknownformat", "Print RDATA in RFC 3597 unknown format",        False, ""),
        ("+vc",            "TCP mode (+tcp)",                               False, ""),
        ("+yaml",          "Present the results as YAML",                   False, ""),
        ("+zflag",         "Set Z flag in query",                           False, ""),
    ]
    def _build_flags(self):
        self._ins_tgt(self._tgt_frame())
        self._ol.addWidget(self._sec(T("dig.flags")))
        for flag,h,hv,ph in self.FLAGS_BASIC:
            self._add_flag(self._ol, flag, h, hv, ph)
        self._ol.addWidget(self._sec(T("dig.query_opts")))
        for flag,h,hv,ph in self.FLAGS_DOPTS:
            self._add_flag(self._ol, flag, h, hv, ph)
        self._ol.addStretch()
    def _build_cmd(self):
        p=["dig"]
        for cb,le,f in self._flag_widgets:
            if cb.isChecked():
                p.append(f)
                if le and le.text().strip(): p.append(le.text().strip())
        p.append(self._get_tgt())
        return " ".join(p)

class HttpxDialog(BaseToolDialog):
    TOOL_NAME="httpx"; ICON="🌐"; SUBTITLE="Fast HTTP toolkit"

    def __init__(self,host,dns,rate=5,ua="",hdr="",parent=None):
        self._r=rate; self._ua=ua; self._hdr=hdr
        super().__init__(host,dns,parent)

    SECTIONS = [
        ("PROBES", [
            ("-sc",     "Display response status-code",                             False, "",      True),
            ("-cl",     "Display response content-length",                          False, "",      False),
            ("-ct",     "Display response content-type",                            False, "",      False),
            ("-location","Display response redirect location",                      False, "",      False),
            ("-favicon", "Display mmh3 hash for /favicon.ico",                      False, "",      False),
            ("-hash",   "Display response body hash (md5,mmh3,sha1,sha256,sha512)", True,  "sha256",False),
            ("-jarm",   "Display JARM fingerprint hash",                            False, "",      False),
            ("-rt",     "Display response time",                                    False, "",      False),
            ("-lc",     "Display response body line count",                         False, "",      False),
            ("-wc",     "Display response body word count",                         False, "",      False),
            ("-title",  "Display page title",                                       False, "",      True),
            ("-bp",     "Display first N chars of response body (default 100)",     True,  "100",   False),
            ("-server", "Display server name",                                      False, "",      True),
            ("-td",     "Display technology (wappalyzer)",                          False, "",      True),
            ("-cff",    "Custom fingerprint file for tech detection",               True,  "/path/fingerprints.yaml", False),
            ("-cpe",    "Display CPE (Common Platform Enumeration)",                False, "",      False),
            ("-wp",     "Display WordPress plugins and themes",                     False, "",      False),
            ("-method", "Display HTTP request method",                              False, "",      False),
            ("-ws",     "Display server using WebSocket",                           False, "",      False),
            ("-ip",     "Display host IP address",                                  False, "",      False),
            ("-cname",  "Display host CNAME",                                       False, "",      False),
            ("-efqdn",  "Get domain/subdomains from response body+header",          False, "",      False),
            ("-asn",    "Display host ASN information",                             False, "",      False),
            ("-cdn",    "Display CDN/WAF in use (default true)",                    False, "",      False),
            ("-probe",  "Display probe status",                                     False, "",      False),
        ]),
        ("HEADLESS", [
            ("-ss",                  "Enable screenshot via headless browser",      False, "",      False),
            ("-system-chrome",       "Use local installed Chrome for screenshot",   False, "",      False),
            ("-ho",                  "Headless Chrome additional options",          True,  "--disable-gpu",  False),
            ("-esb",                 "Exclude screenshot bytes from JSON output",   False, "",      False),
            ("-ehb",                 "Exclude headless header from JSON output",    False, "",      False),
            ("-no-screenshot-full-page","Disable full page screenshot",             False, "",      False),
            ("-st",                  "Screenshot timeout (e.g. 10s)",               True,  "10s",   False),
            ("-sid",                 "Screenshot idle time before capture (e.g. 1s)",True, "1s",   False),
            ("-jsc",                 "Execute JavaScript after navigation",          True,  "document.title", False),
        ]),
        ("MATCHERS", [
            ("-mc",   "Match status code(s) (e.g. 200,302)",                       True,  "200,302",  False),
            ("-ml",   "Match content length (e.g. 100,102)",                       True,  "100",      False),
            ("-mlc",  "Match body line count",                                     True,  "423,532",  False),
            ("-mwc",  "Match body word count",                                     True,  "43,55",    False),
            ("-mfc",  "Match favicon hash",                                        True,  "1494302000",False),
            ("-ms",   "Match string in response",                                  True,  "admin",    False),
            ("-mr",   "Match regex in response",                                   True,  "api[_-]?key",False),
            ("-mcdn", "Match CDN provider (cloudfront, fastly, cloudflare…)",      True,  "cloudfront",False),
            ("-mrt",  "Match response time (e.g. '< 1')",                          True,  "< 1",      False),
            ("-mdc",  "Match DSL expression condition",                            True,  "status_code==200 && content_length>0", False),
        ]),
        ("EXTRACTOR", [
            ("-er",   "Extract response content with regex",                       True,  r"api[_-]?key[\s=:]+[\w-]+", False),
            ("-ep",   "Extract preset regex (url,ipv4,mail)",                      True,  "url,ipv4,mail", False),
        ]),
        ("FILTERS", [
            ("-fc",   "Filter status code(s) (e.g. 403,401)",                     True,  "403,401",  False),
            ("-fpt",  "Filter page type (login,captcha,parked)",                   True,  "parked",   False),
            ("-fd",   "Filter near-duplicate responses",                           False, "",         False),
            ("-fl",   "Filter content length",                                     True,  "23,33",    False),
            ("-flc",  "Filter body line count",                                    True,  "423,532",  False),
            ("-fwc",  "Filter body word count",                                    True,  "423,532",  False),
            ("-ffc",  "Filter favicon hash",                                       True,  "1494302000",False),
            ("-fs",   "Filter string in response",                                 True,  "error",    False),
            ("-fe",   "Filter regex in response",                                  True,  "cloudflare",False),
            ("-fcdn", "Filter CDN provider",                                       True,  "cloudfront",False),
            ("-frt",  "Filter response time (e.g. '> 1')",                         True,  "> 1",      False),
            ("-fdc",  "Filter DSL expression condition",                           True,  "status_code==404",False),
            ("-strip","Strip HTML/XML tags from response",                         False, "",         False),
            ("-eof",  "Exclude output fields based on condition",                  True,  "status_code==200",False),
        ]),
        ("RATE-LIMIT", [
            ("-t",    "Number of threads (default 50)",                            True,  "50",       False),
            ("-rl",   "Max requests per second (auto from rate limit)",            True,  "150",      False),
            ("-rlm",  "Max requests per minute",                                   True,  "1000",     False),
        ]),
        ("CONFIG", [
            ("-H",           "Custom HTTP header(s) (auto from sidebar)",          True,  "X-Custom: value", False),
            ("-fr",          "Follow HTTP redirects",                              False, "",         True),
            ("-maxr",        "Max redirects per host (default 10)",                True,  "10",       False),
            ("-fhr",         "Follow redirects on same host only",                 False, "",         False),
            ("-rhsts",       "Respect HSTS headers for redirect",                  False, "",         False),
            ("-random-agent","Enable random User-Agent (default true)",            False, "",         False),
            ("-auto-referer","Set Referer header to current URL",                  False, "",         False),
            ("-proxy",       "HTTP/SOCKS proxy (e.g. http://127.0.0.1:8080)",      True,  "http://127.0.0.1:8080", False),
            ("-x",           "Request methods to probe (use 'all' for all)",       True,  "GET,POST,PUT", False),
            ("-body",        "POST body to include in request",                    True,  "key=value",False),
            ("-sni",         "Custom TLS SNI name",                                True,  "example.com",False),
            ("-unsafe",      "Send raw requests, skip golang normalization",       False, "",         False),
            ("-ztls",        "Use ztls with autofallback for TLS1.3",              False, "",         False),
            ("-tlsi",        "Experimental TLS client hello (ja3) randomization",  False, "",         False),
            ("-no-decode",   "Avoid decoding response body",                       False, "",         False),
            ("-r",           "Custom resolvers (file or comma-separated)",         True,  "8.8.8.8,1.1.1.1",False),
            ("-allow",       "Allowed IP/CIDR list to process",                    True,  "192.168.0.0/24",False),
            ("-deny",        "Denied IP/CIDR list",                                True,  "10.0.0.0/8",False),
            ("-sf",          "Secret file for authentication",                     True,  "/path/secrets.yaml",False),
            ("-resume",      "Resume scan using resume.cfg",                       False, "",         False),
            ("-s",           "Stream mode (no sorting)",                           False, "",         False),
            ("-sd",          "Skip deduplication (stream mode only)",              False, "",         False),
            ("-ldp",         "Leave default http/https ports in host header",      False, "",         False),
            ("-hae",         "Experimental HTTP API endpoint",                     True,  "http://127.0.0.1:9090",False),
        ]),
        ("MISCELLANEOUS", [
            ("-pa",          "Probe all IPs for same host",                        False, "",         False),
            ("-p",           "Ports to probe (nmap syntax)",                       True,  "80,443,8080",False),
            ("-path",        "Path(s) to probe (comma-separated or file)",         True,  "/,/api,/admin",False),
            ("-tls-probe",   "Send HTTP probes on extracted TLS domains",          False, "",         False),
            ("-csp-probe",   "Send HTTP probes on extracted CSP domains",          False, "",         False),
            ("-tls-grab",    "Perform TLS/SSL data grabbing",                      False, "",         False),
            ("-pipeline",    "Probe HTTP1.1 pipeline support",                     False, "",         False),
            ("-http2",       "Probe HTTP/2 support",                               False, "",         False),
            ("-vhost",       "Probe VHOST support",                                False, "",         False),
        ]),
        ("OUTPUT", [
            ("-o",     "Output file",                                              True,  "/tmp/httpx.json", False),
            ("-oa",    "Output all formats to filename base",                      True,  "/tmp/httpx_all",  False),
            ("-sr",    "Store HTTP responses to directory",                        False, "",         False),
            ("-srd",   "Store responses to custom directory",                      True,  "/tmp/httpx_resp/",False),
            ("-ob",    "Omit response body from output",                           False, "",         False),
            ("-csv",   "CSV output format",                                        False, "",         False),
            ("-j",     "JSONL output format",                                      False, "",         False),
            ("-md",    "Markdown table output",                                    False, "",         False),
            ("-irh",   "Include response headers in JSON",                         False, "",         False),
            ("-irr",   "Include request+response (headers+body) in JSON",          False, "",         False),
            ("-irrb",  "Include base64 encoded req/resp in JSON",                  False, "",         False),
            ("-include-chain","Include redirect chain in JSON",                    False, "",         False),
            ("-store-chain", "Include redirect chain in stored responses",         False, "",         False),
            ("-pr",    "Protocol (unknown, http11, http2, http3)",                 True,  "http11",   False),
            ("-fepp",  "Path to store filtered error pages",                       True,  "/tmp/filtered_errors.json",False),
        ]),
        ("DATABASE OUTPUT", [
            ("-rdb",   "Store results in database",                                False, "",         False),
            ("-rdbc",  "Path to database config file",                             True,  "/path/db.yaml",False),
            ("-rdbt",  "Database type (mongodb, postgres, mysql)",                 True,  "postgres",  False),
            ("-rdbcs", "Database connection string",                               True,  "postgres://user:pass@host/db",False),
            ("-rdbn",  "Database name (default: httpx)",                           True,  "httpx",    False),
            ("-rdbtb", "Table/collection name (default: results)",                 True,  "results",  False),
            ("-rdbbs", "Batch size for DB inserts (default 100)",                  True,  "100",      False),
            ("-rdbor", "Omit raw request/response data from DB",                   False, "",         False),
        ]),
        ("OPTIMIZATION", [
            ("-retries","Number of retries",                                       True,  "3",        False),
            ("-timeout","Timeout in seconds (default 10)",                         True,  "10",       False),
            ("-delay",  "Delay between requests (e.g. 200ms, 1s)",                True,  "200ms",    False),
            ("-nf",     "Display both HTTPS and HTTP probed protocol",             False, "",         False),
            ("-nfs",    "Probe with protocol scheme from input",                   False, "",         False),
            ("-maxhr",  "Max errors per host before skip (default 30)",            True,  "30",       False),
            ("-e",      "Exclude host filter (cdn, private-ips, cidr, regex)",     True,  "cdn",      False),
            ("-rsts",   "Max response size to save (bytes)",                       True,  "512000000",False),
            ("-rstr",   "Max response size to read (bytes)",                       True,  "512000000",False),
        ]),
        ("DEBUG", [
            ("-hc",          "Run health check",                                   False, "",         False),
            ("-debug",       "Display request/response content in CLI",            False, "",         False),
            ("-debug-req",   "Display request content in CLI",                     False, "",         False),
            ("-debug-resp",  "Display response content in CLI",                    False, "",         False),
            ("-version",     "Display httpx version",                              False, "",         False),
            ("-stats",       "Display scan statistics",                            False, "",         False),
            ("-profile-mem", "Memory profile dump file",                           True,  "/tmp/httpx_mem.prof",False),
            ("-silent",      "Silent mode",                                        False, "",         False),
            ("-v",           "Verbose mode",                                       False, "",         False),
            ("-si",          "Stats update interval (seconds)",                    True,  "5",        False),
            ("-nc",          "Disable colors in CLI output",                       False, "",         False),
            ("-tr",          "Trace mode",                                         False, "",         False),
        ]),
    ]

    def _build_flags(self):
        self._ins_tgt(self._tgt_frame())
        for sec_name, flags in self.SECTIONS:
            self._ol.addWidget(self._sec(sec_name))
            for entry in flags:
                flag, h, hv, ph, defon = entry
                browse = flag in ("-o", "-oa", "-srd", "-cff", "-sf", "-rdbc", "-fepp", "-profile-mem")
                cb, le = self._add_flag(self._ol, flag, h, hv, ph, defon, "", browse)
                # Auto-fill header and rate
                if flag == "-H" and (self._hdr or self._ua) and le:
                    parts = []
                    if self._hdr: parts.append(f'"{self._hdr}"')
                    if self._ua:  parts.append(f'"User-Agent: {self._ua}"')
                    le.setText(" -H ".join(parts)); cb.setChecked(True); le.setEnabled(True)
                if flag == "-rl" and self._r > 0 and le:
                    le.setText(str(self._r)); cb.setChecked(True); le.setEnabled(True)
        self._ol.addStretch()

    def _build_cmd(self):
        p = ["httpx", "-u", self._get_tgt()]
        for cb, le, f in self._flag_widgets:
            if cb.isChecked():
                p.append(f)
                if le and le.text().strip():
                    v = le.text().strip()
                    if f == "-H" and not v.startswith('"'): v = f'"{v}"'
                    p.append(v)
        return " ".join(p)

class DnsxDialog(BaseToolDialog):
    TOOL_NAME="dnsx"; ICON="🔎"; SUBTITLE="Fast DNS toolkit"

    SECTIONS = [
        ("QUERY TYPES", [
            ("-a",            "Query A record (default)",                           False, "", True),
            ("-aaaa",         "Query AAAA record",                                  False, "", False),
            ("-cname",        "Query CNAME record",                                 False, "", True),
            ("-ns",           "Query NS record",                                    False, "", False),
            ("-txt",          "Query TXT record",                                   False, "", False),
            ("-srv",          "Query SRV record",                                   False, "", False),
            ("-ptr",          "Query PTR record",                                   False, "", False),
            ("-mx",           "Query MX record",                                    False, "", False),
            ("-soa",          "Query SOA record",                                   False, "", False),
            ("-any",          "Query ANY record",                                   False, "", False),
            ("-axfr",         "Query AXFR (zone transfer)",                         False, "", False),
            ("-caa",          "Query CAA record",                                   False, "", False),
            ("-all",          "Query ALL records (a,aaaa,cname,ns,txt,srv,ptr,mx,soa,axfr,caa)", False, "", False),
            ("-e",            "Exclude query type(s) (e.g. a,cname)",               True,  "aaaa,axfr", False),
        ]),
        ("FILTER", [
            ("-resp",         "Display DNS response",                               False, "", True),
            ("-resp-only",    "Display DNS response only (no hostname)",            False, "", False),
            ("-rcode",        "Filter by DNS status code (noerror,servfail,refused)",True,"noerror", False),
            ("-rtf",          "Return entries with NO records for specified type",  True,  "a,cname", False),
        ]),
        ("PROBE", [
            ("-cdn",          "Display CDN name for resolved host",                 False, "", False),
            ("-asn",          "Display host ASN information",                       False, "", False),
        ]),
        ("RATE-LIMIT", [
            ("-t",            "Concurrent threads (default 100)",                   True,  "100", False),
            ("-rl",           "DNS requests per second (default: disabled)",        True,  "100", False),
        ]),
        ("OUTPUT", [
            ("-o",            "Output file",                                        True,  "/tmp/dnsx_out.txt", False),
            ("-j",            "Write output in JSONL format",                       False, "", False),
            ("-omit-raw",     "Omit raw DNS response from JSONL output",            False, "", False),
        ]),
        ("OPTIMIZATION", [
            ("-retry",        "DNS attempts per query (min 1, default 2)",          True,  "2",    False),
            ("-hf",           "Use system hosts file",                              False, "",     False),
            ("-trace",        "Perform DNS tracing",                                False, "",     False),
            ("-trace-max-recursion","Max recursion for DNS trace (default 255)",    True,  "255",  False),
            ("-resume",       "Resume existing scan",                               False, "",     False),
            ("-stream",       "Stream mode (disables resume/wildcard/stats)",       False, "",     False),
            ("-timeout",      "Max time for a DNS query (default 3s)",              True,  "3s",   False),
        ]),
        ("CONFIGURATIONS", [
            ("-r",            "Custom resolvers (file or comma-separated)",         True,  "8.8.8.8,1.1.1.1", False),
            ("-wt",           "Wildcard filter threshold (default 5)",              True,  "5",    False),
            ("-wd",           "Wildcard domain for filtering (JSON output only)",   True,  "example.com", False),
            ("-proxy",        "SOCKS5 proxy (e.g. socks5://127.0.0.1:1080)",        True,  "socks5://127.0.0.1:1080", False),
        ]),
        ("DEBUG", [
            ("-hc",           "Run diagnostic health check",                        False, "", False),
            ("-silent",       "Display only results in output",                     False, "", False),
            ("-v",            "Verbose output",                                     False, "", False),
            ("-raw",          "Display raw DNS response",                           False, "", False),
            ("-stats",        "Display scan statistics",                            False, "", False),
            ("-version",      "Display dnsx version",                               False, "", False),
            ("-nc",           "Disable color in output",                            False, "", False),
        ]),
    ]

    def _build_flags(self):
        self._ins_tgt(self._tgt_frame())
        for sec_name, flags in self.SECTIONS:
            self._ol.addWidget(self._sec(sec_name))
            for flag, h, hv, ph, defon in flags:
                self._add_flag(self._ol, flag, h, hv, ph, defon, "",
                               flag in ["-o"])
        self._ol.addStretch()

    def _build_cmd(self):
        p = ["dnsx", "-u", self._get_tgt()]
        for cb, le, f in self._flag_widgets:
            if cb.isChecked():
                p.append(f)
                if le and le.text().strip(): p.append(le.text().strip())
        return " ".join(p)

class CurlDialog(BaseToolDialog):
    TOOL_NAME="curl"; ICON="🌐"; SUBTITLE="HTTP transfer tool"

    def __init__(self,host,dns,ua="",hdr="",parent=None):
        self._ua=ua; self._hdr=hdr
        super().__init__(host,dns,parent)

    SECTIONS = [
        ("HTTP REQUEST", [
            # flag, help, has_value, placeholder, default_on, quote_value
            ("-i",              "Show response headers in output",                          False, "", True,  False),
            ("-I",              "HEAD request — show document info only",                  False, "", False, False),
            ("-X",              "Request method (GET, POST, PUT, DELETE, PATCH…)",         True,  "POST", False, False),
            ("-d",              "HTTP POST data (sends as application/x-www-form-urlencoded)",True,"key=value&key2=val2",False,False),
            ("-d@",             "Send POST data from file",                                 True,  "/path/data.txt",False,False),
            ("--data-urlencode","URL-encode POST data",                                    True,  "param=value with spaces",False,False),
            ("--data-raw",      "Send raw POST data (no @ file interpretation)",           True,  "raw string here",False,False),
            ("--data-binary",   "Send binary POST data",                                   True,  "@/path/file.bin",False,False),
            ("-G",              "Force GET — append -d data as URL query string",          False, "", False, False),
            ("-F",              "Multipart form data (file upload)",                       True,  "file=@/path/to/file", False,False),
            ("--json",          "Send JSON data (sets Content-Type: application/json)",    True,  '{"key":"value"}', False, True),
            ("--upload-file",   "Transfer local file to destination (PUT)",                True,  "/path/to/file",  False,False),
        ]),
        ("HEADERS & AUTH", [
            ("-H",              "Custom header (auto-filled from sidebar)",                True,  "X-Custom: value", False, True),
            ("-A",              "User-Agent string (auto-filled from sidebar)",            True,  "Mozilla/5.0",     False, True),
            ("-e",              "Referer URL",                                             True,  "https://example.com",False,False),
            ("-u",              "Server user:password (Basic Auth)",                       True,  "user:password",  False, True),
            ("-n",              "Use .netrc for credentials",                              False, "", False, False),
            ("--oauth2-bearer", "OAuth 2 Bearer Token",                                   True,  "your_token_here", False, True),
            ("--negotiate",     "Use HTTP Negotiate (SPNEGO) authentication",             False, "", False, False),
            ("--ntlm",          "Use HTTP NTLM authentication",                           False, "", False, False),
            ("--digest",        "Use HTTP Digest authentication",                         False, "", False, False),
            ("--anyauth",       "Use any available authentication method",                False, "", False, False),
            ("-b",              "Send cookies (string or cookie file path)",               True,  "name=value; name2=val2",False,True),
            ("-c",              "Write received cookies to file (cookie jar)",             True,  "/tmp/cookies.txt",False,False),
            ("--cookie-jar",    "Same as -c (write cookies to file)",                     True,  "/tmp/cookies.txt",False,False),
        ]),
        ("TLS / SSL", [
            ("-k",              "Allow insecure SSL connections (skip cert verify)",       False, "", False, False),
            ("--cert",          "Client certificate file (PEM) and optional password",    True,  "/path/cert.pem",  False,False),
            ("--cert-type",     "Certificate type (PEM, DER, ENG, P12)",                  True,  "PEM",             False,False),
            ("--key",           "Private key file",                                       True,  "/path/key.pem",   False,False),
            ("--key-type",      "Private key type (PEM, DER, ENG)",                       True,  "PEM",             False,False),
            ("--cacert",        "CA certificate bundle to verify peer",                   True,  "/etc/ssl/certs/ca-bundle.crt",False,False),
            ("--capath",        "Directory with CA certificates",                         True,  "/etc/ssl/certs/",False,False),
            ("--crlfile",       "Certificate Revocation List file",                       True,  "/path/crl.pem",  False,False),
            ("--pinnedpubkey",  "Pinned public key (PEM/DER file or sha256// hash)",      True,  "sha256//base64==",False,False),
            ("--tls-max",       "Maximum TLS version (1.0, 1.1, 1.2, 1.3)",               True,  "1.3",             False,False),
            ("--tlsv1",         "Use TLS v1.x or later",                                  False, "", False, False),
            ("--tlsv1.2",       "Use TLS v1.2 or later",                                  False, "", False, False),
            ("--tlsv1.3",       "Use TLS v1.3 or later",                                  False, "", False, False),
            ("--ssl-revoke-best-effort","Ignore cert revocation checks if offline",       False, "", False, False),
            ("--ciphers",       "SSL cipher list to use",                                 True,  "ECDHE-RSA-AES256-GCM-SHA384",False,False),
        ]),
        ("CONNECTION", [
            ("-L",              "Follow redirects",                                        False, "", False, False),
            ("--max-redirs",    "Maximum number of redirects (default 30)",                True,  "10",  False,False),
            ("-m",              "Maximum operation time in seconds",                       True,  "30",  False,False),
            ("--connect-timeout","Seconds until connection timeout",                      True,  "10",  False,False),
            ("--speed-limit",   "Stop if slower than this (bytes/sec)",                   True,  "1000",False,False),
            ("--speed-time",    "Trigger speed-limit check after N seconds",              True,  "30",  False,False),
            ("-x",              "Proxy (protocol://host:port)",                            True,  "http://127.0.0.1:8080",False,False),
            ("-U",              "Proxy user:password",                                    True,  "user:pass",False,True),
            ("--socks5",        "SOCKS5 proxy host:port",                                 True,  "127.0.0.1:1080",False,False),
            ("--socks5-hostname","SOCKS5 with remote DNS resolution",                     True,  "127.0.0.1:1080",False,False),
            ("--noproxy",       "Comma-separated list of hosts to bypass proxy",          True,  "localhost,127.0.0.1",False,False),
            ("--interface",     "Use specified network interface/IP address",             True,  "eth0",False,False),
            ("-4",              "Resolve and connect to IPv4 addresses only",             False, "", False, False),
            ("-6",              "Resolve and connect to IPv6 addresses only",             False, "", False, False),
            ("--retry",         "Retry request N times on transient errors",              True,  "3",   False,False),
            ("--retry-delay",   "Wait N seconds between retries",                         True,  "5",   False,False),
            ("--retry-max-time","Give up retrying after N seconds total",                 True,  "60",  False,False),
            ("--keepalive-time","Interval for keepalive probes (seconds)",                True,  "60",  False,False),
            ("--no-keepalive",  "Disable TCP keepalive",                                  False, "", False, False),
        ]),
        ("HTTP VERSION", [
            ("--http1.0",       "Use HTTP 1.0",                                            False, "", False, False),
            ("--http1.1",       "Use HTTP 1.1",                                            False, "", False, False),
            ("--http2",         "Use HTTP/2 (fallback to HTTP/1.1)",                       False, "", False, False),
            ("--http2-prior-knowledge","Use HTTP/2 without HTTP/1.1 upgrade",             False, "", False, False),
            ("--http3",         "Use HTTP/3 (QUIC)",                                       False, "", False, False),
            ("--compressed",    "Request compressed response (Accept-Encoding)",           False, "", False, False),
            ("--tr-encoding",   "Request chunked Transfer-Encoding",                       False, "", False, False),
            ("--compressed-ssh","Enable OpenSSH's built-in compression",                  False, "", False, False),
        ]),
        ("OUTPUT", [
            ("-o",              "Write output to file instead of stdout",                  True,  "/tmp/curl_out.txt",False,False),
            ("-O",              "Write output to file named as remote file",               False, "", False, False),
            ("-s",              "Silent mode — no progress or error messages",             False, "", False, False),
            ("-S",              "Show error even when -s is used",                         False, "", False, False),
            ("-v",              "Verbose — show full request+response details",            False, "", False, False),
            ("--trace",         "Dump full trace to file",                                 True,  "/tmp/curl_trace.txt",False,False),
            ("--trace-ascii",   "Dump ASCII trace to file",                                True,  "/tmp/curl_trace.txt",False,False),
            ("-w",              "Output format after completion",                          True,  "%{http_code}\\n%{time_total}\\n%{size_download}",False,False),
            ("-D",              "Write received headers to file",                          True,  "/tmp/curl_headers.txt",False,False),
            ("--dump-header",   "Same as -D — write headers to file",                     True,  "/tmp/headers.txt",False,False),
            ("-R",              "Use remote file's time on local output",                  False, "", False, False),
            ("-J",              "Use server-supplied filename for -O",                     False, "", False, False),
            ("-Z",              "Parallel transfers (multi)",                              False, "", False, False),
        ]),
        ("DNS", [
            ("--dns-servers",   "DNS servers to use (comma-separated)",                   True,  "8.8.8.8,1.1.1.1",False,False),
            ("--dns-ipv4-addr", "IPv4 address to bind DNS queries to",                    True,  "0.0.0.0",False,False),
            ("--dns-ipv6-addr", "IPv6 address to bind DNS queries to",                    True,  "::",False,False),
            ("--resolve",       "Resolve host:port to address (host:port:addr)",          True,  "example.com:443:1.2.3.4",False,False),
            ("--connect-to",    "Connect to host2:port2 instead of host:port",            True,  "example.com:443:target.com:443",False,False),
            ("--doh-url",       "DNS-over-HTTPS resolver URL",                             True,  "https://1.1.1.1/dns-query",False,False),
            ("--doh-insecure",  "Allow insecure DoH server connection",                   False, "", False, False),
        ]),
        ("MISC", [
            ("-V",              "Show curl version and exit",                              False, "", False, False),
            ("--path-as-is",    "Do not squash .. sequences in URL path",                 False, "", False, False),
            ("--disallow-username-in-url","Disallow username in URL",                     False, "", False, False),
            ("--local-port",    "Use specified local port range (num or range)",          True,  "10000-10100",False,False),
            ("--proto",         "Enable/disable specified protocols",                     True,  "https",False,False),
            ("--proto-redir",   "Enable/disable protocols on redirect",                   True,  "https",False,False),
            ("--max-filesize",  "Maximum file size to download (bytes)",                  True,  "10485760",False,False),
            ("--limit-rate",    "Limit transfer speed (e.g. 500k, 2M)",                   True,  "500k",False,False),
            ("--no-buffer",     "Disable output stream buffering",                        False, "", False, False),
            ("--stderr",        "Redirect stderr to file",                                True,  "/tmp/curl_err.txt",False,False),
            ("-q",              "Disable .curlrc config file",                            False, "", False, False),
            ("-K",              "Read config from file",                                   True,  "/path/.curlrc",False,False),
        ]),
    ]

    def _build_flags(self):
        # URL frame
        uf=QFrame(); uf.setStyleSheet(f"background:{D['surf']};border:1px solid {D['border']};border-radius:5px;")
        ul=QVBoxLayout(uf); ul.setContentsMargins(10,8,10,8); ul.setSpacing(4)
        pr_row=QHBoxLayout()
        ul.addWidget(QLabel("URL:"))
        self._proto=QComboBox(); self._proto.addItems(["https://","http://"])
        self._proto.setStyleSheet(CMB+"QComboBox{min-height:26px;font-size:12px;max-width:110px;}")
        self._proto.currentTextChanged.connect(self._update_cmd)
        pr_row.addWidget(self._proto); pr_row.addStretch(); ul.addLayout(pr_row)
        self._tgts=[("HOST",self.host)]; seen={self.host}
        self._tgt_group=QButtonGroup(self)
        for rt,rv in self.dns_values:
            if rv and rv not in seen: self._tgts.append((rt,rv)); seen.add(rv)
        for i,(rt,rv) in enumerate(self._tgts):
            rb=QRadioButton(f"  {rt}  {rv}"); rb.setStyleSheet(f"color:{D['text']};font-size:12px;background:transparent;border:none;")
            if i==0: rb.setChecked(True)
            self._tgt_group.addButton(rb,i); rb.toggled.connect(self._update_cmd); ul.addWidget(rb)
        path_row=QHBoxLayout(); path_row.addWidget(QLabel("Path:"))
        self._path=QLineEdit(); self._path.setPlaceholderText("/path (optional)")
        self._path.setStyleSheet(INP+"QLineEdit{min-height:26px;font-size:12px;}"); fp(self._path)
        self._path.textChanged.connect(self._update_cmd); path_row.addWidget(self._path); ul.addLayout(path_row)
        self._ins_tgt(uf)

        for sec_name, flags in self.SECTIONS:
            self._ol.addWidget(self._sec(sec_name))
            for entry in flags:
                flag, h, hv, ph, defon, quote = entry
                browse = flag in ["-o","--trace","--trace-ascii","-D","--dump-header","--stderr","-K"]
                cb, le = self._add_flag(self._ol, flag, h, hv, ph, defon, "", browse, quote)
                if flag=="-A" and self._ua and le:
                    le.setText(f'"{self._ua}"'); cb.setChecked(True); le.setEnabled(True)
                if flag=="-H" and self._hdr and le:
                    le.setText(f'"{self._hdr}"'); cb.setChecked(True); le.setEnabled(True)
        self._ol.addStretch()

    def _get_url(self):
        bid=self._tgt_group.checkedId() if self._tgt_group else 0
        tgt=self._tgts[bid][1] if 0<=bid<len(self._tgts) else self.host
        pfx=self._proto.currentText(); path=self._path.text().strip()
        if path and not path.startswith("/"): path="/"+path
        return f"{pfx}{tgt}{path}"

    def _build_cmd(self):
        p=["curl"]
        for cb,le,f in self._flag_widgets:
            if cb.isChecked():
                p.append(f)
                if le and le.text().strip():
                    v=le.text().strip()
                    if le.property("quote") and not v.startswith('"'): v=f'"{v}"'
                    p.append(v)
        p.append(self._get_url()); return " ".join(p)

class WgetDialog(BaseToolDialog):
    TOOL_NAME="wget"; ICON="⬇"; SUBTITLE="Non-interactive network downloader"

    def __init__(self,host,dns,ua="",hdr="",parent=None):
        self._ua=ua; self._hdr=hdr
        super().__init__(host,dns,parent)

    SECTIONS = [
        ("wget.startup", [
            ("-b",                  {"hu": "Indítás után folytatás a háttérben", "en": "Continue in background after startup"},                  False, ""),
            ("-e",                  {"hu": ".wgetrc stílusú parancs végrehajtása", "en": "Execute .wgetrc-style command"},                 True,  "robots=off"),
        ]),
        ("wget.logging", [
            ("-o",                  {"hu": "Üzenetek naplózása fájlba", "en": "Log messages to file"},                            True,  "/tmp/wget.log"),
            ("-a",                  {"hu": "Üzenetek hozzáfűzése fájlhoz", "en": "Append messages to file"},                         True,  "/tmp/wget.log"),
            ("-d",                  {"hu": "Debug: rengeteg hibakeresési info", "en": "Debug: print lots of debugging info"},                    False, ""),
            ("-q",                  {"hu": "Csendes mód (nincs kimenet)", "en": "Quiet (no output)"},                          False, ""),
            ("-v",                  {"hu": "Részletes kimenet (alapértelmezett)", "en": "Verbose (default)"},                  False, ""),
            ("-nv",                 {"hu": "Részletesség kikapcsolása csendesség nélkül", "en": "Turn off verbose without quiet"},          False, ""),
            ("--report-speed",      {"hu": "Sávszélesség kiírás típusa (bits)", "en": "Report speed in bits/s"},                    True,  "bits"),
            ("--config",            {"hu": "Beállítófájl megadása", "en": "Specify config file"},                                True,  "/path/.wgetrc"),
            ("--no-config",         {"hu": "Ne olvasson semmilyen beállítófájlt", "en": "Do not read any config file"},                  False, ""),
            ("--rejected-log",      {"hu": "URL-visszautasítás okainak naplózása", "en": "Log reasons for URL rejection"},                 True,  "/tmp/rejected.log"),
        ]),
        ("wget.download", [
            ("-t",                  {"hu": "Újrapróbálkozások száma (0=végtelen)", "en": "Number of retries (0=infinite)"},                 True,  "3"),
            ("--retry-connrefused", {"hu": "Újrapróbálkozás visszautasított kapcsolatnál", "en": "Retry even if connection refused"},         False, ""),
            ("--retry-on-host-error",{"hu": "Hoszt hibák nem végzetesnek kezelése", "en": "Treat host errors as non-fatal"},                False, ""),
            ("--retry-on-http-error",{"hu": "Újrapróbálandó HTTP hibák (pl. 500,503)", "en": "Retry on HTTP errors (e.g. 500,503)"},             True,  "500,503"),
            ("-O",                  {"hu": "Dokumentum írása fájlba (- = stdout)", "en": "Write document to file (- = stdout)"},                 True,  "/tmp/wget_out.html"),
            ("-nc",                 {"hu": "Meglévő fájlok felülírásának kihagyása", "en": "Skip downloads that would overwrite existing files"},               False, ""),
            ("--no-netrc",          {"hu": "Ne használjon .netrc hitelesítési adatokat", "en": "Don't use .netrc auth data"},           False, ""),
            ("-c",                  {"hu": "Részben letöltött fájl folytatása", "en": "Resume getting a partially downloaded file"},                    False, ""),
            ("--start-pos",         {"hu": "Letöltés kezdése eltolástól (bájtokban)", "en": "Start download at offset (bytes)"},              True,  "0"),
            ("--progress",          {"hu": "Előrehaladás típusa (dot, bar)", "en": "Progress indicator type (dot, bar)"},                       True,  "bar"),
            ("--show-progress",     {"hu": "Folyamatsáv megjelenítése minden módban", "en": "Show progress bar in all modes"},              False, ""),
            ("-N",                  {"hu": "Timestamping: ne töltse le ha nem újabb", "en": "Timestamping: don't re-retrieve unless newer"},              False, ""),
            ("--no-if-modified-since",{"hu": "Ne használjon If-Modified-Since kéréseket", "en": "Don't use If-Modified-Since requests"},          False, ""),
            ("--no-use-server-timestamps",{"hu": "Ne állítsa a fájl időbélyegét a szerverihez", "en": "Don't set local file timestamps to server timestamps"},   False, ""),
            ("-S",                  {"hu": "Kiszolgáló válaszának kiírása", "en": "Print server response"},                        False, ""),
            ("--spider",            {"hu": "Ne töltsön le semmit (csak ellenőriz)", "en": "Don't download anything (check only)"},                False, ""),
            ("-T",                  {"hu": "Minden időkorlát értéke (mp)", "en": "All timeout values (sec)"},                         True,  "30"),
            ("--dns-timeout",       {"hu": "DNS keresés időkorlátja (mp)", "en": "DNS lookup timeout (sec)"},                         True,  "10"),
            ("--connect-timeout",   {"hu": "Kapcsolódási időkorlát (mp)", "en": "Connection timeout (sec)"},                          True,  "10"),
            ("--read-timeout",      {"hu": "Olvasási időkorlát (mp)", "en": "Read timeout (sec)"},                              True,  "30"),
            ("-w",                  {"hu": "Várakozás letöltések között (mp)", "en": "Wait between downloads (sec)"},                     True,  "1"),
            ("--waitretry",         {"hu": "Várakozás újrapróbálások között (mp)", "en": "Wait between retries (sec)"},                 True,  "5"),
            ("--random-wait",       {"hu": "Véletlenszerű várakozás 0.5*wait...1.5*wait", "en": "Random wait between 0.5*wait and 1.5*wait"},         False, ""),
            ("--no-proxy",          {"hu": "Proxy kikapcsolása", "en": "Disable proxy"},                                   False, ""),
            ("-Q",                  {"hu": "Letöltési kvóta (pl. 100M, 1G)", "en": "Download quota (e.g. 100M, 1G)"},                       True,  "100M"),
            ("--bind-address",      {"hu": "Hozzákötés helyi gépnévhez/IP-hez", "en": "Bind to local hostname/address"},                    True,  "0.0.0.0"),
            ("--limit-rate",        {"hu": "Letöltési sebesség korlátozása (pl. 500k)", "en": "Limit download rate (e.g. 500k)"},            True,  "500k"),
            ("--no-dns-cache",      {"hu": "DNS gyorsítótár letiltása", "en": "Disable DNS caching"},                            False, ""),
            ("--restrict-file-names",{"hu": "Fájlnév-karakterek korlátozása (unix/windows)", "en": "Restrict file name characters (unix/windows)"},      True,  "unix"),
            ("--ignore-case",       {"hu": "Kis/nagybetűk figyelmen kívül hagyása", "en": "Ignore case when matching files"},                False, ""),
            ("-4",                  {"hu": "Csak IPv4 kapcsolódás", "en": "IPv4 connections only"},                                False, ""),
            ("-6",                  {"hu": "Csak IPv6 kapcsolódás", "en": "IPv6 connections only"},                                False, ""),
            ("--prefer-family",     {"hu": "Elsőként kapcsolódni: IPv4, IPv6, none", "en": "Prefer family: IPv4, IPv6, none"},               True,  "IPv4"),
            ("--user",              {"hu": "FTP és HTTP felhasználónév", "en": "FTP and HTTP username"},                           True,  "user"),
            ("--password",          {"hu": "FTP és HTTP jelszó", "en": "FTP and HTTP password"},                                   True,  "pass"),
            ("--no-iri",            {"hu": "IRI támogatás kikapcsolása", "en": "Disable IRI support"},                           False, ""),
            ("--local-encoding",    {"hu": "IRI helyi kódolás (pl. UTF-8)", "en": "IRI local encoding (e.g. UTF-8)"},                        True,  "UTF-8"),
            ("--remote-encoding",   {"hu": "Alapértelmezett távoli kódolás", "en": "Default remote encoding"},                       True,  "UTF-8"),
            ("--unlink",            {"hu": "Fájl törlése felülírás előtt", "en": "Remove file before clobbering"},                         False, ""),
            ("--xattr",             {"hu": "Metaadatok kiterjesztett fájlattribútumokban", "en": "Store metadata in extended attributes"},          False, ""),
        ]),
        ("wget.directories", [
            ("-nd",                 {"hu": "Ne hozzon létre könyvtárakat", "en": "No directories"},                         False, ""),
            ("-x",                  {"hu": "Könyvtárak létrehozásának kényszerítése", "en": "Force creation of directories"},              False, ""),
            ("-nH",                 {"hu": "Ne hozzon létre kiszolgálókönyvtárakat", "en": "Don't create host directories"},               False, ""),
            ("--protocol-directories",{"hu": "Protokollnév a könyvtárakban", "en": "Protocol name in directories"},                       False, ""),
            ("-P",                  {"hu": "Fájlok mentése előtag-könyvtárba", "en": "Save files to prefix directory"},                     True,  "/tmp/wget_dl/"),
            ("--cut-dirs",          {"hu": "Könyvtárösszetevők kihagyása (db)", "en": "Skip directory components"},                    True,  "1"),
        ]),
        ("wget.http", [
            ("--http-user",         {"hu": "HTTP felhasználónév", "en": "HTTP username"},                                  True,  "user"),
            ("--http-password",     {"hu": "HTTP jelszó", "en": "HTTP password"},                                          True,  "pass"),
            ("--no-cache",          {"hu": "Gyorsítótárazott adatok tiltása", "en": "Disallow server-cached data"},                      False, ""),
            ("--default-page",      {"hu": "Alapértelmezett oldalnév (default: index.html)", "en": "Default page name (default: index.html)"},       True,  "index.html"),
            ("-E",                  {"hu": "HTML/CSS mentése megfelelő kiterjesztéssel", "en": "Save HTML/CSS with proper extensions"},            False, ""),
            ("--ignore-length",     {"hu": "Content-Length fejlécmező mellőzése", "en": "Ignore Content-Length header"},                  False, ""),
            ("--header",            {"hu": "HTTP fejléc hozzáadása (auto-kitöltve sidebar-ból)", "en": "HTTP header (auto-filled)"},   True,  "X-Custom: value"),
            ("--compression",       {"hu": "Tömörítés típusa (auto, gzip, none)", "en": "Compression type (auto, gzip, none)"},                  True,  "auto"),
            ("--max-redirect",      {"hu": "Átirányítások max. száma oldalanként", "en": "Maximum redirections per page"},                 True,  "10"),
            ("--proxy-user",        {"hu": "Proxy felhasználónév", "en": "Proxy username"},                                 True,  "user"),
            ("--proxy-password",    {"hu": "Proxy jelszó", "en": "Proxy password"},                                         True,  "pass"),
            ("--referer",           {"hu": "Referer URL a HTTP kérésbe", "en": "Referer URL in HTTP request"},                           True,  "https://example.com"),
            ("--save-headers",      {"hu": "HTTP fejlécek mentése fájlba", "en": "Save HTTP headers to file"},                         False, ""),
            ("-U",                  {"hu": "User-Agent string (auto-kitöltve sidebar-ból)", "en": "User-Agent string (auto-filled)"},        True,  "Mozilla/5.0"),
            ("--no-http-keep-alive",{"hu": "HTTP keep-alive letiltása", "en": "Disable HTTP keep-alive"},                            False, ""),
            ("--no-cookies",        {"hu": "Sütik mellőzése", "en": "Do not use cookies"},                                      False, ""),
            ("--load-cookies",      "Load cookies from file",                              True,  "/tmp/cookies.txt"),
            ("--save-cookies",      "Save cookies to file",                                 True,  "/tmp/cookies.txt"),
            ("--keep-session-cookies","Load and save session cookies",              False, ""),
            ("--post-data",         "Send POST data (application/x-www-form-urlencoded)",True,"key=value"),
            ("--post-file",         "Send POST data from file",                          True,  "/path/data.txt"),
            ("--method",            "HTTP method (GET, POST, PUT, DELETE…)",               True,  "GET"),
            ("--body-data",         "Request body data (--method required)",               True,  '{"key":"value"}'),
            ("--body-file",         "Request body from file (--method required)",              True,  "/path/body.json"),
            ("--content-disposition","Respect Content-Disposition header",         False, ""),
            ("--content-on-error",  "Write output on server errors",              False, ""),
            ("--auth-no-challenge",  "Send Basic auth without challenge",                 False, ""),
        ]),
        ("HTTPS / TLS", [
            ("--secure-protocol",   "TLS protocol (auto,TLSv1,TLSv1_2,TLSv1_3,PFS)",     True,  "auto"),
            ("--https-only",        {"hu": "Csak HTTPS hivatkozások követése", "en": "Only follow HTTPS links"},                     False, ""),
            ("--no-check-certificate","Skip certificate verification",                   False, ""),
            ("--certificate",       "Client certificate file (PEM/DER)",                   True,  "/path/client.pem"),
            ("--certificate-type",  "Certificate type (PEM or DER)",                    True,  "PEM"),
            ("--private-key",       "Private key file",                               True,  "/path/key.pem"),
            ("--private-key-type",  {"hu": "Személyes kulcs típusa (PEM vagy DER)", "en": "Private key type (PEM or DER)"},                True,  "PEM"),
            ("--ca-certificate",    {"hu": "CA tanúsítványok fájlja", "en": "CA certificate file"},                              True,  "/etc/ssl/certs/ca-bundle.crt"),
            ("--ca-directory",      {"hu": "CA tanúsítványok könyvtára", "en": "CA certificate directory"},                           True,  "/etc/ssl/certs/"),
            ("--crl-file",          {"hu": "Visszavont tanúsítványok (CRL) fájlja", "en": "Revoked certificates (CRL) file"},                True,  "/path/crl.pem"),
            ("--pinnedpubkey",      {"hu": "Rögzített nyilvános kulcs (PEM/sha256//hash)", "en": "Pinned public key (PEM/sha256//hash)"},         True,  "sha256//base64=="),
            ("--ciphers",           {"hu": "TLS titkosítólista (GnuTLS/OpenSSL formátum)", "en": "TLS cipher list (GnuTLS/OpenSSL)"},         True,  "ECDHE-RSA-AES256-GCM-SHA384"),
            ("--no-hsts",           {"hu": "HSTS letiltása", "en": "Disable HSTS"},                                       False, ""),
            ("--hsts-file",         {"hu": "HSTS adatbázis útvonala", "en": "HSTS database path"},                              True,  "/tmp/wget_hsts"),
        ]),
        ("wget.recursive", [
            ("-r",                  {"hu": "Rekurzív letöltés", "en": "Recursive download"},                                    False, ""),
            ("-l",                  {"hu": "Max rekurzió mélysége (0=végtelen)", "en": "Max recursion depth (0=infinite)"},                   True,  "2"),
            ("--delete-after",      {"hu": "Helyi fájlok törlése letöltés után", "en": "Delete local files after download"},                   False, ""),
            ("-k",                  {"hu": "Hivatkozások átalakítása helyi fájlokra", "en": "Convert links to local files"},              False, ""),
            ("--convert-file-only", {"hu": "Csak az URL fájlrészének átalakítása", "en": "Convert only file part of URLs"},                 False, ""),
            ("--backups",           {"hu": "Max N mentési fájl forgatása X fájlok előtt", "en": "Rotate up to N backup files"},          True,  "3"),
            ("-K",                  {"hu": "Backup az átalakítás előtt (X.orig)", "en": "Backup before convert (X.orig)"},                  False, ""),
            ("-m",                  {"hu": "Tükrözés (-N -r -l inf --no-remove-listing)", "en": "Mirror (-N -r -l inf --no-remove-listing)"},          False, ""),
            ("-p",                  {"hu": "Összes oldalelem letöltése (képek, CSS stb.)", "en": "Download all page requisites"},         False, ""),
            ("--strict-comments",   {"hu": "Szigorú HTML megjegyzés kezelés (SGML)", "en": "Strict HTML comment handling (SGML)"},               False, ""),
        ]),
        ("wget.accept", [
            ("-A",                  {"hu": "Elfogadott kiterjesztések (vesszőkkel elválasztva)", "en": "Accepted extensions (comma-separated)"},   True,  "html,htm,php,asp"),
            ("-R",                  {"hu": "Visszautasított kiterjesztések", "en": "Rejected extensions"},                       True,  "jpg,png,gif,css"),
            ("--accept-regex",      {"hu": "Regex illesztéssel elfogadott URL-ek", "en": "Accepted URLs (regex)"},                 True,  r"\\.php(\\?.*)?$"),
            ("--reject-regex",      {"hu": "Regex illesztéssel visszautasított URL-ek", "en": "Rejected URLs (regex)"},            True,  r"\\.(jpg|png|gif)$"),
            ("--regex-type",        {"hu": "Regex típusa (posix, pcre)", "en": "Regex type (posix, pcre)"},                           True,  "pcre"),
            ("-D",                  {"hu": "Elfogadott tartományok listája", "en": "Accepted domains"},                       True,  "example.com,sub.example.com"),
            ("--exclude-domains",   {"hu": "Visszautasított tartományok listája", "en": "Rejected domains"},                  True,  "ads.example.com"),
            ("--follow-ftp",        {"hu": "FTP hivatkozások követése HTML-ből", "en": "Follow FTP links from HTML"},                   False, ""),
            ("--follow-tags",       {"hu": "Követett HTML címkék listája", "en": "Followed HTML tags"},                         True,  "a,img,link"),
            ("--ignore-tags",       {"hu": "Figyelmen kívül hagyott HTML címkék", "en": "Ignored HTML tags"},                  True,  "script,style"),
            ("-H",                  {"hu": "Rekurzív módban idegen gépekre is menjen", "en": "Span hosts in recursive mode"},             False, ""),
            ("-L",                  {"hu": "Csak relatív hivatkozások követése", "en": "Follow only relative links"},                   False, ""),
            ("-I",                  {"hu": "Engedélyezett könyvtárak listája", "en": "List of allowed directories"},                     True,  "/allowed/path/"),
            ("--trust-server-names",{"hu": "Átirányítási URL utolsó összetevője alapján nevezzen", "en": "Use last component of redirect URL as filename"}, False, ""),
            ("-X",                  {"hu": "Kihagyott könyvtárak listája", "en": "List of excluded directories"},                         True,  "/admin/,/private/"),
            ("-np",                 {"hu": "Ne lépjen be a szülőkönyvtárba", "en": "Don't ascend to parent directory"},                       False, ""),
        ]),
        ("wget.ftp", [
            ("--ftp-user",          {"hu": "FTP felhasználónév", "en": "FTP username"},                                   True,  "anonymous"),
            ("--ftp-password",      {"hu": "FTP jelszó", "en": "FTP password"},                                           True,  "guest@"),
            ("--no-remove-listing", {"hu": "Ne távolítsa el a .listing fájlokat", "en": "Don't remove .listing files"},                  False, ""),
            ("--no-glob",           {"hu": "Helyettesítő karakterek kikapcsolása FTP-ben", "en": "Disable globbing in FTP"},         False, ""),
            ("--no-passive-ftp",    {"hu": "Passzív FTP letiltása", "en": "Disable passive FTP"},                                False, ""),
            ("--preserve-permissions",{"hu": "Távoli fájljogosultságok megőrzése", "en": "Preserve remote file permissions"},                 False, ""),
            ("--retr-symlinks",     {"hu": "Szimbolikus linkek célját töltse le", "en": "Retrieve symlink targets"},                  False, ""),
        ]),
        ("wget.ftps", [
            ("--ftps-implicit",             {"hu": "Implicit FTPS (port 990)", "en": "Use implicit FTPS (port 990)"},                     False, ""),
            ("--ftps-resume-ssl",           {"hu": "SSL munkamenet folytatása adatkapcsolatnál", "en": "Resume SSL session on data connection"},   False, ""),
            ("--ftps-clear-data-connection",{"hu": "Csak vezérlőkapcsolat titkosítva", "en": "Only control connection encrypted"},             False, ""),
            ("--ftps-fallback-to-ftp",      {"hu": "Visszaváltás FTP-re ha FTPS nem támogatott", "en": "Fallback to FTP if FTPS not supported"},  False, ""),
        ]),
        ("wget.warc", [
            ("--warc-file",         {"hu": "WARC fájlba mentés (.warc.gz)", "en": "Save to WARC file (.warc.gz)"},                        True,  "/tmp/wget_archive"),
            ("--warc-header",       {"hu": "KARAKTERLÁNC a warcinfo rekordba", "en": "String in warcinfo record"},                     True,  "operator: user@example.com"),
            ("--warc-max-size",     {"hu": "WARC fájlok legnagyobb mérete (pl. 100M)", "en": "Max WARC file size (e.g. 100M)"},             True,  "100M"),
            ("--warc-cdx",          {"hu": "CDX indexfájlok kiírása", "en": "Write CDX index files"},                              False, ""),
            ("--warc-dedup",        {"hu": "Ne tárolja a CDX fájlban felsorolt rekordokat", "en": "Don't store CDX-listed records"},        True,  "/path/existing.cdx"),
            ("--no-warc-compression",{"hu": "WARC fájlok GZIP tömörítés nélkül", "en": "Don't compress WARC files with GZIP"},                  False, ""),
            ("--no-warc-digests",   {"hu": "Ne számítson SHA1 ellenőrzőösszegeket", "en": "Don't calculate SHA1 digests"},                False, ""),
            ("--no-warc-keep-log",  {"hu": "Ne tárolja a naplófájlt WARC rekordban", "en": "Don't store log in WARC record"},               False, ""),
            ("--warc-tempdir",      {"hu": "WARC ideiglenes fájlok könyvtára", "en": "WARC temporary files directory"},                     True,  "/tmp/warc_temp/"),
        ]),
    ]

    def _build_flags(self):
        self._ins_tgt(self._tgt_frame(["https://","http://"]))
        for sec_key, flags in self.SECTIONS:
            self._ol.addWidget(self._sec(T(sec_key) if sec_key.startswith("wget.") else sec_key))
            for flag, h, hv, ph in flags:
                h_text = h.get(_LANG.lang, h.get("en", h)) if isinstance(h, dict) else h
                browse = flag in ["-O","-o","-a","--warc-file","--warc-dedup",
                                   "--load-cookies","--save-cookies","--post-file",
                                   "--body-file","--certificate","--private-key",
                                   "--ca-certificate","--crl-file","--rejected-log",
                                   "--config","--hsts-file","--trace-file"]
                cb, le = self._add_flag(self._ol, flag, h_text, hv, ph, False, "", browse)
                if flag == "-U" and self._ua and le:
                    le.setText(self._ua); cb.setChecked(True); le.setEnabled(True)
                if flag == "--header" and self._hdr and le:
                    le.setText(self._hdr); cb.setChecked(True); le.setEnabled(True)
        self._ol.addStretch()

    def _build_cmd(self):
        p = ["wget"]
        for cb, le, f in self._flag_widgets:
            if cb.isChecked():
                p.append(f)
                if le and le.text().strip():
                    p.append(le.text().strip())
        p.append(self._get_tgt())
        return " ".join(p)

class NaabuDialog(BaseToolDialog):
    TOOL_NAME="naabu"; ICON="🔌"; SUBTITLE="Fast Port Scanner — ProjectDiscovery"

    def __init__(self,host,dns,rate=1000,parent=None):
        self._r=rate
        super().__init__(host,dns,parent)

    SECTIONS = [
        ("PORT", [
            ("-port",           "Ports to scan (e.g. 80,443 or 100-200)",                  True,  "80,443,8080",   False),
            ("-top-ports",      "Top ports preset: full, 100, 1000",                        True,  "100",           False),
            ("-exclude-ports",  "Ports to exclude (comma-separated or file)",               True,  "22,3306",       False),
            ("-ports-file",     "List of ports to scan (file)",                             True,  "/path/ports.txt",False),
            ("-port-threshold", "Port threshold to skip scan for host",                     True,  "10",            False),
            ("-exclude-cdn",    "Skip full port scan for CDN/WAF (only 80,443)",             False, "",              False),
            ("-display-cdn",    "Display CDN in use",                                        False, "",              False),
        ]),
        ("RATE-LIMIT", [
            ("-c",              "General internal worker threads (default 25)",              True,  "25",            False),
            ("-rate",           "Packets per second (auto from rate limit setting)",         True,  "1000",          True),
        ]),
        ("CONFIGURATION", [
            ("-config",         "Path to naabu configuration file",                         True,  "$HOME/.config/naabu/config.yaml", False),
            ("-scan-all-ips",   "Scan all IPs associated with DNS record",                   False, "",              False),
            ("-ip-version",     "IP version to scan (4,6)",                                  True,  "4,6",           False),
            ("-scan-type",      "Port scan type: SYN or CONNECT",                            True,  "c",             False),
            ("-source-ip",      "Source IP and port (x.x.x.x:yyy)",                          True,  "0.0.0.0:0",     False),
            ("-connect-payload","Payload to send in CONNECT scans",                          True,  "CONNECT",       False),
            ("-interface-list", "List available interfaces and public IP",                   False, "",              False),
            ("-interface",      "Network interface to use for port scan",                    True,  "eth0",          False),
            ("-nmap-cli",       "Run nmap command on found results",                         True,  "nmap -sV",      False),
            ("-r",              "Custom DNS resolvers (comma-separated or file)",            True,  "8.8.8.8,1.1.1.1",False),
            ("-proxy",          "SOCKS5 proxy (ip[:port] / fqdn[:port])",                    True,  "socks5://127.0.0.1:1080",False),
            ("-proxy-auth",     "SOCKS5 proxy authentication (username:password)",           True,  "user:pass",     False),
            ("-dns-order",      "DNS resolution order (p/l/lp/pl, default l)",               True,  "l",             False),
            ("-system-resolver","Use system DNS as fallback resolver",                       False, "",              False),
            ("-resume",         "Resume scan using resume.cfg",                              False, "",              False),
            ("-stream",         "Stream mode (disables resume/nmap/verify/retries)",         False, "",              False),
            ("-passive",        "Display passive open ports via Shodan internetdb API",      False, "",              False),
            ("-input-read-timeout","Timeout on input read (default 3m0s)",                   True,  "3m0s",          False),
            ("-no-stdin",       "Disable Stdin processing",                                  False, "",              False),
        ]),
        ("HOST DISCOVERY", [
            ("-host-discovery", "Perform only host discovery (no port scan)",                False, "",              False),
            ("-skip-host-discovery","Skip host discovery (treat all hosts as up)",          False, "",              False),
            ("-with-host-discovery","Enable host discovery alongside port scan",             False, "",              False),
            ("-probe-tcp-syn",  "TCP SYN Ping ports (comma-separated)",                      True,  "80,443",        False),
            ("-probe-tcp-ack",  "TCP ACK Ping ports (comma-separated)",                      True,  "80,443",        False),
            ("-probe-icmp-echo","ICMP echo request Ping",                                    False, "",              False),
            ("-probe-icmp-timestamp","ICMP timestamp request Ping",                          False, "",              False),
            ("-probe-icmp-address-mask","ICMP address mask request Ping",                    False, "",              False),
            ("-arp-ping",       "ARP ping (requires host discovery enabled)",                False, "",              False),
            ("-nd-ping",        "IPv6 Neighbor Discovery ping",                              False, "",              False),
            ("-rev-ptr",        "Reverse PTR lookup for input IPs",                         False, "",              False),
        ]),
        ("SERVICES DISCOVERY", [
            ("-service-discovery","Service Discovery",                                       False, "",              False),
            ("-service-version","Service Version detection",                                 False, "",              False),
            ("-sV-fast",        "Only probe port-hinted services (faster)",                  False, "",              False),
            ("-sV-timeout",     "Timeout for service version probes (default 5s)",           True,  "5s",            False),
            ("-sV-workers",     "Concurrent service version workers (default 25)",           True,  "25",            False),
            ("-sV-probes",      "Custom nmap-service-probes file path",                      True,  "/path/probes",  False),
            ("-udp-probes",     "Send UDP payloads using nmap-service-probes",               False, "",              False),
        ]),
        ("OPTIMIZATION", [
            ("-retries",        "Number of retries for port scan (default 3)",               True,  "3",             False),
            ("-timeout",        "Milliseconds to wait before timeout (default 1s)",          True,  "1000",          False),
            ("-warm-up-time",   "Seconds between scan phases (default 2)",                   True,  "2",             False),
            ("-ping",           "Ping probes for host verification",                         False, "",              False),
            ("-verify",         "Validate ports again with TCP verification",                False, "",              False),
            ("-smart-scan",     "Predictive port scanning (port correlation model)",         False, "",              False),
            ("-prediction-threshold","Min confidence for port predictions 0-100% (default 20)",True,"20",           False),
        ]),
        ("OUTPUT", [
            ("-o",              "Output file",                                               True,  "/tmp/naabu_out.txt", False),
            ("-list-output-fields","List fields to output (comma-separated)",               True,  "host,port,protocol",False),
            ("-exclude-output-fields","Exclude output fields based on condition",            True,  "port==80",      False),
            ("-json",           "Write output in JSON lines format",                         False, "",              False),
            ("-csv",            "Write output in CSV format",                                False, "",              False),
        ]),
        ("CLOUD", [
            ("-pd",             "Upload/view output in ProjectDiscovery Cloud dashboard",    False, "",              False),
            ("-tid",            "Upload results to given team ID",                           True,  "team_id",       False),
            ("-aid",            "Upload assets to existing asset ID",                        True,  "asset_id",      False),
            ("-aname",          "Assets group name",                                         True,  "my_assets",     False),
        ]),
        ("DEBUG", [
            ("-health-check",   "Run diagnostic health check",                               False, "",              False),
            ("-debug",          "Display debugging information",                             False, "",              False),
            ("-verbose",        "Display verbose output",                                    False, "",              False),
            ("-no-color",       "Disable colors in CLI output",                              False, "",              False),
            ("-silent",         "Display only results in output",                            False, "",              False),
            ("-version",        "Display version of naabu",                                  False, "",              False),
            ("-metrics-port",   "Port to expose naabu metrics on (default 63636)",           True,  "63636",         False),
        ]),
    ]

    def _build_flags(self):
        self._ins_tgt(self._tgt_frame())
        for sec_name, flags in self.SECTIONS:
            self._ol.addWidget(self._sec(sec_name))
            for flag, h, hv, ph, defon in flags:
                browse = flag in ["-o", "-ports-file", "-sV-probes", "-r"]
                cb, le = self._add_flag(self._ol, flag, h, hv, ph, defon, "", browse)
                if flag == "-rate" and le:
                    le.setText(str(self._r) if self._r > 0 else "1000")
                    cb.setChecked(True); le.setEnabled(True)
        self._ol.addStretch()

    def _build_cmd(self):
        p = ["naabu", "-host", self._get_tgt()]
        for cb, le, f in self._flag_widgets:
            if cb.isChecked():
                p.append(f)
                if le and le.text().strip(): p.append(le.text().strip())
        return " ".join(p)

class NmapDialog(BaseToolDialog):
    TOOL_NAME="nmap"; ICON="🗺"; SUBTITLE="Network Mapper — Slow PortScanner"

    def __init__(self,host,dns,rate=5,ua="",sudo_pw="",parent=None):
        self._r=rate; self._ua=ua; self._sudo_pw=sudo_pw
        super().__init__(host,dns,parent)

    SECTIONS = [
        ("HOST DISCOVERY", [
            ("-sL",              "List Scan — list targets only, no scan",              False, "",           False),
            ("-sn",              "Ping Scan — disable port scan",                        False, "",           False),
            ("-Pn",              "Treat all hosts online — skip host discovery",         False, "",           False),
            ("-PS",              "TCP SYN discovery to given ports",                     True,  "80,443",     False),
            ("-PA",              "TCP ACK discovery to given ports",                     True,  "80,443",     False),
            ("-PU",              "UDP discovery to given ports",                         True,  "53,161",     False),
            ("-PY",              "SCTP discovery to given ports",                        True,  "80,443",     False),
            ("-PE",              "ICMP echo request discovery probe",                    False, "",           False),
            ("-PP",              "ICMP timestamp request discovery probe",               False, "",           False),
            ("-PM",              "ICMP netmask request discovery probe",                 False, "",           False),
            ("-PO",              "IP Protocol Ping (protocol list)",                     True,  "1,2,4",      False),
            ("-n",               "Never do DNS resolution",                              False, "",           False),
            ("-R",               "Always resolve DNS",                                   False, "",           False),
            ("--dns-servers",    "Specify custom DNS servers",                           True,  "8.8.8.8,1.1.1.1", False),
            ("--system-dns",     "Use OS DNS resolver",                                  False, "",           False),
            ("--traceroute",     "Trace hop path to each host",                          False, "",           False),
        ]),
        ("SCAN TECHNIQUES", [
            ("-sS",              "TCP SYN scan (requires root/sudo)",                    False, "",           False),
            ("-sT",              "TCP Connect scan",                                     False, "",           False),
            ("-sA",              "TCP ACK scan",                                         False, "",           False),
            ("-sW",              "TCP Window scan",                                      False, "",           False),
            ("-sM",              "TCP Maimon scan",                                      False, "",           False),
            ("-sU",              "UDP Scan",                                              False, "",           False),
            ("-sN",              "TCP Null scan",                                        False, "",           False),
            ("-sF",              "TCP FIN scan",                                         False, "",           False),
            ("-sX",              "Xmas scan",                                            False, "",           False),
            ("--scanflags",      "Customize TCP scan flags (e.g. URGACKPSH)",            True,  "URGACKPSH",  False),
            ("-sI",              "Idle scan (zombie host[:probeport])",                  True,  "zombie.host",False),
            ("-sY",              "SCTP INIT scan",                                       False, "",           False),
            ("-sZ",              "SCTP COOKIE-ECHO scan",                                False, "",           False),
            ("-sO",              "IP protocol scan",                                     False, "",           False),
            ("-b",               "FTP bounce scan (FTP relay host)",                     True,  "ftp.host",   False),
        ]),
        ("PORTS", [
            ("-p",               "Port ranges (e.g. 22; 1-65535; U:53,T:21-25,80)",     True,  "22,80,443",  False),
            ("--exclude-ports",  "Exclude port ranges from scanning",                    True,  "9090,3306",  False),
            ("-F",               "Fast mode — scan fewer ports than default",            False, "",           False),
            ("-r",               "Scan ports sequentially (no randomize)",               False, "",           False),
            ("--top-ports",      "Scan N most common ports",                             True,  "100",        False),
            ("--port-ratio",     "Scan ports more common than given ratio",              True,  "0.1",        False),
        ]),
        ("SERVICE / VERSION", [
            ("-sV",              "Probe open ports for service/version info",            False, "",           False),
            ("--version-intensity","Version scan intensity 0 (light) to 9 (all)",       True,  "5",          False),
            ("--version-light",  "Limit to most likely probes (intensity 2)",            False, "",           False),
            ("--version-all",    "Try every single probe (intensity 9)",                 False, "",           False),
            ("--version-trace",  "Show detailed version scan activity",                  False, "",           False),
        ]),
        ("SCRIPTS (NSE)", [
            ("-sC",              "Run default NSE scripts (--script=default)",           False, "",           False),
            ("--script",         "Lua scripts/categories (comma-separated)",             True,  "default",    False),
            ("--script-args",    "Script arguments (n1=v1,n2=v2,…)",                    True,  "",           False),
            ("--script-args-file","NSE script args from file",                          True,  "/path/args.txt",False),
            ("--script-trace",   "Show all data sent/received by scripts",              False, "",           False),
            ("--script-updatedb","Update the NSE script database",                      False, "",           False),
        ]),
        ("OS DETECTION", [
            ("-O",               "Enable OS detection",                                  False, "",           False),
            ("--osscan-limit",   "Limit OS detection to promising targets",              False, "",           False),
            ("--osscan-guess",   "Guess OS more aggressively",                           False, "",           False),
        ]),
        ("TIMING AND PERFORMANCE", [
            ("-T0",              "Paranoid timing — IDS evasion, very slow",             False, "",           False),
            ("-T1",              "Sneaky timing",                                        False, "",           False),
            ("-T2",              "Polite timing — slower, less bandwidth",               False, "",           False),
            ("-T3",              "Normal timing (default)",                              False, "",           True),
            ("-T4",              "Aggressive timing — faster, good for LAN",            False, "",           False),
            ("-T5",              "Insane timing — very fast, may miss ports",           False, "",           False),
            ("--min-hostgroup",  "Minimum parallel host scan group size",               True,  "1",          False),
            ("--max-hostgroup",  "Maximum parallel host scan group size",               True,  "16",         False),
            ("--min-parallelism","Minimum probe parallelization",                       True,  "1",          False),
            ("--max-parallelism","Maximum probe parallelization",                       True,  "256",        False),
            ("--min-rtt-timeout","Minimum probe round trip time",                       True,  "100ms",      False),
            ("--max-rtt-timeout","Maximum probe round trip time",                       True,  "10s",        False),
            ("--initial-rtt-timeout","Initial probe round trip time",                   True,  "1s",         False),
            ("--max-retries",    "Max port scan probe retransmissions",                 True,  "3",          False),
            ("--host-timeout",   "Give up on target after this long",                   True,  "30m",        False),
            ("--scan-delay",     "Delay between probes (auto from rate limit)",          True,  "200ms",      False),
            ("--max-scan-delay", "Maximum delay between probes",                        True,  "1s",         False),
            ("--min-rate",       "Send packets no slower than N per second",            True,  "100",        False),
            ("--max-rate",       "Send packets no faster than N per second",            True,  "1000",       False),
        ]),
        ("FIREWALL/IDS EVASION AND SPOOFING", [
            ("-f",               "Fragment packets",                                     False, "",           False),
            ("--mtu",            "Fragment packets with given MTU",                     True,  "24",         False),
            ("-D",               "Cloak scan with decoys (decoy1,decoy2,ME,…)",         True,  "RND:5,ME",   False),
            ("-S",               "Spoof source IP address",                             True,  "1.2.3.4",    False),
            ("-e",               "Use specified network interface",                     True,  "eth0",       False),
            ("-g",               "Use given source port number",                        True,  "53",         False),
            ("--proxies",        "Relay via HTTP/SOCKS4 proxies",                       True,  "http://127.0.0.1:8080",False),
            ("--data",           "Append custom hex payload to packets",                True,  "deadbeef",   False),
            ("--data-string",    "Append custom ASCII string to packets",               True,  "hello",      False),
            ("--data-length",    "Append N bytes of random data to packets",            True,  "32",         False),
            ("--ip-options",     "Send packets with specified IP options",              True,  "R",          False),
            ("--ttl",            "Set IP time-to-live field",                           True,  "64",         False),
            ("--spoof-mac",      "Spoof MAC address (address/prefix/vendor)",           True,  "0",          False),
            ("--badsum",         "Send packets with bogus TCP/UDP/SCTP checksum",       False, "",           False),
        ]),
        ("OUTPUT", [
            ("-oN",              "Normal output to file",                               True,  "/tmp/nmap.txt",   False),
            ("-oX",              "XML output to file",                                  True,  "/tmp/nmap.xml",   False),
            ("-oS",              "Script kiddie output to file",                        True,  "/tmp/nmap.skiddie",False),
            ("-oG",              "Grepable output to file",                             True,  "/tmp/nmap.gnmap", False),
            ("-oA",              "Output in all three major formats (basename)",        True,  "/tmp/nmap_all",   False),
            ("-v",               "Increase verbosity (-vv for more)",                   False, "",           False),
            ("-d",               "Increase debugging level (-dd for more)",             False, "",           False),
            ("--reason",         "Display the reason a port is in its state",           False, "",           False),
            ("--open",           "Show open (or possibly open) ports only",             False, "",           False),
            ("--packet-trace",   "Show all packets sent and received",                  False, "",           False),
            ("--iflist",         "Print host interfaces and routes",                    False, "",           False),
            ("--append-output",  "Append to output files instead of clobber",           False, "",           False),
            ("--resume",         "Resume an aborted scan from file",                    True,  "/tmp/nmap.txt",   False),
            ("--noninteractive", "Disable runtime keyboard interactions",               False, "",           False),
            ("--stylesheet",     "XSL stylesheet to transform XML output",              True,  "https://nmap.org/svn/docs/nmap.xsl",False),
            ("--webxml",         "Reference stylesheet from Nmap.Org (portable XML)",   False, "",           False),
            ("--no-stylesheet",  "Prevent XSL stylesheet association",                  False, "",           False),
        ]),
        ("MISC", [
            ("-6",               "Enable IPv6 scanning",                                False, "",           False),
            ("-A",               "OS+version detection, scripts and traceroute",        False, "",           False),
            ("--datadir",        "Specify custom Nmap data file location",              True,  "/path/nmapdata/",False),
            ("--send-eth",       "Send using raw ethernet frames",                      False, "",           False),
            ("--send-ip",        "Send using raw IP packets",                           False, "",           False),
            ("--privileged",     "Assume user is fully privileged (root)",              False, "",           False),
            ("--unprivileged",   "Assume user lacks raw socket privileges",             False, "",           False),
            ("-V",               "Print version number",                                False, "",           False),
        ]),
    ]

    def _build_flags(self):
        self._ins_tgt(self._tgt_frame())
        for sec_name, flags in self.SECTIONS:
            self._ol.addWidget(self._sec(sec_name))
            for flag, h, hv, ph, defon in flags:
                browse = flag in ["-oN","-oX","-oS","-oG","-oA","--resume","--script-args-file","--stylesheet"]
                cb, le = self._add_flag(self._ol, flag, h, hv, ph, defon, "", browse)
                if flag == "--scan-delay" and self._r > 0 and le:
                    le.setText(f"{max(1,int(1000/self._r))}ms")
                    cb.setChecked(True); le.setEnabled(True)
                if flag == "--script-args" and self._ua and le:
                    le.setText(f'http.useragent="{self._ua}"')
                    cb.setChecked(True); le.setEnabled(True)
        self._ol.addStretch()

    def _build_cmd(self):
        p = ["nmap"]
        for cb, le, f in self._flag_widgets:
            if cb.isChecked():
                p.append(f)
                if le and le.text().strip(): p.append(le.text().strip())
        p.append(self._get_tgt())
        return " ".join(p)

    def _run(self):
        """Override to prepend sudo if root-requiring flags selected."""
        if self._rbtn.text().startswith("⏹"):
            if hasattr(self,"_worker") and self._worker: self._worker.stop()
            self._rbtn.setText(T("btn.start")); self._rbtn.setStyleSheet(BRUN); return
        cmd = self._cedit.text().strip() or self._build_cmd()
        root_flags = {"-sS","-sU","-sN","-sF","-sX","-sO","-sY","-sZ","-sW","-sM","-sA",
                      "-O","--osscan-guess","--osscan-limit","-PE","-PP","-PM","-PS","-PA"}
        needs_root = any(f" {fl}" in f" {cmd}" or cmd.startswith(fl) for fl in root_flags)
        if needs_root and self._sudo_pw:
            import shlex as _sl
            cmd = f"echo {_sl.quote(self._sudo_pw)} | sudo -S {cmd}"
        elif needs_root:
            self._out.insertHtml(f"<span style='color:{D['orange']}'>⚠ {T('scan.sudo_warn')}</span><br>")
        self._out.clear()
        self._out.insertHtml(f"<span style='color:{D['muted']}'>$ {_html.escape(cmd)}</span><br><br>")
        self._rbtn.setText(T("btn.stop")); self._rbtn.setStyleSheet(BSTOP)
        try: parts = shlex.split(cmd)
        except: parts = cmd.split()
        self._worker = CmdWorker(parts)
        self._worker.output.connect(self._on_out)
        self._worker.finished.connect(self._on_done)
        self._worker.start()

class NucleiDialog(BaseToolDialog):
    TOOL_NAME="nuclei"; ICON="☢"; SUBTITLE="Fast Vulnerability Scanner — ProjectDiscovery"
    def __init__(self,host,dns,rate=150,ua="",hdr="",parent=None):
        self._r=rate; self._ua=ua; self._hdr=hdr; self._is_ip=self._check_if_ip(host); super().__init__(host,dns,parent)
    
    @staticmethod
    def _check_if_ip(target):
        """Ellenőriz, hogy a target IP cím-e"""
        try:
            ipaddress.ip_address(target.split(':')[0].strip('[]'))
            return True
        except:
            return False
    
    def _build_flags(self):
        # TARGET section - dinamikus a -u vagy -iv alapján
        target_flags=[
            ("-sa","Scan all IPs",False,"",False),
            ("-iv","IP version (4,6)",True,"4",self._is_ip),  # Enable by default for IP
        ]
        if not self._is_ip:
            target_flags.insert(0,("-u","Target URL/host",True,"https://example.com",False))
        
        sections=[
            ("TARGET",target_flags),
            ("TEMPLATES",[("-nt","New templates only",False,"",False),("-as","Auto-scan (wappalyzer)",False,"",False),("-t","Template/directory",True,"http/cves/,ssl",False),("-tags","Run by tags",True,"cve,rce",False),("-etags","Exclude tags",True,"dos,fuzz",False),("-id","Template IDs",True,"cve-2023-1234",False),("-eid","Exclude IDs",True,"cve-2022-1111",False)]),
            ("FILTERING",[("-a","Author",True,"projectdiscovery",False),("-s","Severity",True,"medium,high,critical",False),("-es","Exclude severity",True,"info,low",False),("-pt","Protocol type",True,"http,ssl,dns",False),("-ept","Exclude protocol",True,"tcp,udp",False)]),
            ("RATE-LIMIT",[("-rl","Rate limit/sec",True,"150",True),("-c","Parallel templates",True,"25",False),("-bs","Hosts per template",True,"25",False),("-hbs","Headless bulk size",True,"10",False)]),
            ("CONFIG",[("-H","Custom header (auto)",True,"X-Custom: val",False),("-fr","Follow redirects",False,"",False),("-fhr","Follow same host",False,"",False),("-mr","Max redirects",True,"10",False),("-dr","Disable redirects",False,"",False),("-passive","Passive HTTP mode",False,"",False),("-proxy","Proxy",True,"http://127.0.0.1:8080",False),("-retries","Retries",True,"1",False),("-timeout","Timeout s",True,"10",False),("-stream","Stream mode",False,"",False),("-dc","Disable clustering",False,"",False)]),
            ("TEMPLATES-CONTROL",[("-validate","Validate templates",False,"",False),("-td","Display template",False,"",False),("-tl","List all templates",False,"",False),("-code","Enable code protocol",False,"",False),("-file","Enable file templates",False,"",False)]),
            ("OUTPUT",[("-o","Output file",True,"/tmp/nuclei.txt",False),("-j","JSONL output",False,"",False),("-silent","Findings only",False,"",False),("-nc","No color",False,"",False),("-v","Verbose",False,"",False),("-stats","Statistics",False,"",False),("-je","JSON export",True,"/tmp/nuclei.json",False),("-me","Markdown export",True,"/tmp/nuclei.md",False),("-se","SARIF export",True,"/tmp/nuclei.sarif",False)]),
            ("HEADLESS",[("-headless","Enable headless",False,"",False),("-page-timeout","Page timeout s",True,"20",False),("-sb","Show browser",False,"",False)]),
            ("FUZZING",[("-dast","DAST templates",False,"",False),("-ft","Fuzzing type",True,"replace",False),("-fa","Aggression level",True,"low",False)]),
            ("INTERACTSH",[("-ni","No Interactsh",False,"",False),("-iserver","Interactsh server",True,"oast.live",False)]),
            ("DEBUG",[("-debug","All req/resp",False,"",False),("-dreq","Debug requests",False,"",False),("-dresp","Debug responses",False,"",False),("-hc","Health check",False,"",False),("-ut","Update templates",False,"",False)]),
        ]
        
        for sname,flags in sections:
            self._ol.addWidget(self._sec(sname))
            for flag,h,hv,ph,defon in flags:
                cb,le=self._add_flag(self._ol,flag,h,hv,ph,defon,"",flag in ["-o","-je","-me","-se"])
                if flag=="-rl" and le:
                    if self._r > 0:
                        le.setText(str(self._r)); cb.setChecked(True); le.setEnabled(True)
                    else:
                        cb.setChecked(False); le.setEnabled(False)  # Disable -rl if rate limit is 0
                if flag=="-H" and (self._hdr or self._ua) and le:
                    parts=[]
                    if self._hdr: parts.append(f'"{self._hdr}"')
                    if self._ua:  parts.append(f'"User-Agent: {self._ua}"')
                    le.setText(" -H ".join(parts)); cb.setChecked(True); le.setEnabled(True)
                if flag=="-sa": cb.setChecked(False)  # Keep -sa disabled by default
                if flag=="-iv" and self._is_ip and le:
                    cb.setChecked(True); le.setEnabled(True)  # Enable -iv by default for IP
        self._ol.addStretch()
    
    def _build_cmd(self):
        """Build nuclei command with dynamic target handling"""
        p=["nuclei"]
        
        # Handle target based on IP or URL
        if self._is_ip:
            # IP address case - use -iv flag
            # First, collect all flags to find the -iv value
            iv_val="4"  # Default
            for cb,le,f in self._flag_widgets:
                if f=="-iv" and le and le.text().strip():
                    iv_val=le.text().strip()
                    break
            p.extend(["-iv",iv_val,self._get_tgt()])
        else:
            # URL case - use -u flag
            p.extend(["-u",self._get_tgt()])
        
        # Add all other flags
        for cb,le,f in self._flag_widgets:
            if cb.isChecked() and f not in ["-iv","-u"]:  # Skip target flags, already handled
                p.append(f)
                if le and le.text().strip():
                    p.append(le.text().strip())
        
        return " ".join(p)

# ─── Sudo dialog ──────────────────────────────────────────────────────────────

# ─── Scope Confirm Dialog ─────────────────────────────────────────────────────
class ScopeConfirmDialog(QDialog):
    """Scope fájl megnyitása után felugró megerősítő ablak Rate/UA/Header beállítással."""
    def __init__(self, scope, wildcard_count, url_count, preview,
                 default_rate=5, default_ua="", default_hdr="", parent=None):
        super().__init__(parent)
        self.setWindowTitle("Scope lista")
        self.setMinimumWidth(540)
        self.setStyleSheet(SS)
        self.setWindowFlags(self.windowFlags() | Qt.WindowType.Window)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 16, 20, 16)
        lay.setSpacing(10)

        # ── Summary szöveg ───────────────────────────────────────────────────
        lbl_n = QLabel(
            f"<b>{'Talált' if _LANG.lang=='hu' else 'Found'} {len(scope)} "
            f"{'domain' if _LANG.lang=='hu' else 'domains'}:</b>"
        )
        lbl_n.setTextFormat(Qt.TextFormat.RichText)
        lbl_n.setStyleSheet(f"color:{D['text']};font-size:13px;")
        lay.addWidget(lbl_n)

        # Preview lista
        preview_lbl = QLabel("\n".join(preview))
        preview_lbl.setStyleSheet(
            f"color:{D['text2']};font-size:12px;font-family:monospace;"
            f"background:{D['surf2']};border:1px solid {D['border']};"
            f"border-radius:4px;padding:8px;"
        )
        preview_lbl.setWordWrap(True)
        lay.addWidget(preview_lbl)

        # Wildcard / URL info
        info_hu = (f"  • {wildcard_count} Wildcard  (subfinder is fut)\n"
                   f"  • {url_count} URL  (subfinder kihagyva)")
        info_en = (f"  • {wildcard_count} Wildcard  (subfinder also runs)\n"
                   f"  • {url_count} URL  (subfinder skipped)")
        info_lbl = QLabel(info_hu if _LANG.lang=="hu" else info_en)
        info_lbl.setStyleSheet(f"color:{D['muted']};font-size:11px;")
        lay.addWidget(info_lbl)

        # ── Separator ────────────────────────────────────────────────────────
        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color:{D['border']};")
        lay.addWidget(sep)

        # ── Rate / UA / Header beállítások ───────────────────────────────────
        grid = QVBoxLayout()
        grid.setSpacing(6)

        def _row(label_text, widget):
            h = QHBoxLayout(); h.setSpacing(8)
            lbl = QLabel(label_text)
            lbl.setFixedWidth(210)
            lbl.setStyleSheet(f"color:{D['muted']};font-size:11px;")
            h.addWidget(lbl); h.addWidget(widget, 1)
            grid.addLayout(h)

        # Rate limit
        self._rate_sp = QSpinBox()
        self._rate_sp.setRange(0, 9999)
        self._rate_sp.setValue(default_rate)
        self._rate_sp.setStyleSheet(f"QSpinBox{{background:{D['surf2']};color:{D['text2']};border:1px solid {D['border']};border-radius:4px;padding:3px 6px;}}")
        _row(T("main.rate_label"), self._rate_sp)

        # User-Agent
        self._ua_le = QLineEdit(default_ua)
        self._ua_le.setPlaceholderText("Mozilla/5.0 ...")
        self._ua_le.setStyleSheet(INP)
        _row(T("main.ua_label"), self._ua_le)

        # Request Header
        self._hdr_le = QLineEdit(default_hdr)
        self._hdr_le.setPlaceholderText("X-Custom: value")
        self._hdr_le.setStyleSheet(INP)
        _row(T("main.hdr_label"), self._hdr_le)

        lay.addLayout(grid)

        # ── Gombok ───────────────────────────────────────────────────────────
        btn_lay = QHBoxLayout(); btn_lay.setSpacing(8)
        btn_lay.addStretch()
        cancel_btn = QPushButton(T("btn.cancel"))
        cancel_btn.setStyleSheet(BMUT); cancel_btn.setFixedWidth(100)
        cancel_btn.clicked.connect(self.reject)
        btn_lay.addWidget(cancel_btn)
        start_btn = QPushButton(T("scope.start_btn"))
        start_btn.setStyleSheet(BRUN); start_btn.setFixedWidth(130)
        start_btn.clicked.connect(self.accept)
        btn_lay.addWidget(start_btn)
        lay.addLayout(btn_lay)

    @property
    def rate(self): return self._rate_sp.value()
    @property
    def ua(self): return self._ua_le.text().strip()
    @property
    def hdr(self): return self._hdr_le.text().strip()


# ─── Sudo Dialog ──────────────────────────────────────────────────────────────
class SudoDialog(QDialog):
    def __init__(self,parent=None):
        super().__init__(parent); self.password=""; self.setWindowTitle("Root"); self.setFixedSize(380,160); self.setStyleSheet(SS)
        lay=QVBoxLayout(self); lay.setContentsMargins(20,20,20,16); lay.setSpacing(10)
        row=QHBoxLayout(); icon=QLabel("🔐"); icon.setStyleSheet("font-size:24px;background:transparent;")
        v=QVBoxLayout(); v.addWidget(QLabel(T("scan.sudo_title"))); v.addWidget(QLabel(T("scan.sudo_hint")))
        row.addWidget(icon); row.addLayout(v); row.addStretch(); lay.addLayout(row)
        self._pw=QLineEdit(); self._pw.setEchoMode(QLineEdit.EchoMode.Password); self._pw.setPlaceholderText(T("scan.sudo_ph")); self._pw.setStyleSheet(INP); fp(self._pw); self._pw.returnPressed.connect(self._ok); lay.addWidget(self._pw)
        bl=QHBoxLayout(); ok=QPushButton("OK"); ok.setStyleSheet(BRUN); ok.setFixedWidth(80); ok.clicked.connect(self._ok)
        ca=QPushButton(T("btn.cancel")); ca.setStyleSheet(BMUT); ca.setFixedWidth(80); ca.clicked.connect(self.reject)
        bl.addStretch(); bl.addWidget(ca); bl.addWidget(ok); lay.addLayout(bl)

    def _ok(self): self.password=self._pw.text(); self.accept()

# ─── NoScrollComboBox — ignores mouse wheel to prevent accidental value change ─
class NoScrollComboBox(QComboBox):
    """QComboBox that ignores scroll wheel events — prevents accidental changes
    when the user scrolls the sidebar."""
    def wheelEvent(self, event):
        event.ignore()  # pass scroll to parent instead of changing value


# ─── Scope file parser ────────────────────────────────────────────────────────
def _wildcard_to_apex(pattern):
    """
    Egy wildcard mintából kinyeri az apex domain(oka)t, amire subfinder-t kell futtatni.
    Példák:
      *.xyz.com          → xyz.com
      xy-*.xyz.com       → xyz.com
      *.asd.*.xyz.com    → xyz.com  (legmélyebb nem-wildcard suffix)
      *.asd.xyz.com      → xyz.com
    Visszaad: (apex_domain, regex_pattern_string)
    """
    # Protokoll eltávolítása
    p = re.sub(r'^https?://', '', pattern).rstrip('/')
    parts = p.split('.')

    # Apex = az utolsó N rész ahol nincs csillag, de legalább 2 rész
    # Megkeressük a legjobboldalibb csillagos szegmenst
    last_star_idx = -1
    for i, seg in enumerate(parts):
        if '*' in seg:
            last_star_idx = i

    if last_star_idx == -1:
        # Nincs wildcard — normál domain
        return p, None

    # Az apex a last_star_idx utáni részek
    apex_parts = parts[last_star_idx + 1:]
    if len(apex_parts) < 1:
        # Csak TLD maradt pl "*.com" — nem kezeljük
        return None, None
    apex = '.'.join(apex_parts)

    # Regex pattern: csillag → bármely nem-pont karaktersorozat
    escaped = re.escape(p).replace(r'\*', r'[^.]+')
    regex = f'^{escaped}$'
    return apex, regex


def _is_wildcard_pattern(s):
    """Igaz ha a string tartalmaz * karaktert és így wildcard pattern."""
    return '*' in s


def parse_scope_file(path):
    """
    Parse a bug bounty scope file (copy-pasted from platform).
    Returns list of dicts: {domain, is_wildcard, scan_subfinder,
                             wildcard_pattern, wildcard_regex, apex_domain}

    Supported types (second line of each block):
      URL, Web application, API              → direct domain, skip subfinder
      Wildcard                               → strip *., run subfinder
      Mobile application iOS/Android, other  → skip entirely

    Wildcard formátumok (automatikusan felismeri, ha a sorban * van):
      *.xyz.com          → subfinder xyz.com, összes eredmény
      xy-*.xyz.com       → subfinder xyz.com, szűrés: xy-<valami>.xyz.com
      *.asd.*.xyz.com    → subfinder xyz.com, szűrés: <valami>.asd.<valami>.xyz.com
    """
    SKIP_TYPES = {
        "mobile application ios", "mobile application android",
        "mobile application", "ios", "android", "out of scope",
        "hardware", "other",
    }
    URL_TYPES = {
        "url", "web application", "api", "web app",
    }
    WILDCARD_TYPES = {"wildcard"}

    results = []
    seen = set()

    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            raw = f.read()
    except Exception as e:
        return [], str(e)

    lines = [l.rstrip() for l in raw.splitlines()]

    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if not line:
            i += 1
            continue

        target = line
        type_line = lines[i+1].strip().lower() if i+1 < len(lines) else ""
        i += 1
        if type_line:
            i += 1
            while i < len(lines) and lines[i].strip() and not _looks_like_target(lines[i].strip()):
                i += 1

        if any(sk in type_line for sk in SKIP_TYPES):
            continue

        is_wildcard = any(wt in type_line for wt in WILDCARD_TYPES)

        # Protokoll eltávolítása
        target_clean = re.sub(r"^https?://", "", target).rstrip("/")

        # Wildcard felismerés: ha a célban * van, automatikusan wildcard
        wildcard_pattern = None
        wildcard_regex   = None
        apex_domain      = None

        if _is_wildcard_pattern(target_clean):
            is_wildcard = True
            wildcard_pattern = target_clean
            apex_domain, wildcard_regex = _wildcard_to_apex(target_clean)
            if apex_domain is None:
                i += 0; continue
            # A "domain" mező az apex lesz, amire subfinder fut
            domain = apex_domain
        elif target_clean.startswith("*."):
            # Klasszikus *.xyz.com forma
            is_wildcard = True
            wildcard_pattern = target_clean
            domain = target_clean[2:]
            apex_domain = domain
            wildcard_regex = None  # minden subdomain OK
        else:
            domain = target_clean
            apex_domain = domain

        # Skip ha nem domain
        if not domain or " " in domain or "," in domain:
            continue
        if any(skip in domain for skip in ["apple.com", "play.google.com", "github.com"]):
            continue
        if not re.search(r"\.[a-z]{2,}$", domain, re.I):
            continue

        key = wildcard_pattern or domain
        if key not in seen:
            seen.add(key)
            results.append({
                "domain":           domain,          # apex — subfinder erre fut
                "is_wildcard":      is_wildcard,
                "scan_subfinder":   is_wildcard,
                "wildcard_pattern": wildcard_pattern, # eredeti minta pl. xy-*.xyz.com
                "wildcard_regex":   wildcard_regex,   # compiled regex szűréshez
                "apex_domain":      apex_domain,
            })

    return results, None

def _looks_like_target(s):
    """Heuristic: does this line look like a new domain/URL target?"""
    s = s.strip()
    if not s: return False
    if "." in s and " " not in s: return True
    if s.startswith("http"): return True
    return False


# ─── ScanWorker ───────────────────────────────────────────────────────────────
class ScanWorker(QThread):
    log=pyqtSignal(str); progress=pyqtSignal(int,str); done_db=pyqtSignal(dict); finished=pyqtSignal(bool,str)
    def __init__(self,domain,rate,workdir,sudo_pw="",ua="",hdr="",skip_subfinder=False,
                 wildcard_regex=None,wildcard_pattern=None):
        super().__init__()
        self.domain=domain; self.rate=rate; self.workdir=workdir
        self.sudo_pw=sudo_pw; self.ua=ua; self.hdr=hdr
        self.skip_subfinder=skip_subfinder; self._stop=False
        self.wildcard_regex=wildcard_regex; self.wildcard_pattern=wildcard_pattern
    def stop(self): self._stop=True
    def _cmd(self,cmd,label,shell=False):
        self.log.emit(f"<span style='color:#58a6ff'>▶ {label}</span>")
        self.log.emit(f"<span style='color:#484f58'>$ {_html.escape(cmd if isinstance(cmd,str) else ' '.join(cmd))}</span>")
        try:
            r=subprocess.run(cmd,shell=shell,capture_output=True,text=True,timeout=600)
            out=(r.stdout or r.stderr).strip()
            for l in out.splitlines()[:4]: self.log.emit(f"<span style='color:#8b949e'>{_html.escape(l)}</span>")
            return r.stdout.strip(),r.returncode
        except Exception as e:
            self.log.emit(f"<span style='color:#f85149'>✗ {e}</span>"); return "",-1
    def run(self):
        try: self._scan()
        except Exception as e: self.finished.emit(False,str(e))
    def _scan(self):
        d=self.domain; wdir=self.workdir
        sf=os.path.join(wdir,"subdomains.txt")
        hf=os.path.join(wdir,"httpx.json")
        df=os.path.join(wdir,"dnsx.txt")
        wildcard_regex = getattr(self, 'wildcard_regex', None)
        wildcard_pattern = getattr(self, 'wildcard_pattern', None)
        # 1. subfinder (skip if direct URL scan)
        if self._stop: return
        if self.skip_subfinder:
            self.log.emit(f"<span style='color:#d29922'>⤷ {T('scan.direct_url',d=d)}</span>")
            with open(sf,"w") as fw: fw.write(d+"\n")
            subs=[d]
            self.log.emit(f"<span style='color:#3fb950'>✓ 1 direkt URL: {d}</span>")
        else:
            self.progress.emit(5,"Subfinder fut...")
            pw=f"echo {shlex.quote(self.sudo_pw)} | sudo -S " if self.sudo_pw else ""
            self._cmd(f"{pw}subfinder -d {d} -all -o {shlex.quote(sf)} -silent","Subfinder",shell=True)
            if not os.path.exists(sf) or os.path.getsize(sf)==0:
                self.finished.emit(False,"Subfinder hiba — nincs subdomain"); return
            with open(sf) as f: raw_subs=sorted(set(l.strip() for l in f if l.strip()))
            # Wildcard pattern szűrés ha van (pl. xy-*.xyz.com → csak xy-valami.xyz.com)
            if wildcard_regex:
                subs = [s for s in raw_subs if re.match(wildcard_regex, s, re.I)]
                self.log.emit(f"<span style='color:#d29922'>⤷ Wildcard szűrés: {wildcard_pattern} → {len(subs)}/{len(raw_subs)} match</span>")
                # Felülírjuk a fájlt a szűrt listával
                with open(sf,"w") as fw: fw.write("\n".join(subs)+"\n")
            else:
                subs = raw_subs
            if not subs:
                self.finished.emit(False,f"Wildcard szűrés után nincs találat: {wildcard_pattern}"); return
            self.log.emit(f"<span style='color:#3fb950'>✓ {len(subs)} subdomain</span>")
        self.progress.emit(25,f"{len(subs)} subdomain — httpx fut...")
        # 2. httpx
        if self._stop: return
        hfl=""
        if self.hdr: hfl+=f' -H "{self.hdr}"'
        if self.ua:  hfl+=f' -H "User-Agent: {self.ua}"'
        rl=f"-rate-limit {self.rate}" if self.rate>0 else ""
        cmd=(f"httpx -l {shlex.quote(sf)} -title -status-code -web-server -tech-detect -follow-redirects {rl} -no-color -json -o {shlex.quote(hf)} -silent{hfl}")
        self._cmd(cmd,"httpx",shell=True)
        if not os.path.exists(hf) or os.path.getsize(hf)==0:
            hf2=os.path.join(wdir,"httpx.txt")
            cmd=(f"httpx -l {shlex.quote(sf)} -title -status-code -web-server -tech-detect -follow-redirects {rl} -no-color -o {shlex.quote(hf2)} -silent{hfl}")
            self._cmd(cmd,"httpx (text fallback)",shell=True); hf=hf2
        self.progress.emit(55,"dnsx fut...")
        # 3. dnsx
        if self._stop: return
        self._cmd(f"dnsx -l {shlex.quote(sf)} -resp -no-color -a -cname -o {shlex.quote(df)} -silent","dnsx",shell=True)
        self.progress.emit(75,"wget Last-Modified...")
        # 4. wget last-modified — csak httpx által talált URL-ekre, párhuzamosan
        hdata=self._phttpx(hf)
        httpx_subs=set(hdata.keys())
        last_mod={sub:"N/A" for sub in subs}

        def _wget_one(sub):
            if self._stop: return sub,"N/A"
            for scheme in ("https","http"):
                try:
                    r=subprocess.run(
                        f'wget --server-response --spider --timeout=3 --tries=1 -q -O /dev/null'
                        f' "{scheme}://{sub}" 2>&1 | grep -i "Last-Modified:" | sed \'s/^[[:space:]]*//' + "' | cut -d' ' -f2-",
                        shell=True,capture_output=True,text=True,timeout=8)
                    v=(r.stdout or r.stderr).strip()
                    if v: return sub,v
                except: pass
            return sub,"N/A"

        httpx_subs_list=[s for s in subs if s in httpx_subs]
        max_workers=min(20,len(httpx_subs_list)) if httpx_subs_list else 1
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs={ex.submit(_wget_one,s):s for s in httpx_subs_list}
            for fut in as_completed(futs):
                if self._stop: break
                sub,val=fut.result(); last_mod[sub]=val

        self.progress.emit(90,T("scan.db_building"))
        # 5. parse & merge
        ddata=self._pdnsx(df)
        db={}
        for sub in subs:
            h=hdata.get(sub,{}); dns=ddata.get(sub,[])
            db[sub]={"subdomain":sub,"title":h.get("title",""),"status":h.get("status_code",""),
                     "webserver":h.get("webserver",""),"tech":h.get("tech",""),
                     "dns":dns,"last_modified":last_mod.get(sub,"N/A")}
        self.progress.emit(100,T("scan.ready_label"))
        self.done_db.emit(db); self.finished.emit(True,T("scan.done",n=len(subs)))

    def _phttpx(self,fp2):
        data={}
        if not os.path.exists(fp2): return data
        try:
            with open(fp2,encoding="utf-8",errors="ignore") as f:
                first=f.readline().strip()
                if not first: return data
                is_json=first.startswith("{")
                lines=[first]+f.readlines()
            if is_json:
                for line in lines:
                    line=line.strip()
                    if not line: continue
                    try:
                        j=json.loads(line)
                        url=j.get("url",j.get("input",""))
                        host=re.sub(r'^https?://','',url).rstrip('/')
                        if not host: continue
                        tr=j.get("technologies",j.get("tech",[]))
                        final_code=str(j.get("status_code",""))
                        chain_codes_raw=j.get("chain_status_codes",[])
                        if not chain_codes_raw:
                            chain=j.get("chain",[])
                            chain_codes_raw=[c.get("status_code","") for c in chain if c.get("status_code")]
                        chain_codes=[str(c) for c in chain_codes_raw if str(c)]
                        status_display=", ".join(chain_codes) if chain_codes else final_code
                        data[host]={"status_code":status_display,"title":j.get("title",""),
                                    "webserver":j.get("webserver",""),
                                    "tech":", ".join(tr) if isinstance(tr,list) else str(tr)}
                    except: continue
            else:
                for line in lines:
                    line=line.strip()
                    if not line: continue
                    um=re.match(r'(https?://[^\s\[]+)',line)
                    if not um: continue
                    host=re.sub(r'^https?://','',um.group(1)).rstrip('/')
                    brackets=re.findall(r'\[([^\]]*)\]',line[len(um.group(0)):])
                    numbered=[(i,v) for i,v in enumerate(brackets) if re.match(r'^\d{3}$',v.strip())]
                    if numbered:
                        idx,status=numbered[0]; rem=[v for i,v in enumerate(brackets) if i!=idx]
                        data[host]={"status_code":status.strip(),"title":(rem[0].strip() if rem else ""),
                                    "webserver":(rem[1].strip() if len(rem)>1 else ""),
                                    "tech":", ".join(v.strip() for v in rem[2:])}
        except Exception as e: self.log.emit(f"<span style='color:#f85149'>! httpx parse: {e}</span>")
        return data

    def _pdnsx(self,fp2):
        data=defaultdict(list)
        if not os.path.exists(fp2): return data
        try:
            with open(fp2,encoding="utf-8",errors="ignore") as f:
                for line in f:
                    line=line.strip()
                    m=re.match(r'^(\S+)\s+\[(\w+)\]\s+\[([^\]]+)\]',line)
                    if m: data[m.group(1).rstrip('.')].append((m.group(2),m.group(3).rstrip('.')))
        except Exception as e: self.log.emit(f"<span style='color:#f85149'>! dnsx parse: {e}</span>")
        return data

# ─── HTTP status color helpers ────────────────────────────────────────────────
def hcol(c):
    """Color based on final status code. Handles '200', '301,200', '[301,200]' formats."""
    codes = re.findall(r"\d{3}", str(c))
    if not codes: return D["muted"]
    last = codes[-1]
    if last.startswith("2"): return D["green"]
    if last.startswith("3"): return "#79c0ff"  # Kék (3xx)
    if last.startswith("4"): return D["red"]
    if last.startswith("5"): return D["orange"]
    return D["muted"]

def format_http_status_html(status_str):
    """
    Format HTTP status codes with color scheme:
    1xx: light purple, 2xx: green, 3xx: blue, 4xx: red, 5xx: orange
    Input: '200' or '302, 200'
    Output: HTML with colored codes
    """
    codes = re.findall(r"\d{3}", str(status_str))
    if not codes:
        return status_str
    color_map = {
        "1": "#d2a8ff",
        "2": D["green"],
        "3": "#79c0ff",
        "4": D["red"],
        "5": D["orange"],
    }
    html_parts = []
    for i, code in enumerate(codes):
        color = color_map.get(code[0], D["muted"])
        html_parts.append(f"<span style='color:{color};font-weight:bold'>{code}</span>")
        if i < len(codes) - 1:
            html_parts.append("<span style='color:white'>, </span>")
    return "".join(html_parts)


# ─── HTTP Status Cell Delegate — per-kód szín a táblában ─────────────────────
class HttpStatusDelegate(QStyledItemDelegate):
    """Custom delegate: minden HTTP státuszkódot saját színnel rajzol ki."""
    # Szín map — egy helyen definiálva
    COLOR_MAP = {
        "1": "#d2a8ff",   # 1xx lila
        "2": None,        # 2xx — D['green'] runtime-ban
        "3": "#79c0ff",   # 3xx kék
        "4": None,        # 4xx — D['red'] runtime-ban
        "5": None,        # 5xx — D['orange'] runtime-ban
    }

    def _code_color(self, code):
        d = code[0] if code else "?"
        return {
            "1": "#d2a8ff",
            "2": D["green"],
            "3": "#79c0ff",
            "4": D["red"],
            "5": D["orange"],
        }.get(d, D["muted"])

    def paint(self, painter, option, index):
        painter.save()
        # Background
        if option.state & QStyle.StateFlag.State_Selected:
            painter.fillRect(option.rect, QColor(D["acc"] + "55"))
        else:
            painter.fillRect(option.rect, QColor(D["surf"]))

        status_str = index.data(Qt.ItemDataRole.DisplayRole) or ""
        codes = re.findall(r"\d{3}", status_str)

        if not codes:
            painter.restore()
            return

        # Minden kód szélességét kiszámítjuk
        font = QFont("JetBrains Mono", 11, QFont.Weight.Bold)
        painter.setFont(font)
        fm = painter.fontMetrics()
        comma_w = fm.horizontalAdvance(", ")

        # Teljes szélességet számítjuk
        parts = []
        for i, code in enumerate(codes):
            w = fm.horizontalAdvance(code)
            parts.append((code, w))

        total_w = sum(p[1] for p in parts) + comma_w * (len(parts) - 1)
        x = option.rect.x() + (option.rect.width() - total_w) / 2
        y = option.rect.y() + (option.rect.height() + fm.ascent() - fm.descent()) / 2

        for i, (code, w) in enumerate(parts):
            painter.setPen(QColor(self._code_color(code)))
            painter.drawText(int(x), int(y), code)
            x += w
            if i < len(parts) - 1:
                painter.setPen(QColor("#ffffff"))
                painter.drawText(int(x), int(y), ", ")
                x += comma_w

        painter.restore()

    def sizeHint(self, option, index):
        codes = re.findall(r"\d{3}", str(index.data() or ""))
        h = 28 if len(codes) <= 1 else 36
        return QSize(80, h)


# ─── BatchScanWorker — runs multiple domains sequentially ─────────────────────
class BatchScanWorker(QThread):
    """Runs ScanWorker for each domain in scope list, merges results into one DB."""
    log       = pyqtSignal(str)
    progress  = pyqtSignal(int, str)
    done_db   = pyqtSignal(dict)
    finished  = pyqtSignal(bool, str)

    def __init__(self, scope_list, rate, workdir_base, sudo_pw="", ua="", hdr=""):
        super().__init__()
        # scope_list: list of {domain, is_wildcard, scan_subfinder}
        self.scope_list   = scope_list
        self.rate         = rate
        self.workdir_base = workdir_base
        self.sudo_pw      = sudo_pw
        self.ua           = ua
        self.hdr          = hdr
        self._stop        = False
        self._merged_db   = {}

    def stop(self): self._stop = True

    def run(self):
        total = len(self.scope_list)
        self.log.emit(f"<span style='color:{D["acc"]};font-weight:bold;'>═══ Batch scan: {total} domain ═══</span>")
        for idx, entry in enumerate(self.scope_list):
            if self._stop: break
            domain       = entry["domain"]
            skip_sf      = not entry.get("scan_subfinder", True)
            entry_type   = "Wildcard" if entry.get("is_wildcard") else "URL"
            pct_base     = int(idx / total * 100)
            pct_end      = int((idx+1) / total * 100)

            self.log.emit(f"<span style='color:{D['acc']}'>▶ [{idx+1}/{total}] {domain} ({entry_type})</span>")
            if entry.get("wildcard_pattern"):
                self.log.emit(f"<span style='color:#d29922'>  ⤷ Wildcard: {entry['wildcard_pattern']}</span>")
            self.progress.emit(pct_base, f"[{idx+1}/{total}] {domain}")

            wdir = os.path.join(self.workdir_base, f"domain_{idx:04d}_{domain.replace('.','_')}")
            os.makedirs(wdir, exist_ok=True)

            scanner = _SyncScan(
                domain=domain, rate=self.rate, workdir=wdir,
                sudo_pw=self.sudo_pw, ua=self.ua, hdr=self.hdr,
                skip_subfinder=skip_sf,
                log_fn=self.log.emit,
                stop_fn=lambda: self._stop,
            )
            # Wildcard adatok átadása
            scanner.wildcard_regex   = entry.get("wildcard_regex")
            scanner.wildcard_pattern = entry.get("wildcard_pattern")
            db = scanner.run()
            self._merged_db.update(db)
            self.done_db.emit(dict(self._merged_db))  # incremental update
            self.progress.emit(pct_end, T("scan.batch_prog",i=idx+1,t=total,d=domain,n=len(db)))

        if not self._stop:
            self.finished.emit(True, T("scan.batch_done",n=len(self._merged_db)))
        else:
            self.finished.emit(False, T("scan.batch_stopped",n=len(self._merged_db)))


class _SyncScan:
    """Synchronous (non-threaded) version of ScanWorker for use inside BatchScanWorker."""
    def __init__(self, domain, rate, workdir, sudo_pw, ua, hdr, skip_subfinder, log_fn, stop_fn):
        self.domain=domain; self.rate=rate; self.workdir=workdir
        self.sudo_pw=sudo_pw; self.ua=ua; self.hdr=hdr
        self.skip_subfinder=skip_subfinder
        self._log=log_fn; self._stopped=stop_fn

    def _cmd(self, cmd, label, shell=False):
        self._log(f"<span style='color:#58a6ff'>  ▷ {label}</span>")
        self._log(f"<span style='color:#484f58'>  $ {_html.escape(cmd if isinstance(cmd,str) else ' '.join(cmd))}</span>")
        try:
            r=subprocess.run(cmd,shell=shell,capture_output=True,text=True,timeout=600)
            out=(r.stdout or r.stderr).strip()
            for l in out.splitlines()[:3]:
                self._log(f"<span style='color:#8b949e'>  {_html.escape(l)}</span>")
            return r.stdout.strip(), r.returncode
        except Exception as e:
            self._log(f"<span style='color:#f85149'>  ✗ {e}</span>"); return "",-1

    def run(self):
        d=self.domain; wdir=self.workdir
        sf=os.path.join(wdir,"subdomains.txt")
        hf=os.path.join(wdir,"httpx.json")
        df=os.path.join(wdir,"dnsx.txt")

        # 1. subfinder or direct
        if self.skip_subfinder:
            with open(sf,"w") as fw: fw.write(d+"\n")
            subs=[d]
            self._log(f"<span style='color:#d29922'>  ⤷ Direkt URL: {d}</span>")
        else:
            pw=f"echo {shlex.quote(self.sudo_pw)} | sudo -S " if self.sudo_pw else ""
            self._cmd(f"{pw}subfinder -d {d} -all -o {shlex.quote(sf)} -silent","subfinder",shell=True)
            if not os.path.exists(sf) or os.path.getsize(sf)==0:
                self._log(f"<span style='color:#f85149'>  ✗ {T('scan.no_subfinder',d=d)}</span>")
                return {}
            with open(sf) as f: raw_subs=sorted(set(l.strip() for l in f if l.strip()))
            # Wildcard regex szűrés ha van (pl. xy-*.xyz.com)
            wc_regex   = getattr(self, 'wildcard_regex', None)
            wc_pattern = getattr(self, 'wildcard_pattern', None)
            if wc_regex:
                subs = [s for s in raw_subs if re.match(wc_regex, s, re.I)]
                self._log(f"<span style='color:#d29922'>  ⤷ Wildcard szűrés: {wc_pattern} → {len(subs)}/{len(raw_subs)} match</span>")
                with open(sf,"w") as fw: fw.write("\n".join(subs)+"\n")
            else:
                subs = raw_subs
            if not subs:
                self._log(f"<span style='color:#f85149'>  ✗ Wildcard szűrés után nincs találat: {wc_pattern}</span>")
                return {}
            self._log(f"<span style='color:#3fb950'>  ✓ {len(subs)} subdomain: {d}</span>")

        if self._stopped(): return {}

        # 2. httpx
        hfl=""
        if self.hdr: hfl+=f' -H "{self.hdr}"'
        if self.ua:  hfl+=f' -H "User-Agent: {self.ua}"'
        rl=f"-rate-limit {self.rate}" if self.rate>0 else ""
        cmd=(f"httpx -l {shlex.quote(sf)} -title -status-code -web-server "
             f"-tech-detect -follow-redirects {rl} -no-color -json -o {shlex.quote(hf)} -silent{hfl}")
        self._cmd(cmd,"httpx",shell=True)
        if not os.path.exists(hf) or os.path.getsize(hf)==0:
            hf2=os.path.join(wdir,"httpx.txt")
            cmd=(f"httpx -l {shlex.quote(sf)} -title -status-code -web-server "
                 f"-tech-detect -follow-redirects {rl} -no-color -o {shlex.quote(hf2)} -silent{hfl}")
            self._cmd(cmd,"httpx (text fallback)",shell=True); hf=hf2

        if self._stopped(): return {}

        # 3. dnsx
        self._cmd(f"dnsx -l {shlex.quote(sf)} -resp -no-color -a -cname -o {shlex.quote(df)} -silent","dnsx",shell=True)

        # 4. wget last-modified — csak httpx által talált URL-ekre, párhuzamosan
        w = ScanWorker.__new__(ScanWorker)  # reuse parsers without threading
        w.log = type('L',(),{'emit':self._log})()
        hdata = w._phttpx(hf) if hasattr(w,'_phttpx') else {}
        httpx_subs=set(hdata.keys())
        last_mod={sub:"N/A" for sub in subs}

        def _wget_one(sub):
            if self._stopped(): return sub,"N/A"
            for scheme in ("https","http"):
                try:
                    r=subprocess.run(
                        f'wget --server-response --spider --timeout=3 --tries=1 -q -O /dev/null "{scheme}://{sub}" 2>&1'
                        f" | grep -i 'Last-Modified:' | sed 's/^[[:space:]]*//' | cut -d' ' -f2-",
                        shell=True,capture_output=True,text=True,timeout=8)
                    v=(r.stdout or r.stderr).strip()
                    if v: return sub,v
                except: pass
            return sub,"N/A"

        httpx_subs_list=[s for s in subs if s in httpx_subs]
        max_workers=min(20,len(httpx_subs_list)) if httpx_subs_list else 1
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs={ex.submit(_wget_one,s):s for s in httpx_subs_list}
            for fut in as_completed(futs):
                if self._stopped(): break
                sub,val=fut.result(); last_mod[sub]=val

        # 5. parse & merge
        ddata = w._pdnsx(df)  if hasattr(w,'_pdnsx') else {}

        db={}
        for sub in subs:
            h=hdata.get(sub,{}); dns=ddata.get(sub,[])
            db[sub]={"subdomain":sub,"title":h.get("title",""),"status":h.get("status_code",""),
                     "webserver":h.get("webserver",""),"tech":h.get("tech",""),
                     "dns":list(dns),"last_modified":last_mod.get(sub,"N/A")}
        return db


# ─── ResultTable (collapsible rows) ─────────────────────────────────────────
def COL_NAMES(): return [T("col.expand"),T("col.subdomain"),T("col.title"),T("col.http"),T("col.webserver"),T("col.tech"),T("col.dns_type"),T("col.dns_val"),T("col.takeover"),T("col.last_mod")]
COL_W    =[28, 240,        160,     80,    120,         160,   80,         200,        80,        140]
C_EXP,C_SUB,C_TITLE,C_HTTP,C_WS,C_TECH,C_DTYPE,C_DVAL,C_TAKE,C_LAST=range(10)

class ResultTable(QTableWidget):
    """
    One row per subdomain (collapsed). Click ▶ to expand DNS records inline.
    """
    def __init__(self,parent=None):
        super().__init__(0,len(COL_NAMES()),parent)
        self._db={}
        self._sub_rows={}    # sub -> main row index
        self._expanded=set() # subs currently expanded
        self._setup()

    def _setup(self):
        self.setHorizontalHeaderLabels(COL_NAMES())
        hh=self.horizontalHeader()
        for i,w in enumerate(COL_W): self.setColumnWidth(i,w)
        for i in range(len(COL_NAMES())): hh.setSectionResizeMode(i,QHeaderView.ResizeMode.Interactive)
        hh.setSectionResizeMode(C_EXP, QHeaderView.ResizeMode.Fixed)
        hh.setStretchLastSection(False)   # NE stretch — auto-fit kezeli
        hh.setMinimumSectionSize(24)
        hh.setSortIndicatorShown(True); hh.setSectionsClickable(True)
        self.setSortingEnabled(False)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(30)
        self.setShowGrid(True); self.setWordWrap(True)
        # Scrollbar — mindig látható, húzható (javítja a drag-problémát)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._ctx)
        self.cellClicked.connect(self._on_click)
        # HTTP cella: custom delegate per-kód szín-kódoláshoz
        self._http_delegate = HttpStatusDelegate(self)
        self.setItemDelegateForColumn(C_HTTP, self._http_delegate)

    def load_db(self,db):
        self.setSortingEnabled(False); self.setUpdatesEnabled(False)
        sorted_items=sorted(db.items())
        self.setRowCount(0)
        self._db=db; self._sub_rows={}; self._expanded=set()
        self.setRowCount(len(sorted_items))
        for r,(sub,rec) in enumerate(sorted_items):
            self._sub_rows[sub]=r
            self._fill_main_row(r,sub,rec)
        self.setUpdatesEnabled(True)
        self._auto_fit_columns()

    def _auto_fit_columns(self):
        """Oszlopszélességeket a tartalom alapján állítja be. Max 200 sor mintavétel."""
        hh = self.horizontalHeader()
        fm = self.fontMetrics()
        MAX_COL = {C_SUB:420,C_TITLE:320,C_TECH:300,C_DVAL:340,C_LAST:180}
        PAD = 20
        total = self.rowCount()
        step = max(1, total // 200)  # Max ~200 sor mintavétel

        for col in range(len(COL_NAMES())):
            if col == C_EXP: continue
            header_text = self.horizontalHeaderItem(col)
            best = fm.horizontalAdvance(header_text.text() if header_text else "") + PAD
            for row in range(0, total, step):
                item = self.item(row, col)
                if item:
                    w = fm.horizontalAdvance(item.text()) + PAD
                    if w > best: best = w
            final_w = max(COL_W[col], min(best, MAX_COL.get(col, 600)))
            self.setColumnWidth(col, final_w)
            hh.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)

    def _fill_main_row(self, r, sub, rec):
        def ti(t,c=D["text2"],align=None):
            it=QTableWidgetItem(str(t)); it.setForeground(QColor(c))
            if align: it.setTextAlignment(align)
            return it

        # Expand toggle button cell
        dns = rec.get("dns",[])
        has_dns = len(dns) > 0
        exp_it = QTableWidgetItem("▶" if has_dns else " ")
        exp_it.setTextAlignment(Qt.AlignmentFlag.AlignCenter|Qt.AlignmentFlag.AlignVCenter)
        exp_it.setForeground(QColor(D["acc"] if has_dns else D["dim"]))
        exp_it.setToolTip(T("tbl.dns_tip") if has_dns else "")
        self.setItem(r,C_EXP,exp_it)

        # Subdomain
        si=ti(sub,D["acc"]); si.setToolTip(T("tbl.sub_tip"))
        self.setItem(r,C_SUB,si)

        self.setItem(r,C_TITLE,ti(rec.get("title","")))

        # HTTP — delegate rajzolja szín-kódoltan (HttpStatusDelegate)
        status = rec.get("status", "")
        codes = re.findall(r"\d{3}", status)
        display = ", ".join(codes) if codes else status

        hi = QTableWidgetItem(display)
        hi.setData(Qt.ItemDataRole.UserRole, display)   # delegate ezt olvassa
        hi.setTextAlignment(Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignVCenter)
        # Tooltip: szín-kódolt HTML
        html_status = format_http_status_html(display)
        hi.setToolTip(f"{T('tbl.http_tip')}<br>{html_status.replace(', ', '<br>')}")
        self.setItem(r, C_HTTP, hi)
        if len(codes) > 1:
            self.setRowHeight(r, 34)

        self.setItem(r,C_WS,ti(rec.get("webserver",""),D["muted"]))
        self.setItem(r,C_TECH,ti(rec.get("tech","")))

        # DNS summary in collapsed state
        if dns:
            types  = ", ".join(sorted(set(t for t,v in dns)))
            values = ", ".join(v for t,v in dns[:2]) + ("…" if len(dns)>2 else "")
        else:
            types=""; values=""
        dt_it=ti(types, D["muted"] if not dns else D["text2"])
        dt_it.setTextAlignment(Qt.AlignmentFlag.AlignCenter|Qt.AlignmentFlag.AlignVCenter)
        self.setItem(r,C_DTYPE,dt_it)
        self.setItem(r,C_DVAL,ti(values,D["muted"]))

        is_v,reason=check_takeover(rec)
        tk=QTableWidgetItem("⚠" if is_v else "✓")
        tk.setTextAlignment(Qt.AlignmentFlag.AlignCenter|Qt.AlignmentFlag.AlignVCenter)
        tk.setForeground(QColor(D["red"] if is_v else D["dim"]))
        if is_v: tk.setFont(QFont("JetBrains Mono",14,QFont.Weight.Bold)); tk.setToolTip(reason)
        self.setItem(r,C_TAKE,tk)
        self.setItem(r,C_LAST,ti(rec.get("last_modified","N/A"),D["muted"]))

    def _on_click(self,row,col):
        # Expand/collapse on ▶ column OR subdomain column left click
        sub = self._get_sub_for_mainrow(row)
        if sub is None: return
        if col==C_EXP:
            self._toggle_expand(sub, row)
        elif col==C_SUB:
            # Copy to clipboard and toast
            QGuiApplication.clipboard().setText(sub)
            self._toast(sub)

    def _get_sub_for_mainrow(self, row):
        """Return subdomain if 'row' is a main row, else None."""
        item = self.item(row, C_SUB)
        if item and item.text() in self._db:
            return item.text()
        return None

    def _get_sub_for_any_row(self, row):
        """Return the subdomain this row belongs to (main or child)."""
        # Check main row
        sub = self._get_sub_for_mainrow(row)
        if sub: return sub
        # Check if it's a child row (data in C_EXP is "  " indent marker)
        exp_item = self.item(row, C_EXP)
        if exp_item and exp_item.data(Qt.ItemDataRole.UserRole):
            return exp_item.data(Qt.ItemDataRole.UserRole)
        return None

    def _toggle_expand(self, sub, main_row):
        rec = self._db.get(sub,{})
        dns = rec.get("dns",[])
        if not dns: return

        if sub in self._expanded:
            # Collapse: remove child rows
            self._expanded.discard(sub)
            # Find and remove rows after main_row until next main row
            to_remove=[]
            r=main_row+1
            while r < self.rowCount():
                exp_it=self.item(r,C_EXP)
                if exp_it and exp_it.data(Qt.ItemDataRole.UserRole)==sub:
                    to_remove.append(r)
                    r+=1
                else:
                    break
            for r in reversed(to_remove): self.removeRow(r)
            # Update toggle indicator
            exp_cell=self.item(main_row,C_EXP)
            if exp_cell: exp_cell.setText("▶")
            # Restore summary in DNS cols
            types  = ", ".join(sorted(set(t for t,v in dns)))
            values = ", ".join(v for t,v in dns[:2]) + ("…" if len(dns)>2 else "")
            self.item(main_row,C_DTYPE).setText(types)
            self.item(main_row,C_DVAL).setText(values)
        else:
            # Expand: insert child rows after main_row
            self._expanded.add(sub)
            exp_cell=self.item(main_row,C_EXP)
            if exp_cell: exp_cell.setText("▼")
            # Clear DNS summary in main row
            self.item(main_row,C_DTYPE).setText("")
            self.item(main_row,C_DVAL).setText("")
            insert_at=main_row+1
            # Check if there's an active DNS type filter
            active_filter = getattr(self, '_active_dns_filter', "")

            for rtype,rval in dns:
                self.insertRow(insert_at)
                # Mark as child
                marker=QTableWidgetItem("  ·")
                marker.setForeground(QColor(D["dim"]))
                marker.setTextAlignment(Qt.AlignmentFlag.AlignCenter|Qt.AlignmentFlag.AlignVCenter)
                marker.setData(Qt.ItemDataRole.UserRole, sub)
                self.setItem(insert_at,C_EXP,marker)
                # Blank left columns
                for c in [C_SUB,C_TITLE,C_HTTP,C_WS,C_TECH]:
                    it=QTableWidgetItem(""); it.setBackground(QColor(D["surf2"])); self.setItem(insert_at,c,it)
                # DNS type
                dt=QTableWidgetItem(rtype)
                dt.setTextAlignment(Qt.AlignmentFlag.AlignCenter|Qt.AlignmentFlag.AlignVCenter)
                dt.setForeground(QColor("#79c0ff" if rtype=="CNAME" else (D["green"] if rtype=="A" else D["muted"])))
                dt.setBackground(QColor(D["surf2"])); self.setItem(insert_at,C_DTYPE,dt)
                # DNS value
                dv=QTableWidgetItem(rval)
                dv.setForeground(QColor(D["text2"])); dv.setBackground(QColor(D["surf2"]))
                self.setItem(insert_at,C_DVAL,dv)
                # Blank right cols
                for c in [C_TAKE,C_LAST]:
                    it=QTableWidgetItem(""); it.setBackground(QColor(D["surf2"])); self.setItem(insert_at,c,it)
                # Apply active DNS type filter immediately
                if active_filter and rtype != active_filter:
                    self.setRowHidden(insert_at, True)
                insert_at+=1
            # Update sub_rows index (rows after may have shifted)
            self._rebuild_sub_rows()

    def _rebuild_sub_rows(self):
        self._sub_rows={}
        for r in range(self.rowCount()):
            sub=self._get_sub_for_mainrow(r)
            if sub: self._sub_rows[sub]=r

    def mousePressEvent(self,ev):
        super().mousePressEvent(ev)
        if ev.button()==Qt.MouseButton.LeftButton:
            it=self.itemAt(ev.pos())
            if it and it.column()==C_SUB and it.text() and it.text() in self._db:
                QGuiApplication.clipboard().setText(it.text()); self._toast(it.text())

    def _toast(self,val):
        t=QLabel(T("tbl.copied",val=val),self.viewport())
        t.setStyleSheet(f"background:{D['surf2']};color:{D['text']};border:1px solid {D['acc']};border-radius:6px;padding:6px 12px;font-size:12px;")
        t.setAlignment(Qt.AlignmentFlag.AlignCenter); t.adjustSize()
        vp=self.viewport(); cp=vp.mapFromGlobal(QCursor.pos())
        t.move(max(0,min(cp.x()+10,vp.width()-t.width()-4)),max(0,min(cp.y()+10,vp.height()-t.height()-4)))
        t.show(); t.raise_(); QTimer.singleShot(1500,t.deleteLater)

    def _ctx(self,pos):
        it=self.itemAt(pos)
        if not it: return
        row=it.row()
        sub=self._get_sub_for_any_row(row)
        if not sub: return
        menu=QMenu(self)
        acts=[
            ("⛏   Dig",self._odig),
            ("🌐   httpx",self._ohttpx),
            ("🔎   dnsx",self._odnsx),
            None,
            ("🌐   Curl",self._ocurl),
            ("⬇   Wget",self._owget),
            ("🕷   WhatWeb",self._owhatweb),
            None,
            ("🔌   Naabu  (Fast PortScanner)",self._onaabu),
            ("🗺   Nmap  (Slow PortScanner)",self._onmap),
            None,
            ("☢   Nuclei",self._onuclei),
            ("🔀   ffuf  (Web Fuzzer)",self._offuf),
            ("⚔   Katana  (Crawler)",self._okatana),
            None,
            ("🔐   WpScan",self._owpscan),
        ]
        for item in acts:
            if item is None: menu.addSeparator(); continue
            label,fn=item; a=QAction(label,self); a.triggered.connect(lambda _=False,f=fn,s=sub: f(s)); menu.addAction(a)
        menu.exec(self.viewport().mapToGlobal(pos))

    def _tgts(self,sub):
        rec=self._db.get(sub,{}); dns=rec.get("dns",[])
        tgts=[("HOST",sub)]; seen={sub}
        for rt,rv in dns:
            if rv and rv not in seen: tgts.append((rt,rv)); seen.add(rv)
        return tgts

    def _pval(self,attr):
        # Először a globális singleton-ban keressük (parent=None esetén is működik)
        if hasattr(_AppSettings, attr):
            return getattr(_AppSettings, attr)
        p=self.parent()
        while p:
            if hasattr(p,attr): return getattr(p,attr)
            p=p.parent() if hasattr(p,'parent') else None
    def _rate(self): w=self._pval('_rate'); return w.value() if w else 5
    def _ua(self):   w=self._pval('_user_agent'); return w.text().strip() if w else ""
    def _hdr(self):  w=self._pval('_req_header'); return w.text().strip() if w else ""
    def _sudopw(self):
        # Először a globális singleton-ban keressük
        if _AppSettings._sudo_pw:
            return _AppSettings._sudo_pw
        p = self.parent()
        while p:
            if hasattr(p, '_sudo_pw'): return p._sudo_pw or ""
            p = p.parent() if hasattr(p, 'parent') else None
        return ""

    def _open(self, dlg_class, sub, *args):
        """Tool ablak megnyitása. A referenciát a globális _OPEN_DIALOGS listában tároljuk,
        hogy a QThread ne semmisüljön meg GC által futás közben (SIGABRT megelőzése)."""
        d = dlg_class(sub, self._tgts(sub), *args)
        _OPEN_DIALOGS.append(d)
        # Cleanup: ha bezárják, vegyük ki a listából
        d.finished.connect(lambda: _OPEN_DIALOGS.discard(d) if hasattr(_OPEN_DIALOGS,'discard') else None)
        d.show(); d.raise_()

    def _odig(self,sub):      self._open(DigDialog,sub)
    def _ohttpx(self,sub):    self._open(HttpxDialog,sub,self._rate(),self._ua(),self._hdr())
    def _odnsx(self,sub):     self._open(DnsxDialog,sub)
    def _ocurl(self,sub):     self._open(CurlDialog,sub,self._ua(),self._hdr())
    def _owget(self,sub):     self._open(WgetDialog,sub,self._ua(),self._hdr())
    def _owhatweb(self,sub):  self._open(WhatWebDialog,sub,self._ua(),self._hdr())
    def _onaabu(self,sub):    self._open(NaabuDialog,sub,self._rate())
    def _onmap(self,sub):     self._open(NmapDialog,sub,self._rate(),self._ua(),self._sudopw())
    def _onuclei(self,sub):   self._open(NucleiDialog,sub,self._rate(),self._ua(),self._hdr())
    def _owpscan(self,sub):   self._open(WpScanDialog,sub,self._ua(),self._hdr())
    def _offuf(self,sub):     self._open(FfufDialog,sub,self._rate(),self._ua(),self._hdr())
    def _okatana(self,sub):   self._open(KatanaDialog,sub,self._rate(),self._ua(),self._hdr())

    def apply_filters(self,filters):
        f_dt=filters.get("dns_type","")
        f_sub=filters.get("subdomain","").lower()
        f_title=filters.get("title","").lower()
        f_http=filters.get("http","")
        f_ws=filters.get("ws","").lower()
        f_tech=filters.get("tech","").lower()
        f_dv=filters.get("dns_value","").lower()
        f_take=filters.get("takeover",False)
        self._active_dns_filter = f_dt

        sub_show={}
        for sub,rec in self._db.items():
            show=True
            if f_sub and f_sub not in sub.lower(): show=False
            elif f_title and f_title not in rec.get("title","").lower(): show=False
            elif f_http and f_http not in re.findall(r"\d{3}",rec.get("status","")): show=False
            elif f_ws and f_ws not in rec.get("webserver","").lower(): show=False
            elif f_tech and f_tech not in rec.get("tech","").lower(): show=False
            elif f_dt and f_dt not in [t for t,v in rec.get("dns",[])]: show=False
            elif f_dv and not any(f_dv in v.lower() for t,v in rec.get("dns",[])): show=False
            elif f_take:
                is_v,_=check_takeover(rec)
                if not is_v: show=False
            sub_show[sub]=show

        # Second pass: apply to rows
        for r in range(self.rowCount()):
            exp_it=self.item(r,C_EXP)
            parent_sub = exp_it.data(Qt.ItemDataRole.UserRole) if exp_it else None

            if parent_sub:
                # Child row (DNS record row)
                parent_hidden = not sub_show.get(parent_sub, True)
                if parent_hidden:
                    self.setRowHidden(r, True)
                    continue
                # If DNS type filter active, hide child rows that don't match
                if f_dt:
                    dtype_it = self.item(r, C_DTYPE)
                    row_type = dtype_it.text().strip() if dtype_it else ""
                    # Hide child rows that don't match the DNS type filter
                    # Also hide empty-type rows (continuation spacers)
                    self.setRowHidden(r, row_type != f_dt)
                else:
                    self.setRowHidden(r, False)
            else:
                # Main row
                sub = self._get_sub_for_mainrow(r)
                if not sub:
                    self.setRowHidden(r, True)
                    continue
                show = sub_show.get(sub, True)
                self.setRowHidden(r, not show)

                # If DNS filter active AND this sub is expanded:
                # update the expand toggle to reflect filtered DNS summary
                if show and f_dt and sub in self._expanded:
                    rec = self._db.get(sub, {})
                    matching = [(t,v) for t,v in rec.get("dns",[]) if t==f_dt]
                    # Update summary cell in main row
                    dt_cell = self.item(r, C_DTYPE)
                    dv_cell = self.item(r, C_DVAL)
                    if dt_cell: dt_cell.setText(f_dt if matching else "")
                    if dv_cell: dv_cell.setText(", ".join(v for _,v in matching[:2]) + ("…" if len(matching)>2 else ""))

    def clear_all(self): self._db={}; self._sub_rows={}; self._expanded=set(); self.setRowCount(0)

    def export_session(self, path, settings: dict):
        """
        Teljes munkamenet mentése JSON formátumban (.inscop3).
        Tartalmazza: adatbázis, beállítások (rate, ua, header), aktív HTTP kód lista, jegyzetek.
        """
        # DNS rekordok sorosítása
        records = {}
        for sub, rec in self._db.items():
            dns = rec.get("dns", [])
            is_v, _ = check_takeover(rec)
            records[sub] = {
                "title":         rec.get("title", ""),
                "status":        rec.get("status", ""),
                "webserver":     rec.get("webserver", ""),
                "tech":          rec.get("tech", ""),
                "last_modified": rec.get("last_modified", "N/A"),
                "takeover":      is_v,
                "dns":           [[t, v] for t, v in dns],
            }
        payload = {
            "version":  3,
            "saved_at": datetime.now().isoformat(timespec="seconds"),
            "settings": settings,       # rate, ua, header
            "records":  records,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)

    def import_session(self, path):
        """
        Munkamenet betöltése .inscop3 (JSON) fájlból.
        Visszaad: (db_dict, settings_dict, notes_str, http_codes_list, error_str|None)
        """
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                raw = f.read().strip()

            # ── JSON munkamenet (.inscop3) ──────────────────────────────────
            if raw.startswith("{"):
                payload = json.loads(raw)
                settings = payload.get("settings", {})
                notes    = settings.pop("notes", "")
                http_codes = settings.pop("http_codes", [])
                records  = payload.get("records", {})
                db = {}
                for sub, r in records.items():
                    db[sub] = {
                        "subdomain":     sub,
                        "title":         r.get("title", ""),
                        "status":        r.get("status", ""),
                        "webserver":     r.get("webserver", ""),
                        "tech":          r.get("tech", ""),
                        "last_modified": r.get("last_modified", "N/A"),
                        "dns":           [tuple(x) for x in r.get("dns", [])],
                    }
                self.load_db(db)
                return db, settings, notes, http_codes, None

            # ── Régi pipe-formátum (visszafelé-kompatibilis) ────────────────
            lines = raw.splitlines()
            start = 1 if lines and lines[0].startswith("subdomain|") else 0
            db = {}
            for line in lines[start:]:
                line = line.rstrip("\n")
                if not line.strip(): continue
                parts = line.split("|")
                if len(parts) < 8: continue
                def uesc(s): return s.replace("+", " ").replace("[pipe]", "|").strip()
                sub       = uesc(parts[0])
                title     = uesc(parts[1])
                status    = uesc(parts[2])
                webserver = uesc(parts[3])
                tech      = uesc(parts[4])
                last_mod  = uesc(parts[5])
                dns_raw   = parts[6].strip()
                dns = []
                if dns_raw and dns_raw != "\t":
                    for entry in dns_raw.split(";"):
                        entry = entry.strip()
                        m = re.match(r"^(.+)\((\w+)\)$", entry)
                        if m:
                            dns.append((m.group(2), m.group(1)))
                if not sub: continue
                db[sub] = {
                    "subdomain": sub, "title": title, "status": status,
                    "webserver": webserver, "tech": tech,
                    "dns": dns, "last_modified": last_mod,
                }
            self.load_db(db)
            return db, {}, "", [], None

        except Exception as e:
            return {}, {}, "", [], str(e)

    def import_pipe(self, path):
        """Visszafelé-kompatibilis wrapper — régi pipe betöltés."""
        db, _, _, _, err = self.import_session(path)
        if err:
            return False, err
        return True, T("file.import_ok", msg=f"{len(db)} entries loaded")

    def export_pipe(self, path):
        """
        Régi pipe-separated export (megtartva visszafelé-kompatibilitáshoz).
        subdomain|title|http|webserver|tech|last_modified|dns_records|takeover
        """
        def esc(s):
            return str(s).replace("|", "[pipe]").replace(" ", "+")
        with open(path, "w", encoding="utf-8") as f:
            f.write("subdomain|title|http|webserver|tech|last_modified|dns_records|takeover\n")
            for sub, rec in sorted(self._db.items()):
                dns = rec.get("dns", [])
                is_v, _ = check_takeover(rec)
                dns_field = ";".join(f"{v}({t})" for t, v in dns) if dns else "\t"
                def f_(v): return esc(v) if str(v).strip() else "\t"
                line = "|".join([
                    f_(sub), f_(rec.get("title","")), f_(rec.get("status","")),
                    f_(rec.get("webserver","")), f_(rec.get("tech","")),
                    f_(rec.get("last_modified","N/A")), dns_field,
                    "1" if is_v else "0",
                ])
                f.write(line + "\n")

# ─── WpScan Dialog ────────────────────────────────────────────────────────────
class WpScanDialog(BaseToolDialog):
    TOOL_NAME="wpscan"; ICON="🔐"; SUBTITLE="WordPress Security Scanner"
    def __init__(self,host,dns,ua="",hdr="",parent=None):
        self._ua=ua; self._hdr=hdr; super().__init__(host,dns,parent)

    def _build_flags(self):
        self._ins_tgt(self._tgt_frame(["https://","http://"]))
        sections=[
            ("SCAN OPTIONS",[
                ("--detection-mode","Detection: mixed/passive/aggressive",True,"mixed",False),
                ("--force","Skip WordPress check / 403",False,"",False),
                ("--disable-tls-checks","Disable SSL/TLS verification",False,"",False),
                ("--stealthy","Alias: --random-user-agent + passive mode",False,"",False),
                ("--api-token","WPScan API token (vuln data)",True,"YOUR_TOKEN",False),
            ]),
            ("HTTP OPTIONS",[
                ("--user-agent","User-Agent string (auto from sidebar)",True,"Mozilla/5.0",False),
                ("--random-user-agent","Random User-Agent per scan",False,"",False),
                ("--http-auth","Basic HTTP auth login:password",True,"user:pass",False),
                ("--wp-auth","WP Application Password (REST API)",True,"admin:app_password",False),
                ("--cookie-string","Cookie string",True,"session=abc123",False),
                ("--cookie-jar","Cookie jar file",True,"/tmp/wpscan_cookies.txt",False),
            ]),
            ("ENUMERATION",[
                ("-e","Enumerate (vp,ap,p,vt,at,t,tt,cb,dbe,u,m)",True,"vp,vt,tt,cb,dbe,u",False),
                ("--plugins-detection","Plugin detection mode",True,"mixed",False),
                ("--plugins-version-detection","Plugin version detection",True,"mixed",False),
                ("--exclude-content-based","Exclude matching responses (regex)",True,"",False),
                ("--exclude-usernames","Exclude usernames (regex)",True,"",False),
                ("--wp-content-dir","Custom wp-content dir",True,"wp-content",False),
                ("--wp-plugins-dir","Custom plugins dir",True,"wp-content/plugins",False),
            ]),
            ("PASSWORD ATTACK",[
                ("-P","Passwords file",True,"/tmp/passwords.txt",False),
                ("-U","Usernames (list or file)",True,"admin,editor",False),
                ("--password-attack","Attack type (wp-login/xmlrpc/xmlrpc-multicall)",True,"wp-login",False),
                ("--login-uri","Login URI if not /wp-login.php",True,"/wp-login.php",False),
                ("--wordlist-skip","Skip first N passwords",True,"0",False),
            ]),
            ("PROXY",[
                ("--proxy","Proxy (protocol://IP:port)",True,"http://127.0.0.1:8080",False),
                ("--proxy-auth","Proxy auth login:password",True,"user:pass",False),
                ("--proxy-target-only","Proxy only for target requests",False,"",False),
            ]),
            ("PERFORMANCE",[
                ("-t","Max threads",True,"5",False),
                ("--throttle","Throttle ms between requests (sets threads=1)",True,"200",False),
                ("--request-timeout","Request timeout (s)",True,"60",False),
                ("--connect-timeout","Connection timeout (s)",True,"30",False),
                ("--max-retries","Max retry attempts",True,"0",False),
            ]),
            ("OUTPUT",[
                ("-o","Output file",True,"/tmp/wpscan_out.txt",False),
                ("-f","Output format (cli/json/sarif/jsonl)",True,"cli",False),
                ("-v","Verbose mode",False,"",False),
                ("--no-banner","Hide banner",False,"",False),
                ("--[no-]update","Update database",False,"",False),
            ]),
        ]
        for sname,flags in sections:
            self._ol.addWidget(self._sec(sname))
            for entry in flags:
                flag,h,hv,ph,defon=entry
                cb,le=self._add_flag(self._ol,flag,h,hv,ph,defon,"",
                                     flag in ["-P","-o","--cookie-jar","--passwords"])
                if flag=="--user-agent" and self._ua and le:
                    le.setText(f'"{self._ua}"'); cb.setChecked(True); le.setEnabled(True)
        self._ol.addStretch()

    def _build_cmd(self):
        # --url is always the target for wpscan
        p=["wpscan","--url",self._get_tgt()]
        for cb,le,f in self._flag_widgets:
            if cb.isChecked():
                p.append(f)
                if le and le.text().strip():
                    v=le.text().strip()
                    if f=="--user-agent" and not v.startswith('"'):
                        v=f'"{v}"'
                    p.append(v)
        return " ".join(p)

    def _on_out(self,line):
        safe=_html.escape(line); low=line.lower()
        if any(s in low for s in ["[!]","vulnerability","vulnerab","critical"]): color=D["red"]
        elif any(s in low for s in ["[+]","found","identified","detected"]): color=D["green"]
        elif any(s in low for s in ["[i]","interesting"]): color=D["acc"]
        elif any(s in low for s in ["[?]","todo"]): color=D["orange"]
        elif line.startswith("|"): color=D["text2"]
        elif not line.strip(): self._out.insertHtml("<br>"); return
        else: color=D["muted"]
        self._out.insertHtml(f"<span style='color:{color}'>{safe}</span><br>")


# ─── WhatWeb Dialog ───────────────────────────────────────────────────────────
class WhatWebDialog(BaseToolDialog):
    TOOL_NAME="whatweb"; ICON="🕷"; SUBTITLE="Next-gen web scanner"
    def __init__(self,host,dns,ua="",hdr="",parent=None):
        self._ua=ua; self._hdr=hdr; super().__init__(host,dns,parent)
    def _build_flags(self):
        self._ins_tgt(self._tgt_frame(["https://","http://"]))
        sections=[
            ("AGGRESSION",[
                ("-a","Aggression level: 1=Stealthy, 3=Aggressive, 4=Heavy",True,"1",True),
            ]),
            ("HTTP OPTIONS",[
                ("-U","User-Agent string (auto from sidebar)",True,"Mozilla/5.0",False),
                ("-H","Custom HTTP header (auto from sidebar)",True,"X-Custom: value",False),
                ("--follow-redirect","Follow redirects (never/http-only/always)",True,"always",False),
                ("--max-redirects","Max redirects",True,"10",False),
            ]),
            ("AUTHENTICATION",[
                ("-u","HTTP basic auth user:password",True,"user:pass",False),
                ("-c","Cookies string",True,"name=value; name2=value2",False),
                ("--cookie-jar","Cookie file",True,"/tmp/cookies.txt",False),
                ("--no-cookies","Disable cookie handling",False,"",False),
            ]),
            ("PROXY",[
                ("--proxy","Proxy hostname:port",True,"127.0.0.1:8080",False),
                ("--proxy-user","Proxy user:password",True,"user:pass",False),
            ]),
            ("PLUGINS",[
                ("-p","Select plugins (comma-separated)",True,"",False),
                ("-g","Grep for string/regex in results",True,"admin",False),
                ("--custom-plugin","Define custom plugin",True,":text=>'powered by abc'",False),
                ("-l","List all plugins",False,"",False),
            ]),
            ("OUTPUT",[
                ("-v","Verbose (plugin descriptions)",False,"",False),
                ("-q","Quiet — no brief logging",False,"",False),
                ("--no-errors","Suppress error messages",False,"",False),
                ("--log-brief","Log brief output to file",True,"/tmp/whatweb_brief.txt",False),
                ("--log-json","Log JSON output to file",True,"/tmp/whatweb.json",False),
                ("--log-xml","Log XML output to file",True,"/tmp/whatweb.xml",False),
                ("--colour","Color output (never/always/auto)",True,"always",False),
            ]),
            ("PERFORMANCE",[
                ("-t","Threads",True,"25",False),
                ("--open-timeout","Open timeout (s)",True,"15",False),
                ("--read-timeout","Read timeout (s)",True,"30",False),
                ("--wait","Wait between connections (s)",True,"0",False),
            ]),
        ]
        for sname,flags in sections:
            self._ol.addWidget(self._sec(sname))
            for entry in flags:
                flag,h,hv,ph,defon=entry
                cb,le=self._add_flag(self._ol,flag,h,hv,ph,defon,"",flag in ["--log-brief","--log-json","--log-xml","--cookie-jar"])
                if flag=="-U" and self._ua and le:
                    le.setText(f'"{self._ua}"'); cb.setChecked(True); le.setEnabled(True)
                if flag=="-H" and self._hdr and le:
                    le.setText(f'"{self._hdr}"'); cb.setChecked(True); le.setEnabled(True)
        self._ol.addStretch()

    def _build_cmd(self):
        p=["whatweb"]
        for cb,le,f in self._flag_widgets:
            if cb.isChecked():
                p.append(f)
                if le and le.text().strip():
                    v=le.text().strip()
                    # Quote UA and header values
                    if f in ["-U","-H"] and not v.startswith('"'):
                        v=f'"{v}"'
                    p.append(v)
        p.append(self._get_tgt()); return " ".join(p)

    def _on_out(self, line):
        safe=_html.escape(line)
        low=line.lower()
        if "[200]" in line or "[ok]" in low: color=D["green"]
        elif any(f"[{c}]" in line for c in ["301","302","307","308"]): color="#79c0ff"
        elif any(f"[{c}]" in line for c in ["403","404","410"]): color=D["red"]
        elif any(f"[{c}]" in line for c in ["500","502","503"]): color=D["orange"]
        elif "wordpress" in low or "php" in low or "apache" in low or "nginx" in low: color=D["acc"]
        elif not line.strip(): self._out.insertHtml("<br>"); return
        else: color=D["text2"]
        self._out.insertHtml(f"<span style='color:{color}'>{safe}</span><br>")



# ─── Ffuf Dialog ──────────────────────────────────────────────────────────────
class FfufDialog(BaseToolDialog):
    TOOL_NAME="ffuf"; ICON="🔀"; SUBTITLE="Fuzz Faster U Fool — Web Fuzzer"
    def __init__(self,host,dns,rate=0,ua="",hdr="",parent=None):
        self._r=rate; self._ua=ua; self._hdr=hdr; super().__init__(host,dns,parent)

    def _build_flags(self):
        self._ins_tgt(self._tgt_frame(["https://","http://"]))
        sections=[
            ("HTTP OPTIONS",[
                ("-u",          "Target URL (use FUZZ keyword)",                    True, "https://example.com/FUZZ", True),
                ("-H",          "Header 'Name: Value' (auto-filled)",               True, "X-Custom: val",            False),
                ("-X",          "HTTP method",                                       True, "GET",                      False),
                ("-b",          "Cookie data 'NAME1=VAL1; NAME2=VAL2'",             True, "session=abc123",           False),
                ("-d",          "POST data",                                         True, '{"key":"FUZZ"}',           False),
                ("-x",          "Proxy URL (http or socks5)",                        True, "http://127.0.0.1:8080",   False),
                ("-replay-proxy","Replay matched requests via proxy",                True, "http://127.0.0.1:8080",   False),
                ("-r",          "Follow redirects",                                  False,"",                         False),
                ("-recursion",  "Scan recursively (URL must end in FUZZ)",           False,"",                         False),
                ("-recursion-depth","Maximum recursion depth",                       True, "2",                        False),
                ("-recursion-strategy","Recursion strategy (default/greedy)",        True, "default",                  False),
                ("-timeout",    "HTTP request timeout in seconds",                   True, "10",                       False),
                ("-http2",      "Use HTTP2 protocol",                                False,"",                         False),
                ("-ignore-body","Do not fetch response content",                     False,"",                         False),
                ("-raw",        "Do not encode URI",                                 False,"",                         False),
                ("-sni",        "Target TLS SNI (no FUZZ keyword support)",          True, "example.com",              False),
                ("-cc",         "Client certificate file (PEM)",                     True, "/path/cert.pem",           True),
                ("-ck",         "Client key file (PEM)",                             True, "/path/key.pem",            True),
            ]),
            ("INPUT OPTIONS",[
                ("-w",          "Wordlist:KEYWORD (eg. /path/wordlist:FUZZ)",        True, "/usr/share/wordlists/dirb/common.txt", True),
                ("-e",          "Comma-separated list of extensions",                True, "php,html,js",              False),
                ("-D",          "DirSearch wordlist compatibility mode (use with -e)",False,"",                        False),
                ("-mode",       "Multi-wordlist mode (clusterbomb/pitchfork/sniper)",True, "clusterbomb",              False),
                ("-enc",        "Encoders for keywords (eg. FUZZ:urlencode)",        True, "FUZZ:urlencode",           False),
                ("-ic",         "Ignore wordlist comments",                           False,"",                         False),
                ("-input-cmd",  "Command producing input (requires -input-num)",     True, "seq 1 100",                False),
                ("-input-num",  "Number of inputs (used with -input-cmd)",           True, "100",                      False),
                ("-input-shell","Shell for running input command",                   True, "/bin/bash",                False),
                ("-request",    "File containing raw HTTP request",                  True, "/path/request.txt",        True),
                ("-request-proto","Protocol for raw request (http/https)",           True, "https",                    False),
            ]),
            ("MATCHER OPTIONS",[
                ("-mc",         "Match HTTP status codes (default: 200-299,301,302,307,401,403,405,500)", True, "200", True),
                ("-ms",         "Match HTTP response size",                          True, "1234",                     False),
                ("-ml",         "Match amount of lines in response",                 True, "10",                       False),
                ("-mw",         "Match amount of words in response",                 True, "5",                        False),
                ("-mr",         "Match regexp",                                      True, "admin",                    False),
                ("-mt",         "Match response time (eg. >100 or <100 ms)",        True, ">100",                     False),
                ("-mmode",      "Matcher set operator (and/or)",                     True, "or",                       False),
            ]),
            ("FILTER OPTIONS",[
                ("-fc",         "Filter HTTP status codes (comma-separated)",        True, "404,500",                  False),
                ("-fs",         "Filter response size (comma-separated)",            True, "0",                        False),
                ("-fl",         "Filter by line count (comma-separated)",            True, "1",                        False),
                ("-fw",         "Filter by word count (comma-separated)",            True, "1",                        False),
                ("-fr",         "Filter regexp",                                     True, "error",                    False),
                ("-ft",         "Filter response time (eg. >100 or <100 ms)",       True, ">5000",                    False),
                ("-fmode",      "Filter set operator (and/or)",                      True, "or",                       False),
            ]),
            ("GENERAL OPTIONS",[
                ("-t",          "Number of concurrent threads",                      True, "40",                       False),
                ("-rate",       "Rate of requests per second (0=unlimited)",         True, "0",                        False),
                ("-p",          "Delay between requests (eg. 0.1 or 0.1-2.0)",      True, "0.1",                      False),
                ("-maxtime",    "Maximum running time in seconds (0=unlimited)",     True, "0",                        False),
                ("-maxtime-job","Maximum running time per job in seconds",           True, "0",                        False),
                ("-ac",         "Automatically calibrate filtering options",         False,"",                         False),
                ("-acc",        "Custom auto-calibration string (implies -ac)",      True, "admin",                    False),
                ("-ach",        "Per-host autocalibration",                          False,"",                         False),
                ("-ack",        "Autocalibration keyword",                           True, "FUZZ",                     False),
                ("-acs",        "Custom auto-calibration strategies (implies -ac)",  True, "",                         False),
                ("-c",          "Colorize output",                                   False,"",                         True),   # alapból BE
                ("-v",          "Verbose output (full URL + redirect location)",     False,"",                         False),
                ("-s",          "Silent mode (no additional info)",                  False,"",                         False),
                ("-json",       "JSON output (newline-delimited)",                   False,"",                         False),
                ("-noninteractive","Disable interactive console",                    False,"",                         False),
                ("-sa",         "Stop on all error cases (implies -sf and -se)",     False,"",                         False),
                ("-se",         "Stop on spurious errors",                           False,"",                         False),
                ("-sf",         "Stop when >95% responses return 403",               False,"",                         False),
                ("-config",     "Load configuration from file",                      True, "/path/ffuf.conf",          True),
                ("-scraperfile","Custom scraper file path",                          True, "/path/scraper.json",       True),
                ("-scrapers",   "Active scraper groups",                             True, "all",                      False),
                ("-search",     "Search for FFUFHASH payload from history",         True, "",                         False),
            ]),
            ("OUTPUT OPTIONS",[
                ("-o",          "Write output to file",                              True, "/tmp/ffuf.json",           True),
                ("-of",         "Output format (json/ejson/html/md/csv/ecsv/all)",  True, "json",                     False),
                ("-od",         "Directory to store matched results",                True, "/tmp/ffuf_results/",       True),
                ("-or",         "Don't create output file if no results",            False,"",                         False),
                ("-debug-log",  "Write internal logging to file",                    True, "/tmp/ffuf_debug.log",      True),
                ("-audit-log",  "Write audit log (all requests/responses/config)",   True, "/tmp/ffuf_audit.log",      True),
            ]),
        ]
        for sec, flags in sections:
            self._ol.addWidget(self._sec(sec))
            for flag,h,hv,ph,defon in flags:
                # OUTPUT opciók mind kikapcsolt alapból (fájl nem kell, konzol elég)
                actual_defon = defon if flag not in ("-o","-of","-od","-or","-debug-log","-audit-log","-cc","-ck","-request","-config","-scraperfile") else False
                cb,le=self._add_flag(self._ol,flag,h,hv,ph,actual_defon,"",ph if flag in ("-cc","-ck","-w","-request","-config","-scraperfile","-o","-od","-debug-log","-audit-log") else False)
                if flag=="-H" and (self._hdr or self._ua) and le:
                    parts=[]
                    if self._hdr: parts.append(f'"{self._hdr}"')
                    if self._ua:  parts.append(f'"User-Agent: {self._ua}"')
                    le.setText(" -H ".join(parts)); cb.setChecked(True); le.setEnabled(True)
                if flag=="-rate" and self._r>0 and le:
                    le.setText(str(self._r)); cb.setChecked(True); le.setEnabled(True)
        self._ol.addStretch()

    def _build_cmd(self):
        p=["ffuf"]
        tgt=self._get_tgt()
        p+=["-u", tgt if "FUZZ" in tgt else tgt+"/FUZZ"]
        for cb,le,f in self._flag_widgets:
            if cb.isChecked() and f!="-u":
                p.append(f)
                if le and le.text().strip(): p.append(le.text().strip())
        return " ".join(p)

    def _run(self):
        """Override: FfufCmdWorker-t használ a batch/throttled output miatt."""
        if self._rbtn.text().startswith("⏹"):
            if hasattr(self,'_worker') and self._worker: self._worker.stop()
            self._rbtn.setText(T("btn.start")); self._rbtn.setStyleSheet(BRUN); return
        cmd=self._cedit.text().strip() or self._build_cmd()
        self._out.clear()
        self._out.insertHtml(f"<span style='color:{D['muted']}'>$ {_html.escape(cmd)}</span><br><br>")
        # Progress label (terminál-szerű: csak az utolsó progress sort mutatja)
        if not hasattr(self, '_prog_label'):
            self._prog_label = QLabel("")
            self._prog_label.setStyleSheet(f"color:{D['muted']};font-size:11px;font-family:monospace;padding:2px 4px;")
            self._root.insertWidget(self._root.count()-1, self._prog_label)
        self._prog_label.setText("")
        self._rbtn.setText(T("btn.stop")); self._rbtn.setStyleSheet(BSTOP)
        try: parts=shlex.split(cmd)
        except: parts=cmd.split()
        self._worker=FfufCmdWorker(parts)
        self._worker.batch_output.connect(self._on_batch_out)
        self._worker.finished.connect(self._on_done)
        self._worker.start()

    def _on_batch_out(self, lines):
        """Batch output handler ffuf-hoz.
        - Progress sorok (\x1b[2K vagy :: Progress:) → csak az utolsót tartja meg,
          és egy dedikált progress label-ben mutatja (nem a fő outputban).
        - Hit sorok (Status:) → a fő outputban megjelennek.
        - Egyéb (fejléc, info) → normálisan megjelenik.
        """
        last_progress = None
        html_parts = []

        for line in lines:
            # ANSI escape szekvenciák eltávolítása a vizsgálathoz
            clean = _re_ansi.sub(r'\x1b\[[0-9;]*m', '', line)
            clean = clean.replace('\r', '').replace('\x1b[2K', '').strip()

            # Progress sor: :: Progress: [...] formátum
            if clean.startswith(':: Progress:') or '\x1b[2K' in line or line.startswith('\r'):
                last_progress = clean if clean.startswith('::') else (last_progress or clean)
                continue

            # Üres sor
            if not clean:
                html_parts.append("<br>"); continue

            # ANSI konverzió ha van benne szín
            raw_stripped = _re_ansi.sub(r'\x1b\[[0-9;]*m', '', line)
            if raw_stripped != line:
                html_parts.append(ansi_to_html(line) + "<br>")
                continue

            # Szín-kódolás ANSI nélkül
            safe = _html.escape(clean)
            if re.search(r'\b(200|201|204)\b', clean): color = D['green']
            elif re.search(r'\b(301|302|303|307|308)\b', clean): color = "#79c0ff"
            elif re.search(r'\b(401|403)\b', clean): color = D['orange']
            elif re.search(r'\b(404)\b', clean): color = D['red']
            elif re.search(r'\b(500|502|503)\b', clean): color = "#ff6b6b"
            elif clean.startswith('::') or '[INFO]' in clean: color = D['muted']
            elif '[Warning]' in clean or '[WARN]' in clean: color = D['orange']
            elif '[ERR]' in clean or '[ERROR]' in clean: color = D['red']
            else: color = D['text2']
            html_parts.append(f"<span style='color:{color}'>{safe}</span><br>")

        # Progress label frissítése (az utolsó progress sort mutatja)
        if last_progress and hasattr(self, '_prog_label'):
            self._prog_label.setText(last_progress)

        if html_parts:
            self._out.insertHtml("".join(html_parts))


# ─── Katana Dialog ────────────────────────────────────────────────────────────
class KatanaDialog(BaseToolDialog):
    TOOL_NAME="katana"; ICON="⚔"; SUBTITLE="Fast crawler — ProjectDiscovery"
    def __init__(self,host,dns,rate=0,ua="",hdr="",parent=None):
        self._r=rate; self._ua=ua; self._hdr=hdr; super().__init__(host,dns,parent)

    def _build_flags(self):
        self._ins_tgt(self._tgt_frame(["https://","http://"]))
        sections=[
            ("INPUT",[
                ("-u",          "Target URL / list to crawl",                        True, "https://example.com",      False),
                ("-resume",     "Resume scan using resume.cfg",                      True, "resume.cfg",               True),
                ("-e",          "Exclude host filter (cdn, private-ips, cidr, ip, regex)", True, "cdn,private-ips",   False),
            ]),
            ("CONFIGURATION",[
                ("-d",          "Maximum depth to crawl",                            True, "3",                        False),
                ("-jc",         "Enable endpoint parsing/crawling in JS files",      False,"",                         False),
                ("-jsl",        "Enable jsluice parsing in JS files (memory intensive)",False,"",                      False),
                ("-ct",         "Maximum crawl duration (s/m/h/d, eg. 30s, 5m)",    True, "5m",                       False),
                ("-kf",         "Crawl known files (all/robotstxt/sitemapxml)",      True, "all",                      False),
                ("-mrs",        "Maximum response size to read (bytes)",             True, "4194304",                  False),
                ("-timeout",    "Request timeout in seconds",                        True, "10",                       False),
                ("-aff",        "Enable automatic form filling (experimental)",      False,"",                         False),
                ("-fx",         "Extract form/input/textarea/select in jsonl",       False,"",                         False),
                ("-retry",      "Number of retries",                                 True, "1",                        False),
                ("-proxy",      "HTTP/SOCKS5 proxy",                                 True, "http://127.0.0.1:8080",   False),
                ("-td",         "Enable technology detection",                       False,"",                         False),
                ("-H",          "Custom header (auto-filled)",                       True, "X-Custom: val",            False),
                ("-config",     "Path to katana configuration file",                 True, "/path/katana.yaml",        True),
                ("-fc",         "Path to custom form configuration file",            True, "/path/form.yaml",          True),
                ("-flc",        "Path to custom field configuration file",           True, "/path/field.yaml",         True),
                ("-s",          "Visit strategy (depth-first/breadth-first)",        True, "depth-first",              False),
                ("-iqp",        "Ignore same path with different query-param values",False,"",                         False),
                ("-fsu",        "Filter similar looking URLs",                       False,"",                         False),
                ("-fst",        "Distinct values before path treated as parameter",  True, "10",                       False),
                ("-tlsi",       "Enable experimental TLS JA3 randomization",         False,"",                         False),
                ("-dr",         "Disable following redirects",                       False,"",                         False),
                ("-pc",         "Enable path climb (auto crawl parent paths)",       False,"",                         False),
                ("-kb",         "Enable knowledge base classification",              False,"",                         False),
                ("-mdp",        "Maximum pages to crawl per domain (0=unlimited)",   True, "0",                        False),
            ]),
            ("HEADLESS",[
                ("-hl",         "Enable headless crawling (experimental)",           False,"",                         False),
                ("-hh",         "Enable headless hybrid crawling (experimental)",    False,"",                         False),
                ("-sc",         "Use local Chrome instead of katana's Chrome",       False,"",                         False),
                ("-sb",         "Show browser on screen with headless mode",         False,"",                         False),
                ("-ho",         "Additional headless Chrome options",                True, "--disable-gpu",            False),
                ("-nos",        "Start Chrome in --no-sandbox mode",                 False,"",                         False),
                ("-cdd",        "Path to store Chrome browser data",                 True, "/tmp/katana_chrome/",      True),
                ("-scp",        "Path to Chrome browser for headless crawling",      True, "/usr/bin/chromium",        True),
                ("-noi",        "Start Chrome without incognito mode",               False,"",                         False),
                ("-cwu",        "Chrome debugger WebSocket URL",                     True, "ws://127.0.0.1:9222",      False),
                ("-xhr",        "Extract XHR request url/method in jsonl",           False,"",                         False),
                ("-mfc",        "Max consecutive action failures before stopping",   True, "10",                       False),
                ("-ed",         "Enable diagnostics",                                False,"",                         False),
                ("-pls",        "Page load strategy (heuristic/load/domcontentloaded/networkidle/none)", True, "heuristic", False),
                ("-dwt",        "Wait seconds after page load (domcontentloaded)",   True, "5",                        False),
                ("-csp",        "Captcha solver provider (eg. capsolver)",           True, "capsolver",                False),
                ("-csk",        "Captcha solver provider API key",                   True, "",                         False),
                ("-al",         "Auto-login username:password (headless only)",      True, "user:pass",                False),
            ]),
            ("SCOPE",[
                ("-cs",         "In-scope URL regex",                                True, "example\\.com",            False),
                ("-cos",        "Out-of-scope URL regex",                            True, "logout|admin",             False),
                ("-fs",         "Scope field (dn/rdn/fqdn/custom regex)",            True, "rdn",                      False),
                ("-ns",         "Disable host-based default scope",                  False,"",                         False),
                ("-do",         "Display external endpoints from scoped crawling",   False,"",                         False),
            ]),
            ("FILTER",[
                ("-mr",         "Regex to match on output URL",                      True, r"\.php$",                  False),
                ("-fr",         "Regex to filter on output URL",                     True, r"\.(png|jpg|css)$",        False),
                ("-f",          "Field to display (url/path/fqdn/qurl/file/key/kv...)", True, "url",                   False),
                ("-sf",         "Field to store per-host (url/path/fqdn/qurl...)",   True, "url",                      False),
                ("-em",         "Match output for given extension (eg. php,html,js)",True, "php,html,js",              False),
                ("-ef",         "Filter output for given extension (eg. png,css)",   True, "png,css,jpg",              False),
                ("-ndef",       "Remove default extensions from filter list",        False,"",                         False),
                ("-mdc",        "Match response with DSL condition",                 True, "status_code == 200",       False),
                ("-fdc",        "Filter response with DSL condition",                True, "status_code == 404",       False),
                ("-duf",        "Disable duplicate content filtering",               False,"",                         False),
                ("-fpt",        "Filter response by page type (error/captcha/parked)",True,"error,parked",             False),
            ]),
            ("RATE-LIMIT",[
                ("-c",          "Number of concurrent fetchers",                     True, "10",                       False),
                ("-p",          "Number of concurrent inputs",                       True, "10",                       False),
                ("-rd",         "Request delay between each request (seconds)",      True, "0",                        False),
                ("-rl",         "Maximum requests per second",                       True, "150",                      False),
                ("-rlm",        "Maximum requests per minute",                       True, "0",                        False),
                ("-hrl",        "Maximum requests per second per host",              True, "0",                        False),
                ("-hrlm",       "Maximum requests per minute per host",              True, "0",                        False),
            ]),
            ("OUTPUT",[
                ("-o",          "Output file",                                       True, "/tmp/katana.txt",          True),
                ("-ot",         "Custom output template",                            True, "{{.RequestURL}}",          False),
                ("-sr",         "Store HTTP requests/responses",                     False,"",                         False),
                ("-srd",        "Directory to store requests/responses",             True, "/tmp/katana_resp/",        True),
                ("-ncb",        "Do not overwrite output file",                      False,"",                         False),
                ("-sfd",        "Store per-host field to custom directory",          True, "/tmp/katana_fields/",      True),
                ("-or",         "Omit raw requests/responses from jsonl",            False,"",                         False),
                ("-ob",         "Omit response body from jsonl",                     False,"",                         False),
                ("-j",          "Write output in jsonl format",                      False,"",                         False),
                ("-nc",         "Disable output coloring (ANSI)",                    False,"",                         False),
                ("-silent",     "Display output only (silent mode)",                 False,"",                         False),
                ("-v",          "Display verbose output",                            False,"",                         False),
                ("-debug",      "Display debug output",                              False,"",                         False),
                ("-elog",       "Write error log to file",                            True, "/tmp/katana_err.log",      True),
            ]),
        ]
        for sec, flags in sections:
            self._ol.addWidget(self._sec(sec))
            for flag,h,hv,ph,browse in flags:
                cb,le=self._add_flag(self._ol,flag,h,hv,ph,False,"",browse)
                if flag=="-H" and (self._hdr or self._ua) and le:
                    parts=[]
                    if self._hdr: parts.append(f'"{self._hdr}"')
                    if self._ua:  parts.append(f'"User-Agent: {self._ua}"')
                    le.setText(" -H ".join(parts)); cb.setChecked(True); le.setEnabled(True)
                if flag=="-rl" and self._r>0 and le:
                    le.setText(str(self._r)); cb.setChecked(True); le.setEnabled(True)
        self._ol.addStretch()

    def _build_cmd(self):
        p=["katana","-u",self._get_tgt()]
        for cb,le,f in self._flag_widgets:
            if cb.isChecked() and f!="-u":
                p.append(f)
                if le and le.text().strip(): p.append(le.text().strip())
        return " ".join(p)


class ToolCheckerDialog(QDialog):
    TOOLS=[("subfinder","Subdomain","go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
           ("httpx","HTTP probe","go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
           ("dnsx","DNS probe","go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
           ("naabu","Port scan","go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
           ("nuclei","Vuln scan","go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
           ("katana","Crawler","go install github.com/projectdiscovery/katana/cmd/katana@latest"),
           ("ffuf","Web fuzzer","go install github.com/ffuf/ffuf/v2@latest"),
           ("nmap","Port scan","sudo pacman -S nmap"),("curl","HTTP tool","sudo pacman -S curl"),
           ("wget","Downloader","sudo pacman -S wget"),("whatweb","Web scanner","sudo pacman -S whatweb  # or: gem install whatweb"),
           ("wpscan","WP scanner","gem install wpscan  # requires Ruby"),("dig","DNS lookup","sudo pacman -S bind"),("sudo","Root",T("dep.system"))]
    def __init__(self,parent=None):
        super().__init__(parent); self.setWindowTitle(T("dep.title")); self.setMinimumWidth(560); self.setStyleSheet(SS)
        lay=QVBoxLayout(self); lay.setContentsMargins(20,18,20,16); lay.setSpacing(6)
        lay.addWidget(QLabel(T("dep.header")))
        self._rows={}
        for tool,desc,inst in self.TOOLS:
            row=QHBoxLayout(); st=QLabel("⏳"); st.setFixedWidth(22); nm=QLabel(f"<b>{tool}</b>"); nm.setFixedWidth(90)
            ds=QLabel(desc); ds.setStyleSheet(f"color:{D['muted']};font-size:12px;")
            pt=QLabel(""); pt.setFixedWidth(200); pt.setAlignment(Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter)
            row.addWidget(st); row.addWidget(nm); row.addWidget(ds); row.addStretch(); row.addWidget(pt)
            lay.addLayout(row); self._rows[tool]=(st,pt,inst)
        div=QFrame(); div.setFrameShape(QFrame.Shape.HLine); div.setStyleSheet(f"background:{D['border']};max-height:1px;"); lay.addWidget(div)
        self._hint=QLabel(""); self._hint.setWordWrap(True); self._hint.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._hint.setStyleSheet(f"background:{D['surf2']};color:{D['orange']};border:1px solid {D['border']};border-radius:5px;padding:8px;font-size:11px;"); self._hint.setVisible(False); lay.addWidget(self._hint)
        bl=QHBoxLayout(); self._cont=QPushButton(T("btn.continue")); self._cont.setStyleSheet(BRUN); self._cont.clicked.connect(self.accept)
        q=QPushButton(T("btn.quit")); q.setStyleSheet(BMUT); q.clicked.connect(self.reject)
        bl.addStretch(); bl.addWidget(q); bl.addWidget(self._cont); lay.addLayout(bl); self._check()
    def _check(self):
        missing=[]
        for tool,_,inst in self.TOOLS:
            st,pt,i=self._rows[tool]; r=subprocess.run(["which",tool],capture_output=True,text=True)
            if r.returncode==0: st.setText("✅"); pt.setText(r.stdout.strip()); pt.setStyleSheet(f"color:{D['green']};font-size:11px;")
            else: st.setText("❌"); pt.setText("Nincs"); pt.setStyleSheet(f"color:{D['red']};font-size:11px;"); missing.append((tool,inst)) if tool!="sudo" else None
        if missing: self._hint.setText(T("dep.missing",cmds="\n".join(f"  $ {c}" for _,c in missing))); self._hint.setVisible(True); self._cont.setText(T("btn.continue_warn"))
        else: self._cont.setText(T("btn.all_ready"))

# ─── MainWindow ───────────────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("InScop3 Recon — Comprehensive Reconnaissance Tool")
        self.setMinimumSize(1100,700); self.resize(1440,860); self._worker=None; self._n=0; self._build()

    def _build(self):
        c=QWidget(); self.setCentralWidget(c); root=QVBoxLayout(c); root.setContentsMargins(0,0,0,0); root.setSpacing(0)
        # Topbar
        tb=QFrame(); tb.setStyleSheet(f"background:{D['surf']};border-bottom:1px solid {D['border']};"); tb.setFixedHeight(60)
        tbl=QHBoxLayout(tb); tbl.setContentsMargins(18,0,18,0); tbl.setSpacing(14)
        # Banner: "InScop3" (white) + "Recon" (blue)
        banner_text=f"<b><span style='color:white;'>InScop3</span> <span style='color:{D['acc']};'>Recon</span></b>"
        tbl.addWidget(QLabel(banner_text).setParent(None) or self._mklab(banner_text,f"font-size:20px;font-weight:bold;letter-spacing:2px;"))
        tbl.addStretch()
        # Jegyzet gomb — badge bal oldalán
        self._notes_btn = QPushButton(T("btn.note"))
        self._notes_btn.setStyleSheet(
            f"QPushButton{{background:transparent;color:{D['acc']};"
            f"border:1px solid {D['acc']};border-radius:10px;"
            f"padding:3px 12px;font-size:12px;font-weight:bold;}}"
            f"QPushButton:hover{{background:{D['acc']};color:#fff;}}"
        )
        self._notes_btn.setFixedHeight(28)
        self._notes_btn.clicked.connect(self._open_notes)
        tbl.addWidget(self._notes_btn)
        self._badge=self._mklab(T("scan.0hosts"),f"color:{D['acc']};border:1px solid {D['acc']};border-radius:12px;padding:3px 12px;font-size:12px;font-weight:bold;background:transparent;")
        tbl.addWidget(self._badge); root.addWidget(tb)
        # Splitter
        spl=QSplitter(Qt.Orientation.Vertical); spl.setHandleWidth(7)
        spl.setStyleSheet(f"QSplitter::handle:vertical{{background:{D['border']};}}QSplitter::handle:vertical:hover{{background:{D['acc']};}}")
        # Content
        cont=QWidget(); ch=QHBoxLayout(cont); ch.setContentsMargins(0,0,0,0); ch.setSpacing(0)
        # Sidebar
        sbs=QScrollArea(); sbs.setFixedWidth(292); sbs.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        sbs.setWidgetResizable(True); sbs.setFrameShape(QFrame.Shape.NoFrame)
        sbs.setStyleSheet(f"QScrollArea{{background:{D['surf']};border-right:1px solid {D['border']};}}")
        sbi=QWidget(); sbi.setAutoFillBackground(True)
        pal=sbi.palette(); pal.setColor(QPalette.ColorRole.Window,QColor(D['surf'])); sbi.setPalette(pal)
        sb=QVBoxLayout(sbi); sb.setContentsMargins(12,14,12,14); sb.setSpacing(3); sbs.setWidget(sbi)
        def sec(t): l=QLabel(t); l.setStyleSheet(f"color:{D['acc']};font-size:10px;font-weight:bold;letter-spacing:2px;background:transparent;"); l.setContentsMargins(0,8,0,3); l.setFixedHeight(28); return l
        def lbl(t): l=QLabel(t); l.setStyleSheet(f"color:{D['muted']};font-size:11px;background:transparent;"); l.setContentsMargins(2,0,0,1); l.setFixedHeight(18); return l
        def gap(h=6): w=QWidget(); w.setFixedHeight(h); w.setStyleSheet("background:transparent;"); return w
        def hdiv(): f=QFrame(); f.setFrameShape(QFrame.Shape.HLine); f.setFixedHeight(1); f.setStyleSheet(f"background:{D['border']};margin:6px 0;"); return f
        def inp(): le=QLineEdit(); le.setStyleSheet(INP); fp(le); return le
        def cmb(items): c2=NoScrollComboBox(); c2.addItems(items); c2.setStyleSheet(CMB); return c2
        # TARGET
        sb.addWidget(sec("TARGET")); sb.addWidget(lbl("Domain / URL"))
        dom_row=QHBoxLayout(); dom_row.setSpacing(4)
        self._domain=inp(); self._domain.setPlaceholderText("example.com"); self._domain.returnPressed.connect(self._start)
        dom_row.addWidget(self._domain)
        scope_btn=QPushButton()
        scope_btn.setFixedSize(34,34)
        scope_btn.setToolTip(T("main.scope_tip"))
        scope_btn.setStyleSheet(f"""
            QPushButton {{
                background:{D['surf2']}; border:1px solid {D['border']};
                border-radius:5px; padding:0;
            }}
            QPushButton:hover {{ background:{D['border']}; border-color:{D['muted']}; }}
            QPushButton:pressed {{ background:{D['surf']}; }}
        """)
        # Load SVG icon same as browse buttons
        from PyQt6.QtGui import QIcon as _QIcon
        from PyQt6.QtCore import QSize as _QSize
        _svg = os.path.join(os.path.dirname(os.path.abspath(__file__)), "folder-activities.svg")
        if not os.path.exists(_svg):
            for _d in [os.path.expanduser("~/.local/share/inscop3"), os.path.dirname(os.path.abspath(__file__))]:
                _c = os.path.join(_d, "folder-activities.svg")
                if os.path.exists(_c): _svg = _c; break
        if os.path.exists(_svg):
            scope_btn.setIcon(_QIcon(_svg)); scope_btn.setIconSize(_QSize(20,20))
        else:
            # Fallback: text icon, colored blue
            scope_btn.setText("📂")
        scope_btn.clicked.connect(self._import_scope)
        dom_row.addWidget(scope_btn); sb.addLayout(dom_row)
        sb.addWidget(gap()); sb.addWidget(lbl(T("main.rate_label")))
        self._rate=QSpinBox(); self._rate.setRange(0,10000); self._rate.setValue(5); self._rate.setStyleSheet(SPN)
        sp2=self._rate.palette(); sp2.setColor(QPalette.ColorRole.Text,QColor(D['text'])); sp2.setColor(QPalette.ColorRole.Base,QColor(D['surf2'])); self._rate.setPalette(sp2); sb.addWidget(self._rate)
        sb.addWidget(gap()); sb.addWidget(lbl(T("main.ua_label")))
        self._user_agent=inp(); self._user_agent.setPlaceholderText("Mozilla/5.0 ..."); sb.addWidget(self._user_agent)
        sb.addWidget(gap()); sb.addWidget(lbl(T("main.hdr_label")))
        self._req_header=inp(); self._req_header.setPlaceholderText("X-Intigriti-Username: user"); sb.addWidget(self._req_header)
        # Regisztrálás a globális singleton-ban, hogy parent=None ablakok is elérjék
        _AppSettings._rate = self._rate
        _AppSettings._user_agent = self._user_agent
        _AppSettings._req_header = self._req_header
        sb.addWidget(gap(10))
        self._rbtn=QPushButton(T("btn.scan_start")); self._rbtn.setStyleSheet(BRUN); self._rbtn.setFixedHeight(40); self._rbtn.clicked.connect(self._start); sb.addWidget(self._rbtn)
        sb.addWidget(gap(5))
        self._sbtn=QPushButton(T("btn.scan_stop")); self._sbtn.setStyleSheet(BSTOP); self._sbtn.setFixedHeight(36); self._sbtn.clicked.connect(self._stop); self._sbtn.setEnabled(False); sb.addWidget(self._sbtn)
        sb.addWidget(hdiv())
        # FILTERS
        sb.addWidget(sec(T("main.filters")))
        sb.addWidget(lbl(T("main.f_subdomain"))); self._f_sub=inp(); self._f_sub.setPlaceholderText(T("main.f_sub_ph")); self._f_sub.textChanged.connect(self._filter); sb.addWidget(self._f_sub)
        sb.addWidget(gap()); sb.addWidget(lbl("Title")); self._f_title=inp(); self._f_title.setPlaceholderText("pl. Homepage..."); self._f_title.textChanged.connect(self._filter); sb.addWidget(self._f_title)
        sb.addWidget(gap()); sb.addWidget(lbl(T("main.f_http")))
        self._f_http=cmb([
            T("main.f_all"),
            # 1xx Informational
            "100","101","102","103",
            # 2xx Success
            "200","201","202","203","204","206","207","208",
            # 3xx Redirect
            "301","302","303","304","307","308",
            # 4xx Client Error
            "400","401","402","403","404","405","406","407","408","409",
            "410","411","412","413","414","415","416","417","418",
            "421","422","423","424","425","426","428","429","431","451",
            # 5xx Server Error
            "500","501","502","503","504","505","506","507","508","510","511",
        ]); self._f_http.currentTextChanged.connect(self._filter); sb.addWidget(self._f_http)
        sb.addWidget(gap()); sb.addWidget(lbl(T("main.f_ws"))); self._f_ws=inp(); self._f_ws.setPlaceholderText("nginx, apache..."); self._f_ws.textChanged.connect(self._filter); sb.addWidget(self._f_ws)
        sb.addWidget(gap()); sb.addWidget(lbl(T("main.f_tech"))); self._f_tech=inp(); self._f_tech.setPlaceholderText(T("main.f_tech_ph")); self._f_tech.textChanged.connect(self._filter); sb.addWidget(self._f_tech)
        sb.addWidget(gap()); sb.addWidget(lbl(T("main.f_dns_type")))
        self._f_dt=cmb([T("main.f_all"),"A","CNAME"]); self._f_dt.currentTextChanged.connect(self._filter); sb.addWidget(self._f_dt)
        sb.addWidget(gap()); sb.addWidget(lbl(T("main.f_dns_val"))); self._f_dv=inp(); self._f_dv.setPlaceholderText(T("main.f_dns_val_ph")); self._f_dv.textChanged.connect(self._filter); sb.addWidget(self._f_dv)
        sb.addWidget(gap())
        self._f_take=QCheckBox(T("main.f_takeover")); self._f_take.setStyleSheet(f"color:{D['text2']};font-size:12px;background:transparent;"); self._f_take.toggled.connect(self._filter); sb.addWidget(self._f_take)
        sb.addWidget(gap(8)); clr=QPushButton(T("btn.clear_filters")); clr.setStyleSheet(BMUT); clr.setFixedHeight(32); clr.clicked.connect(self._clrf); sb.addWidget(clr)
        sb.addWidget(hdiv())
        # EXPORT / IMPORT
        sb.addWidget(sec("EXPORT / IMPORT"))
        exp=QPushButton(T("btn.session_save")); exp.setStyleSheet(BGRN); exp.setFixedHeight(34); exp.clicked.connect(self._export); sb.addWidget(exp)
        sb.addWidget(gap(5))
        imp_btn=QPushButton(T("btn.session_load")); imp_btn.setStyleSheet(BMUT); imp_btn.setFixedHeight(34); imp_btn.clicked.connect(self._import_data); sb.addWidget(imp_btn)
        sb.addWidget(gap(5)); clrt=QPushButton(T("btn.clear_table")); clrt.setStyleSheet(BMUT); clrt.setFixedHeight(34); clrt.clicked.connect(self._clrt); sb.addWidget(clrt)
        sb.addStretch()
        ch.addWidget(sbs)
        # Table
        ta=QWidget(); tal=QVBoxLayout(ta); tal.setContentsMargins(0,0,0,0); tal.setSpacing(0)
        self._prog=QProgressBar(); self._prog.setFixedHeight(3); self._prog.setRange(0,100); self._prog.setValue(0); self._prog.setTextVisible(False)
        self._prog.setStyleSheet(f"QProgressBar{{background:{D['surf2']};border:none;}}QProgressBar::chunk{{background:{D['acc']};}}"); tal.addWidget(self._prog)
        self._sl=QLabel(T("scan.status_ready")); self._sl.setStyleSheet(f"background:{D['surf']};color:{D['muted']};font-size:12px;padding:5px 12px;border-bottom:1px solid {D['border']};"); tal.addWidget(self._sl)
        self._table=ResultTable(); tal.addWidget(self._table); ch.addWidget(ta); spl.addWidget(cont)
        # Log
        lw=QWidget(); lw.setStyleSheet(f"background:{D['surf']};"); ll=QVBoxLayout(lw); ll.setContentsMargins(8,4,8,6); ll.setSpacing(3)
        lh=QHBoxLayout(); lh.addWidget(self._mklab("KONZOL LOG",f"color:{D['acc']};font-size:10px;font-weight:bold;letter-spacing:2px;background:transparent;")); lh.addStretch()
        lc=QPushButton(T("btn.clear_log")); lc.setStyleSheet(BMUT); lc.setFixedSize(60,22); lc.clicked.connect(lambda: self._lv.clear()); lh.addWidget(lc); ll.addLayout(lh)
        self._lv=QTextEdit(); self._lv.setReadOnly(True); ll.addWidget(self._lv); spl.addWidget(lw)
        spl.setCollapsible(0,False); spl.setCollapsible(1,False); cont.setMinimumHeight(200); lw.setMinimumHeight(60); spl.setSizes([680,150])
        root.addWidget(spl)
        sbar=QStatusBar(); self.setStatusBar(sbar); self._slbl=QLabel(T("scan.status_bar")); sbar.addWidget(self._slbl); self._sright=QLabel(""); sbar.addPermanentWidget(self._sright)

    def _mklab(self,t,ss=""):
        l=QLabel(t)
        if ss: l.setStyleSheet(ss)
        return l

    def _log(self,html):
        sb=self._lv.verticalScrollBar()
        at_bottom=sb.value()>=sb.maximum()-4
        self._lv.insertHtml(html+"<br>")
        if at_bottom: sb.setValue(sb.maximum())

    def _import_scope(self):
        """Open a scope file (bug bounty txt), parse it, show summary, then start batch scan."""
        path,_=QFileDialog.getOpenFileName(self,T("scope.open_title"),"",T("scope.open_filter"))
        if not path: return
        scope,err=parse_scope_file(path)
        if err: QMessageBox.critical(self,"Parse hiba",err); return
        if not scope: QMessageBox.warning(self,T("scope.empty_title"),T("scope.empty_msg")); return
        wildcard_count=sum(1 for s in scope if s["is_wildcard"])
        url_count=sum(1 for s in scope if not s["is_wildcard"])
        preview=[]
        for s in scope[:8]:
            icon="🌐" if s["is_wildcard"] else "🔗"
            preview.append(f"  {icon} {s['domain']}")
        if len(scope)>8: preview.append(T("scope.more",n=len(scope)-8))

        # Egyedi dialógus rate/ua/header beállításokkal
        dlg=ScopeConfirmDialog(
            scope=scope,
            wildcard_count=wildcard_count,
            url_count=url_count,
            preview=preview,
            default_rate=self._rate.value(),
            default_ua=self._user_agent.text().strip(),
            default_hdr=self._req_header.text().strip(),
            parent=self
        )
        if dlg.exec()!=QDialog.DialogCode.Accepted: return

        # Visszaírjuk a főképernyőre is
        self._rate.setValue(dlg.rate)
        self._user_agent.setText(dlg.ua)
        self._req_header.setText(dlg.hdr)

        sudo_dlg=SudoDialog(self)
        if sudo_dlg.exec()!=QDialog.DialogCode.Accepted: return
        self._start_batch(scope, sudo_dlg.password, dlg.rate, dlg.ua, dlg.hdr)

    def _start_batch(self, scope_list, sudo_pw, rate=None, ua=None, hdr=None):
        rate = rate if rate is not None else self._rate.value()
        ua   = ua   if ua   is not None else self._user_agent.text().strip()
        hdr  = hdr  if hdr  is not None else self._req_header.text().strip()
        self._sudo_pw=sudo_pw
        self._n=0; self._table.clear_all(); self._lv.clear(); self._prog.setValue(0)
        self._rbtn.setEnabled(False); self._sbtn.setEnabled(True); self._badge.setText(T("scan.0hosts"))
        ts=datetime.now().strftime("%Y%m%d_%H%M%S")
        wdir=tempfile.mkdtemp(prefix=f"wcrecon_batch_{ts}_")
        self._log(f"<span style='color:{D['acc']};font-weight:bold;'>═══ Batch Scan — {len(scope_list)} domain ═══</span>")
        self._log(f"<span style='color:{D['muted']}'>Rate: {rate} | Dir: {wdir}</span>")
        self._worker=BatchScanWorker(scope_list,rate,wdir,sudo_pw,ua,hdr)
        self._worker.log.connect(self._log)
        self._worker.progress.connect(lambda v,m:(self._prog.setValue(v),self._sl.setText(f"  ⚙  {m}")))
        self._worker.done_db.connect(self._on_db)
        self._worker.finished.connect(self._on_done)
        self._worker.start()

    def _start(self):
        domain=self._domain.text().strip()
        if not domain: QMessageBox.warning(self,T("warn.no_domain_title"),T("warn.no_domain_msg")); return
        domain=re.sub(r'^https?://','',domain).rstrip('/')
        dlg=SudoDialog(self)
        if dlg.exec()!=QDialog.DialogCode.Accepted: return
        rate=self._rate.value(); ua=self._user_agent.text().strip(); hdr=self._req_header.text().strip()
        self._sudo_pw = dlg.password
        _AppSettings._sudo_pw = self._sudo_pw
        self._n=0; self._table.clear_all(); self._lv.clear(); self._prog.setValue(0)
        self._rbtn.setEnabled(False); self._sbtn.setEnabled(True); self._badge.setText("0 host")
        ts=datetime.now().strftime('%Y%m%d_%H%M%S'); safe=re.sub(r'[^a-zA-Z0-9._-]','_',domain)
        wdir=tempfile.mkdtemp(prefix=f"wcrecon_{safe}_{ts}_")
        self._log(f"<span style='color:{D['acc']};font-weight:bold;'>═══ InScop3 Recon v3 — {domain} ═══</span>")
        self._log(f"<span style='color:{D['muted']}'>Rate: {rate} | Dir: {wdir}</span>")
        # Wildcard felismerés az egyes domain scan-nél is
        wc_regex = wc_pattern = None
        apex = domain
        if _is_wildcard_pattern(domain):
            apex, wc_regex = _wildcard_to_apex(domain)
            wc_pattern = domain
            if apex:
                self._log(f"<span style='color:#d29922'>⤷ Wildcard: {domain} → subfinder: {apex}</span>")
                domain = apex
        self._worker=ScanWorker(domain,rate,wdir,dlg.password,ua,hdr,
                                wildcard_regex=wc_regex,wildcard_pattern=wc_pattern)
        self._worker.log.connect(self._log)
        self._worker.progress.connect(lambda v,m: (self._prog.setValue(v),self._sl.setText(f"  ⚙  {m}")))
        self._worker.done_db.connect(self._on_db); self._worker.finished.connect(self._on_done); self._worker.start()

    def _open_notes(self):
        """Nyissa meg a főablakból a Jegyzet dialógust."""
        if not hasattr(self, "_notes_dialog") or self._notes_dialog is None:
            self._notes_dialog = NotesDialog()
            _OPEN_DIALOGS.append(self._notes_dialog)
        self._notes_dialog.show()
        self._notes_dialog.raise_()
        self._notes_dialog.activateWindow()

    def _stop(self):
        self._rbtn.setEnabled(True); self._sbtn.setEnabled(False)
        self._log(f"<span style='color:{D['orange']}'>{T('scan.stopped')}</span>")
    
    def _on_db(self, db):
        """Update table with database and refresh HTTP filter options"""
        self._table.load_db(db)
        self._n = len(db)
        self._badge.setText(T("scan.n_hosts",n=self._n))
        self._sright.setText(T("scan.n_sub",n=self._n))
        self._update_http_filter_options(db)

    def _update_http_filter_options(self, db):
        """Update HTTP filter combo box with only existing status codes"""
        # Extract all unique HTTP status codes from database
        codes = set()
        for rec in db.values():
            status = rec.get("status", "")
            found = re.findall(r"\d{3}", str(status))
            codes.update(found)
        
        # Sort codes numerically
        sorted_codes = sorted(list(codes), key=lambda x: int(x))
        
        # Preserve current selection
        old_selection = self._f_http.currentText()
        
        # Rebuild combo box
        self._f_http.currentTextChanged.disconnect(self._filter)
        self._f_http.clear()
        self._f_http.addItems([T("main.f_all")] + sorted_codes)
        self._f_http.currentTextChanged.connect(self._filter)
        
        # Restore selection if exists, otherwise select "Minden"
        idx = self._f_http.findText(old_selection)
        self._f_http.setCurrentIndex(idx if idx >= 0 else 0)

    def _on_done(self,ok,msg):
        self._rbtn.setEnabled(True); self._sbtn.setEnabled(False)
        c=D['green'] if ok else D['red']
        self._log(f"<span style='color:{c};font-weight:bold;'>{'✓' if ok else '✗'} {msg}</span>")
        self._sl.setText(f"  {'✓' if ok else '✗'}  {msg}"); self._filter()

    def _filter(self):
        h=self._f_http.currentText(); dt=self._f_dt.currentText()
        all_val=T("main.f_all")
        self._table.apply_filters({"subdomain":self._f_sub.text(),"title":self._f_title.text(),"http":"" if h==all_val else h,"ws":self._f_ws.text(),"tech":self._f_tech.text(),"dns_type":"" if dt==all_val else dt,"dns_value":self._f_dv.text(),"takeover":self._f_take.isChecked()})

    def _clrf(self):
        for w in [self._f_sub,self._f_title,self._f_ws,self._f_tech,self._f_dv]: w.clear()
        self._f_http.setCurrentIndex(0); self._f_dt.setCurrentIndex(0); self._f_take.setChecked(False)

    def _clrt(self): self._table.clear_all(); self._n=0; self._badge.setText(T("scan.0hosts"))

    def _export(self):
        path, _ = QFileDialog.getSaveFileName(
            self, T("file.pipe_save"),
            f"inscop3_{datetime.now().strftime('%Y%m%d_%H%M%S')}.inscop3",
            T("file.pipe_filter"))
        if not path: return
        # Aktív HTTP kódok összegyűjtése a comboboxból
        http_codes = [self._f_http.itemText(i)
                      for i in range(1, self._f_http.count())]  # 0 = "Minden"
        settings = {
            "rate":       self._rate.value(),
            "ua":         self._user_agent.text().strip(),
            "header":     self._req_header.text().strip(),
            "notes":      GlobalNotes().get_html() or GlobalNotes().get(),
            "http_codes": http_codes,
        }
        try:
            self._table.export_session(path, settings)
            self._log(f"<span style='color:{D['green']}'>{T('file.save_ok', path=path)}</span>")
        except Exception as e:
            self._log(f"<span style='color:{D['red']}'>✗ Mentési hiba: {e}</span>")

    def _import_data(self):
        path, _ = QFileDialog.getOpenFileName(
            self, T("file.pipe_open"), "",
            T("file.pipe_filter") + ";;Pipe-separated TXT (*.txt);;"+("Minden fájl (*)" if _LANG.lang=="hu" else "All files (*)"))
        if not path: return
        db, settings, notes, http_codes, err = self._table.import_session(path)
        if err:
            self._log(f"<span style='color:{D['red']}'>✗ Betöltési hiba: {err}</span>")
            return

        # ── Adatbázis ───────────────────────────────────────────────────────
        self._n = len(db)
        self._badge.setText(T("scan.n_hosts", n=self._n))
        self._sright.setText(T("scan.n_sub", n=self._n))

        # ── Beállítások visszaállítása ───────────────────────────────────────
        if settings.get("rate") is not None:
            self._rate.setValue(int(settings["rate"]))
        if settings.get("ua"):
            self._user_agent.setText(settings["ua"])
        if settings.get("header"):
            self._req_header.setText(settings["header"])

        # ── HTTP kód szűrő visszaállítása ────────────────────────────────────
        if http_codes:
            self._f_http.currentTextChanged.disconnect(self._filter)
            self._f_http.clear()
            self._f_http.addItems([T("main.f_all")] + http_codes)
            self._f_http.currentTextChanged.connect(self._filter)
        else:
            # Ha nincs elmentett lista, generáljuk az adatbázisból
            self._update_http_filter_options(db)

        # ── Jegyzetek visszaállítása ─────────────────────────────────────────
        if notes:
            # Ha HTML tartalmaz (< jellel kezdődik), html-ként töltjük be
            if notes.strip().startswith("<"):
                GlobalNotes().set_html(notes)
            else:
                GlobalNotes().set(notes)

        self._log(f"<span style='color:{D['green']}'>✓ Munkamenet betöltve: {self._n} host"
                  + (f", beállítások visszaállítva" if settings else "")
                  + (f", jegyzetek visszaállítva" if notes else "")
                  + "</span>")

# ─── Entry point ──────────────────────────────────────────────────────────────
# ─── Language Selection Dialog ────────────────────────────────────────────────
class LanguageDialog(QDialog):
    """Indulásnál megjelenő nyelv-választó."""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("InScop3 Recon")
        self.setFixedSize(400, 230)
        self.setStyleSheet(SS)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.MSWindowsFixedSizeDialogHint)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(32, 28, 32, 24)
        lay.setSpacing(18)

        # Logo / title
        logo = QLabel("<b><span style='color:white;font-size:22px;'>InScop3</span>"
                      f"<span style='color:{D['acc']};font-size:22px;'> Recon</span></b>")
        logo.setTextFormat(Qt.TextFormat.RichText)
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(logo)

        # Prompt
        prompt = QLabel("Select language / Válassz nyelvet")
        prompt.setAlignment(Qt.AlignmentFlag.AlignCenter)
        prompt.setStyleSheet(f"color:{D['muted']};font-size:12px;")
        lay.addWidget(prompt)

        # Language buttons — egyforma szélességű, stretch 1-1
        btn_lay = QHBoxLayout()
        btn_lay.setSpacing(14)

        self._lang = "hu"  # default

        hu_btn = QPushButton("🇭🇺  Magyar")
        hu_btn.setStyleSheet(BRUN)
        hu_btn.setFixedHeight(44)
        hu_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        hu_btn.clicked.connect(lambda: self._pick("hu"))
        btn_lay.addWidget(hu_btn, 1)

        en_btn = QPushButton("🇬🇧  English")
        en_btn.setStyleSheet(BMUT)
        en_btn.setFixedHeight(44)
        en_btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        en_btn.clicked.connect(lambda: self._pick("en"))
        btn_lay.addWidget(en_btn, 1)

        lay.addLayout(btn_lay)

    def _pick(self, lang: str):
        _LANG.set(lang)
        self._lang = lang
        self.accept()

    def chosen(self) -> str:
        return self._lang


def main():
    app=QApplication(sys.argv); app.setApplicationName("InScop3 Recon"); app.setStyle("Fusion")
    pal=QPalette()
    for role,col in [(QPalette.ColorRole.Window,D['bg']),(QPalette.ColorRole.WindowText,D['text']),(QPalette.ColorRole.Base,D['surf2']),(QPalette.ColorRole.AlternateBase,D['surf']),(QPalette.ColorRole.PlaceholderText,D['muted']),(QPalette.ColorRole.Text,D['text']),(QPalette.ColorRole.Button,D['surf2']),(QPalette.ColorRole.ButtonText,D['text']),(QPalette.ColorRole.Highlight,D['acc']),(QPalette.ColorRole.HighlightedText,QColor("#000"))]:
        pal.setColor(role,QColor(col))
    pal.setColor(QPalette.ColorGroup.Disabled,QPalette.ColorRole.Text,QColor(D['muted'])); pal.setColor(QPalette.ColorGroup.Disabled,QPalette.ColorRole.ButtonText,QColor(D['muted']))
    app.setPalette(pal); app.setStyleSheet(SS)
    for fn in ["JetBrains Mono","Fira Code","Cascadia Code","Hack"]:
        try:
            if fn in QFontDatabase.families(): app.setFont(QFont(fn,12)); break
        except: pass
    # 1. Language selection
    lang_dlg = LanguageDialog()
    if lang_dlg.exec() != QDialog.DialogCode.Accepted:
        sys.exit(0)
    # 2. Tool checker
    checker=ToolCheckerDialog()
    if checker.exec()!=QDialog.DialogCode.Accepted: sys.exit(0)
    # 3. Induláskor töröljük a notes.html-t — mindig üres a jegyzet
    _notes_html = os.path.join(os.path.expanduser("~/.local/share/inscop3"), "notes.html")
    try:
        if os.path.exists(_notes_html): os.remove(_notes_html)
    except Exception: pass
    # 4. Main window
    win=MainWindow(); win.show()
    ret = app.exec()
    # 5. Kilépéskor is töröljük — ne maradjon persistent tartalom
    try:
        if os.path.exists(_notes_html): os.remove(_notes_html)
    except Exception: pass
    sys.exit(ret)

if __name__=="__main__":
    main()
