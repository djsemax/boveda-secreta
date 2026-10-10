#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import uuid
import base64
import shutil
import datetime
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("Falta 'cryptography'. Instala: sudo apt install python3-cryptography")
    sys.exit(1)

import gi
gi.require_version("Gtk", "3.0")
gi.require_version("GdkPixbuf", "2.0")
from gi.repository import Gtk, GdkPixbuf, Gio, GLib, Gdk, GObject

# Intentar cargar Poppler para PDF
try:
    gi.require_version("Poppler", "0.18")
    from gi.repository import Poppler
    HAS_POPPLER = True
except (ValueError, ImportError):
    HAS_POPPLER = False

# Intentar cargar GStreamer para video
try:
    gi.require_version("Gst", "1.0")
    from gi.repository import Gst
    Gst.init(None)
    HAS_GST = True
except (ValueError, ImportError):
    HAS_GST = False


APP_VERSION = "0.4.0"
APP_CREATED_DATE = "2026-10-10"
APP_AUTHOR = "djsemax"
APP_WEBSITE = "https://github.com/djsemax"

xdg_data = os.environ.get("XDG_DATA_HOME", "").strip()
if not xdg_data:
    xdg_data = str(Path.home() / ".local" / "share")

xdg_config = os.environ.get("XDG_CONFIG_HOME", "").strip()
if not xdg_config:
    xdg_config = str(Path.home() / ".config")

DEFAULT_VAULT_DIR = Path(xdg_data) / ".cache-visores"
CONFIG_DIR = Path(xdg_config) / ".visor-notas"
SETTINGS_FILE = CONFIG_DIR / "settings.json"

DEFAULT_SETTINGS = {
    "app_name": "Visor de notas",
    "icon_name": "utilities-text-editor",
    "icon_path": "",
    "theme": "default",
    "blur_images": False,
    "allow_video_pdf": True,
    "biometric_unlock": False,
    "vault_dir": str(DEFAULT_VAULT_DIR),
    "view_mode": "icons",
    "sort_mode": "name",
    "filter_mode": "all",
    "fake_profile": False,
    "last_profile": "",
}

CONFIG = {}
CSS_PROVIDER = None
STATUS_ICON = None


def load_config():
    cfg = DEFAULT_SETTINGS.copy()
    try:
        if SETTINGS_FILE.exists():
            user_cfg = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            cfg.update(user_cfg)
    except Exception:
        pass
    for key, value in DEFAULT_SETTINGS.items():
        cfg.setdefault(key, value)
    return cfg


def save_config():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(CONFIG, indent=4), encoding="utf-8")
    try:
        os.chmod(CONFIG_DIR, 0o700)
        os.chmod(SETTINGS_FILE, 0o600)
    except OSError:
        pass


CONFIG = load_config()


def vault_dir():
    return Path(CONFIG.get("vault_dir", str(DEFAULT_VAULT_DIR))).expanduser()


def profiles_dir():
    return vault_dir() / "perfiles"


def profile_dir(profile_name):
    return profiles_dir() / profile_name


def current_profile_dir():
    return profile_dir(CONFIG.get("current_profile", ""))


def header_file():
    return current_profile_dir() / "index.sys"


def manifest_file():
    return current_profile_dir() / "cache.sys"


def files_dir():
    return current_profile_dir() / "items"


def ensure_dirs():
    profiles_dir().mkdir(parents=True, exist_ok=True)
    if CONFIG.get("current_profile"):
        current_profile_dir().mkdir(parents=True, exist_ok=True)
        files_dir().mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(current_profile_dir(), 0o700)
            os.chmod(files_dir(), 0o700)
        except OSError:
            pass


def write_secure(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


SALT_LEN = 16
NONCE_LEN = 12
ITERATIONS = 600000


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
    return kdf.derive(password.encode("utf-8"))


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def aes_decrypt(key: bytes, blob: bytes) -> bytes:
    if len(blob) < NONCE_LEN + 1:
        raise ValueError("Blob demasiado corto")
    nonce = blob[:NONCE_LEN]
    ciphertext = blob[NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def profile_exists(profile_name: str) -> bool:
    return (profile_dir(profile_name) / "index.sys").exists()


def list_profiles():
    if not profiles_dir().exists():
        return []
    return [d.name for d in profiles_dir().iterdir() if d.is_dir()]


def create_vault(profile_name: str, password: str) -> bytes:
    CONFIG["current_profile"] = profile_name
    ensure_dirs()
    master_key = os.urandom(32)
    salt = os.urandom(SALT_LEN)
    password_key = derive_key(password, salt)
    header_payload = json.dumps({"v": 1, "mk": base64.b64encode(master_key).decode("utf-8")}).encode("utf-8")
    write_secure(header_file(), salt + aes_encrypt(password_key, header_payload))
    write_secure(manifest_file(), aes_encrypt(master_key, json.dumps([]).encode("utf-8")))
    return master_key


def unlock_vault(profile_name: str, password: str):
    if not profile_exists(profile_name):
        return None, None
    hdr = profile_dir(profile_name) / "index.sys"
    raw = hdr.read_bytes()
    if len(raw) <= SALT_LEN:
        return None, None
    salt = raw[:SALT_LEN]
    password_key = derive_key(password, salt)
    try:
        payload = aes_decrypt(password_key, raw[SALT_LEN:])
        data = json.loads(payload.decode("utf-8"))
        master_key = base64.b64decode(data["mk"])
        entries = load_manifest(master_key)
        return master_key, entries
    except Exception:
        return None, None


def load_manifest(master_key: bytes):
    if not manifest_file().exists():
        return []
    try:
        raw = manifest_file().read_bytes()
        return json.loads(aes_decrypt(master_key, raw).decode("utf-8"))
    except Exception:
        return []


def save_manifest(master_key: bytes, entries):
    write_secure(manifest_file(), aes_encrypt(master_key, json.dumps(entries).encode("utf-8")))


def encrypt_file(master_key: bytes, data: bytes) -> bytes:
    return aes_encrypt(master_key, data)


def decrypt_file(master_key: bytes, entry_id: str) -> bytes:
    path = files_dir() / f"{entry_id}.bin"
    return aes_decrypt(master_key, path.read_bytes())


def change_password(master_key: bytes, new_password: str):
    ensure_dirs()
    salt = os.urandom(SALT_LEN)
    password_key = derive_key(new_password, salt)
    header_payload = json.dumps({"v": 1, "mk": base64.b64encode(master_key).decode("utf-8")}).encode("utf-8")
    write_secure(header_file(), salt + aes_encrypt(password_key, header_payload))


def destroy_profile(profile_name: str):
    d = profile_dir(profile_name)
    if d.exists():
        shutil.rmtree(d, ignore_errors=True)


def normalize_entry(entry):
    entry.setdefault("id", str(uuid.uuid4()))
    entry.setdefault("type", "file")
    entry.setdefault("parent", "/")
    entry.setdefault("name", "archivo")
    entry.setdefault("mime", "application/octet-stream")
    entry.setdefault("size", 0)
    entry.setdefault("added", datetime.datetime.now().isoformat())
    entry.setdefault("favorite", False)
    entry.setdefault("pinned", False)
    return entry


def apply_theme():
    global CSS_PROVIDER
    theme = CONFIG.get("theme", "default")
    settings = Gtk.Settings.get_default()
    screen = Gdk.Screen.get_default()
    if CSS_PROVIDER and screen:
        try:
            Gtk.StyleContext.remove_provider_for_screen(screen, CSS_PROVIDER)
        except Exception:
            pass
        CSS_PROVIDER = None
    if not settings:
        return
    css = ""
    if theme == "dark":
        settings.set_property("gtk-application-prefer-dark-theme", True)
    elif theme == "light":
        settings.set_property("gtk-application-prefer-dark-theme", False)
    elif theme == "gray":
        settings.set_property("gtk-application-prefer-dark-theme", True)
        css = "window, .background { background-color: #3a3a3a; color: #e8e8e8; } button, headerbar, menubar, menu, popover { background-color: #454545; color: #f0f0f0; }"
    elif theme == "mono":
        settings.set_property("gtk-application-prefer-dark-theme", True)
        css = "* { background-color: black; color: white; }"
    else:
        settings.set_property("gtk-application-prefer-dark-theme", False)
    if css and screen:
        CSS_PROVIDER = Gtk.CssProvider()
        CSS_PROVIDER.load_from_data(css.encode("utf-8"))
        Gtk.StyleContext.add_provider_for_screen(screen, CSS_PROVIDER, Gtk.STYLE_PROVIDER_PRIORITY_USER)


def generic_pixbuf(size=200):
    try:
        theme = Gtk.IconTheme.get_default()
        for icon_name in ["text-x-generic", "application-x-generic", "dialog-information", "image-missing"]:
            try:
                return theme.load_icon(icon_name, size, Gtk.IconLookupFlags.FORCE_SIZE)
            except Exception:
                pass
    except Exception:
        pass
    pix = GdkPixbuf.Pixbuf.new(GdkPixbuf.Colorspace.RGB, True, 8, size, size)
    pix.fill(0x202020FF)
    return pix


def folder_pixbuf(size=200):
    try:
        theme = Gtk.IconTheme.get_default()
        for icon_name in ["folder", "folder-symbolic", "folder-documents"]:
            try:
                return theme.load_icon(icon_name, size, Gtk.IconLookupFlags.FORCE_SIZE)
            except Exception:
                pass
    except Exception:
        pass
    return generic_pixbuf(size)


def video_pixbuf(size=200):
    try:
        theme = Gtk.IconTheme.get_default()
        for icon_name in ["video-x-generic", "video", "media-video"]:
            try:
                return theme.load_icon(icon_name, size, Gtk.IconLookupFlags.FORCE_SIZE)
            except Exception:
                pass
    except Exception:
        pass
    return generic_pixbuf(size)


def pdf_pixbuf(size=200):
    try:
        theme = Gtk.IconTheme.get_default()
        for icon_name in ["application-pdf", "x-office-document"]:
            try:
                return theme.load_icon(icon_name, size, Gtk.IconLookupFlags.FORCE_SIZE)
            except Exception:
                pass
    except Exception:
        pass
    return generic_pixbuf(size)


def blur_pixbuf(pixbuf, radius=10):
    if not pixbuf or radius <= 0:
        return pixbuf
    try:
        w = pixbuf.get_width()
        h = pixbuf.get_height()
        small_w = max(1, w // 8)
        small_h = max(1, h // 8)
        small = pixbuf.scale_simple(small_w, small_h, GdkPixbuf.InterpType.NEAREST)
        return small.scale_simple(w, h, GdkPixbuf.InterpType.NEAREST)
    except Exception:
        return pixbuf


def add_overlay_icon(pixbuf, icon_name, size=28, position="top-right"):
    try:
        theme = Gtk.IconTheme.get_default()
        overlay = theme.load_icon(icon_name, size, Gtk.IconLookupFlags.FORCE_SIZE)
        if overlay:
            result = pixbuf.copy()
            w = result.get_width()
            h = result.get_height()
            ow = overlay.get_width()
            oh = overlay.get_height()
            if position == "top-right":
                x = max(0, w - ow - 2)
                y = 2
            elif position == "top-left":
                x = 2
                y = 2
            else:
                x = 2
                y = 2
            overlay.composite(result, x, y, ow, oh, x, y, 1, 1, GdkPixbuf.InterpType.NEAREST, 255)
            return result
    except Exception:
        pass
    return pixbuf


def make_thumb(data: bytes, size=200, blur=False):
    try:
        gbytes = GLib.Bytes.new(data)
        stream = Gio.MemoryInputStream.new_from_bytes(gbytes)
        pixbuf = GdkPixbuf.Pixbuf.new_from_stream(stream, None)
        w = pixbuf.get_width()
        h = pixbuf.get_height()
        if max(w, h) <= 0:
            return generic_pixbuf(size)
        scale = min(1.0, size / float(max(w, h)))
        if scale < 1.0:
            pixbuf = pixbuf.scale_simple(max(1, int(w * scale)), max(1, int(h * scale)), GdkPixbuf.InterpType.BILINEAR)
        if blur:
            pixbuf = blur_pixbuf(pixbuf)
        return pixbuf.copy()
    except Exception:
        return generic_pixbuf(size)


def make_view_pixbuf(data: bytes, max_w: int, max_h: int):
    try:
        if max_w <= 0: max_w = 1600
        if max_h <= 0: max_h = 900
        gbytes = GLib.Bytes.new(data)
        stream = Gio.MemoryInputStream.new_from_bytes(gbytes)
        pixbuf = GdkPixbuf.Pixbuf.new_from_stream(stream, None)
        w = pixbuf.get_width()
        h = pixbuf.get_height()
        if max(w, h) <= 0:
            return None
        scale = min(1.0, max_w / float(w), max_h / float(h))
        if scale < 1.0:
            return pixbuf.scale_simple(max(1, int(w * scale)), max(1, int(h * scale)), GdkPixbuf.InterpType.BILINEAR)
        return pixbuf.copy()
    except Exception:
        return None


def unique_path(dest_dir: Path, name: str) -> Path:
    out = dest_dir / name
    n = 1
    stem = Path(name).stem
    suffix = Path(name).suffix
    while out.exists():
        out = dest_dir / f"{stem}_{n}{suffix}"
        n += 1
    return out


FAKE_ITEMS = [
    {"id": "fake-1", "name": "Paisaje.jpg", "color": 0x3A7D44FF, "mime": "image/jpeg"},
    {"id": "fake-2", "name": "Flor.jpg", "color": 0xC77DFFFF, "mime": "image/jpeg"},
    {"id": "fake-3", "name": "Coche.jpg", "color": 0x4361EEFF, "mime": "image/jpeg"},
    {"id": "fake-4", "name": "Playa.jpg", "color": 0x4CC9F0FF, "mime": "image/jpeg"},
    {"id": "fake-5", "name": "Montaña.jpg", "color": 0x8D99AEFF, "mime": "image/jpeg"},
    {"id": "fake-6", "name": "Ciudad.jpg", "color": 0xF77F00FF, "mime": "image/jpeg"},
]


def fake_pixbuf(color, size=200):
    pix = GdkPixbuf.Pixbuf.new(GdkPixbuf.Colorspace.RGB, True, 8, size, size)
    pix.fill(color)
    return pix


def format_time(seconds):
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{minutes:02d}:{secs:02d}"


class FakeViewerWindow(Gtk.Window):
    def __init__(self, parent, name, pixbuf):
        super().__init__(title=name, transient_for=parent, modal=True)
        self.set_default_size(800, 600)
        header = Gtk.HeaderBar(title=name, show_close_button=True)
        self.set_titlebar(header)
        image = Gtk.Image()
        if pixbuf:
            image.set_from_pixbuf(pixbuf)
        scroll = Gtk.ScrolledWindow()
        scroll.add(image)
        self.add(scroll)
        self.show_all()


class ImageViewerWindow(Gtk.Window):
    def __init__(self, parent, ids, index):
        super().__init__(title="Visor", transient_for=parent, modal=True)
        self.parent = parent
        self.ids = ids
        self.index = index
        self.base_pixbuf = None
        self.zoom = 1.0
        self.dragging = False
        self.last_x = 0
        self.last_y = 0
        self.set_default_size(1050, 720)
        self.connect("key-press-event", self.on_key)
        self.header = Gtk.HeaderBar(title="Visor", show_close_button=True)
        self.prev_button = Gtk.Button.new_from_icon_name("go-previous-symbolic", Gtk.IconSize.BUTTON)
        self.next_button = Gtk.Button.new_from_icon_name("go-next-symbolic", Gtk.IconSize.BUTTON)
        zoom_out = Gtk.Button.new_from_icon_name("zoom-out-symbolic", Gtk.IconSize.BUTTON)
        zoom_in = Gtk.Button.new_from_icon_name("zoom-in-symbolic", Gtk.IconSize.BUTTON)
        zoom_fit = Gtk.Button(label="Ajustar")
        zoom_100 = Gtk.Button(label="100%")
        self.prev_button.connect("clicked", lambda b: self.navigate(-1))
        self.next_button.connect("clicked", lambda b: self.navigate(1))
        zoom_out.connect("clicked", lambda b: self.change_zoom(0.8))
        zoom_in.connect("clicked", lambda b: self.change_zoom(1.25))
        zoom_fit.connect("clicked", lambda b: self.fit_zoom())
        zoom_100.connect("clicked", lambda b: self.set_zoom(1.0))
        self.header.pack_start(self.prev_button)
        self.header.pack_start(zoom_out)
        self.header.pack_start(zoom_in)
        self.header.pack_start(zoom_fit)
        self.header.pack_start(zoom_100)
        self.header.pack_end(self.next_button)
        self.set_titlebar(self.header)
        self.image = Gtk.Image()
        self.scroll = Gtk.ScrolledWindow()
        self.scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self.scroll.add(self.image)
        self.scroll.add_events(Gdk.EventMask.BUTTON_PRESS_MASK | Gdk.EventMask.BUTTON1_MOTION_MASK | Gdk.EventMask.BUTTON_RELEASE_MASK)
        self.scroll.connect("button-press-event", self.on_drag_start)
        self.scroll.connect("motion-notify-event", self.on_drag_motion)
        self.scroll.connect("button-release-event", self.on_drag_end)
        self.add(self.scroll)
        self.load_current()
        self.show_all()
        GLib.idle_add(self.fit_zoom)

    def navigate(self, delta):
        new_index = self.index + delta
        if 0 <= new_index < len(self.ids):
            self.index = new_index
            self.load_current()
            GLib.idle_add(self.fit_zoom)

    def on_key(self, widget, event):
        if event.keyval == Gdk.KEY_Escape:
            self.destroy()
            return True
        if event.keyval == Gdk.KEY_Left:
            self.navigate(-1)
            return True
        if event.keyval == Gdk.KEY_Right:
            self.navigate(1)
            return True
        if event.keyval == Gdk.KEY_plus or event.keyval == Gdk.KEY_KP_Add:
            self.change_zoom(1.25)
            return True
        if event.keyval == Gdk.KEY_minus or event.keyval == Gdk.KEY_KP_Subtract:
            self.change_zoom(0.8)
            return True
        return False

    def on_drag_start(self, widget, event):
        if event.button == 1:
            self.dragging = True
            self.last_x = event.x
            self.last_y = event.y
            return True
        return False

    def on_drag_motion(self, widget, event):
        if self.dragging:
            hadj = self.scroll.get_hadjustment()
            vadj = self.scroll.get_vadjustment()
            dx = event.x - self.last_x
            dy = event.y - self.last_y
            hadj.set_value(hadj.get_value() - dx)
            vadj.set_value(vadj.get_value() - dy)
            self.last_x = event.x
            self.last_y = event.y
            return True
        return False

    def on_drag_end(self, widget, event):
        if event.button == 1:
            self.dragging = False
            return True
        return False

    def change_zoom(self, factor):
        self.set_zoom(self.zoom * factor)

    def set_zoom(self, value):
        self.zoom = max(0.1, min(8.0, value))
        self.apply_zoom()

    def fit_zoom(self):
        if not self.base_pixbuf:
            return False
        alloc = self.scroll.get_allocation()
        if alloc.width <= 1 or alloc.height <= 1:
            return True
        w = float(self.base_pixbuf.get_width())
        h = float(self.base_pixbuf.get_height())
        if w <= 0 or h <= 0:
            return False
        fit = min(alloc.width / w, alloc.height / h)
        self.set_zoom(fit if fit > 0 else 1.0)
        return False

    def apply_zoom(self):
        if not self.base_pixbuf:
            self.image.set_from_icon_name("image-missing", Gtk.IconSize.DIALOG)
            return
        if abs(self.zoom - 1.0) < 0.01:
            self.image.set_from_pixbuf(self.base_pixbuf)
            return
        w = max(1, int(self.base_pixbuf.get_width() * self.zoom))
        h = max(1, int(self.base_pixbuf.get_height() * self.zoom))
        pix = self.base_pixbuf.scale_simple(w, h, GdkPixbuf.InterpType.BILINEAR)
        self.image.set_from_pixbuf(pix)

    def load_current(self):
        if not self.ids:
            self.destroy()
            return
        entry_id = self.ids[self.index]
        entry = self.parent.get_entry_by_id(entry_id)
        if not entry:
            self.image.set_from_icon_name("image-missing", Gtk.IconSize.DIALOG)
            return
        try:
            data = self.parent.app.decrypt_file(entry_id)
            self.base_pixbuf = make_view_pixbuf(data, 4096, 4096)
        except Exception:
            self.base_pixbuf = None
        self.apply_zoom()
        self.header.set_title(entry.get("name", "Visor"))
        self.prev_button.set_sensitive(self.index > 0)
        self.next_button.set_sensitive(self.index < len(self.ids) - 1)


class PDFViewerWindow(Gtk.Window):
    def __init__(self, parent, entry):
        super().__init__(title=entry.get("name", "PDF"), transient_for=parent, modal=True)
        self.set_default_size(900, 700)
        header = Gtk.HeaderBar(title=entry.get("name", "PDF"), show_close_button=True)
        self.set_titlebar(header)
        self.image = Gtk.Image()
        scroll = Gtk.ScrolledWindow()
        scroll.add(self.image)
        self.add(scroll)
        try:
            data = parent.app.decrypt_file(entry["id"])
            tmp = Path("/tmp") / f"vault_{entry['id']}.pdf"
            tmp.write_bytes(data)
            doc = Poppler.Document.new_from_file(tmp.as_uri(), None)
            page = doc.get_page(0)
            w, h = page.get_size()
            scale = min(800 / w, 600 / h)
            pixbuf = Gdk.pixbuf_get_from_surface(page.get_thumbnail(w * scale, h * scale), 0, 0, int(w * scale), int(h * scale))
            if pixbuf:
                self.image.set_from_pixbuf(pixbuf)
            tmp.unlink()
        except Exception as e:
            print(f"Error PDF: {e}", file=sys.stderr)
            self.image.set_from_icon_name("application-pdf", Gtk.IconSize.DIALOG)
        self.show_all()


class VideoPlayerWindow(Gtk.Window):
    def __init__(self, parent, entry):
        super().__init__(title=entry.get("name", "Video"), transient_for=parent, modal=True)
        self.set_default_size(900, 600)
        self.parent = parent
        self.entry = entry
        self.playing = False
        self.duration = 0
        self.tmp_file = None

        try:
            data = parent.app.decrypt_file(entry["id"])
            self.tmp_file = Path("/tmp") / f"vault_{entry['id']}"
            self.tmp_file.write_bytes(data)
        except Exception as e:
            print(f"Error descifrando video: {e}", file=sys.stderr)

        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        self.drawing_area = Gtk.DrawingArea()
        self.drawing_area.set_size_request(800, 450)
        vbox.pack_start(self.drawing_area, True, True, 0)

        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        controls.set_border_width(6)

        self.play_button = Gtk.Button.new_from_icon_name("media-playback-pause-symbolic", Gtk.IconSize.BUTTON)
        self.play_button.connect("clicked", self.on_play_pause)
        controls.pack_start(self.play_button, False, False, 0)

        self.position_slider = Gtk.Scale.new_with_range(Gtk.Orientation.HORIZONTAL, 0, 100, 1)
        self.position_slider.set_draw_value(False)
        self.position_slider.connect("button-release-event", self.on_position_seek)
        controls.pack_start(self.position_slider, True, True, 0)

        self.time_label = Gtk.Label(label="00:00 / 00:00")
        controls.pack_start(self.time_label, False, False, 0)

        self.volume_button = Gtk.VolumeButton()
        self.volume_button.set_value(0.5)
        self.volume_button.connect("value-changed", self.on_volume_changed)
        controls.pack_start(self.volume_button, False, False, 0)

        vbox.pack_start(controls, False, False, 0)
        self.add(vbox)

        if self.tmp_file and HAS_GST:
            self.pipeline = Gst.ElementFactory.make("playbin", "player")
            self.pipeline.set_property("uri", self.tmp_file.as_uri())
            self.pipeline.set_property("volume", 0.5)

            bus = self.pipeline.get_bus()
            bus.add_signal_watch()
            bus.connect("message", self.on_bus_message)
            bus.enable_sync_message_emission()
            bus.connect("sync-message::element", self.on_sync_message)

            self.pipeline.set_state(Gst.State.PLAYING)
            self.playing = True

            GLib.timeout_add(500, self.update_position)
        else:
            label = Gtk.Label(label="No se pudo cargar el video. Instala GStreamer.")
            vbox.pack_start(label, True, True, 0)

        self.connect("destroy", self.on_destroy)
        self.connect("key-press-event", self.on_key_press)
        self.show_all()

    def on_sync_message(self, bus, message):
        if message.get_structure() and message.get_structure().get_name() == "prepare-window-handle":
            xid = self.drawing_area.get_window().get_xid()
            message.src.set_window_handle(xid)

    def on_bus_message(self, bus, message):
        if message.type == Gst.MessageType.EOS:
            self.pipeline.set_state(Gst.State.READY)
            self.playing = False
            self.play_button.set_image(Gtk.Image.new_from_icon_name("media-playback-start-symbolic", Gtk.IconSize.BUTTON))
        elif message.type == Gst.MessageType.ERROR:
            err, debug = message.parse_error()
            print(f"GStreamer error: {err}, {debug}", file=sys.stderr)

    def on_play_pause(self, button):
        if not hasattr(self, "pipeline"):
            return
        if self.playing:
            self.pipeline.set_state(Gst.State.PAUSED)
            self.play_button.set_image(Gtk.Image.new_from_icon_name("media-playback-start-symbolic", Gtk.IconSize.BUTTON))
        else:
            self.pipeline.set_state(Gst.State.PLAYING)
            self.play_button.set_image(Gtk.Image.new_from_icon_name("media-playback-pause-symbolic", Gtk.IconSize.BUTTON))
        self.playing = not self.playing

    def on_volume_changed(self, button, value):
        if hasattr(self, "pipeline"):
            self.pipeline.set_property("volume", value)

    def on_position_seek(self, widget, event):
        if not hasattr(self, "pipeline"):
            return False
        value = widget.get_value()
        seek_to = int(value * Gst.SECOND)
        self.pipeline.seek_simple(Gst.Format.TIME, Gst.SeekFlags.FLUSH | Gst.SeekFlags.KEY_UNIT, seek_to)
        return False

    def update_position(self):
        if not hasattr(self, "pipeline") or not self.playing:
            return True
        ok, position = self.pipeline.query_position(Gst.Format.TIME)
        ok2, duration = self.pipeline.query_duration(Gst.Format.TIME)
        if ok and ok2 and duration > 0:
            pos_sec = position / Gst.SECOND
            dur_sec = duration / Gst.SECOND
            self.time_label.set_text(f"{format_time(pos_sec)} / {format_time(dur_sec)}")
            self.position_slider.set_value(pos_sec)
            self.position_slider.set_range(0, dur_sec)
        return True

    def on_key_press(self, widget, event):
        if event.keyval == Gdk.KEY_Escape:
            self.destroy()
            return True
        if event.keyval == Gdk.KEY_space:
            self.on_play_pause(None)
            return True
        if event.keyval == Gdk.KEY_Left:
            self.seek_relative(-10)
            return True
        if event.keyval == Gdk.KEY_Right:
            self.seek_relative(10)
            return True
        if event.keyval == Gdk.KEY_Up:
            self.adjust_volume(0.1)
            return True
        if event.keyval == Gdk.KEY_Down:
            self.adjust_volume(-0.1)
            return True
        if event.keyval == Gdk.KEY_m:
            self.toggle_mute()
            return True
        return False

    def seek_relative(self, seconds):
        if not hasattr(self, "pipeline"):
            return
        ok, position = self.pipeline.query_position(Gst.Format.TIME)
        if ok:
            new_pos = max(0, position + seconds * Gst.SECOND)
            self.pipeline.seek_simple(Gst.Format.TIME, Gst.SeekFlags.FLUSH | Gst.SeekFlags.KEY_UNIT, new_pos)

    def adjust_volume(self, delta):
        if hasattr(self, "pipeline"):
            current = self.pipeline.get_property("volume")
            new_vol = max(0.0, min(1.0, current + delta))
            self.pipeline.set_property("volume", new_vol)
            self.volume_button.set_value(new_vol)

    def toggle_mute(self):
        if hasattr(self, "pipeline"):
            current = self.pipeline.get_property("volume")
            if current > 0:
                self.pipeline.set_property("volume", 0)
                self.volume_button.set_value(0)
            else:
                self.pipeline.set_property("volume", 0.5)
                self.volume_button.set_value(0.5)

    def on_destroy(self, widget):
        if hasattr(self, "pipeline"):
            self.pipeline.set_state(Gst.State.NULL)
        if self.tmp_file and self.tmp_file.exists():
            self.tmp_file.unlink()


class MainWindow(Gtk.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title=CONFIG.get("app_name", "Visor de notas"))
        self.app = app
        self.current_parent = "/"
        self.search_text = ""
        self.set_default_size(1150, 760)
        self.set_icon_name(CONFIG.get("icon_name", "utilities-text-editor"))
        self.connect("key-press-event", self.on_key_press)
        self.build_ui()
        self.apply_window_branding()
        self.refresh()

    def fake_active(self):
        return CONFIG.get("fake_profile", False)

    def build_ui(self):
        self.header = Gtk.HeaderBar(title=CONFIG.get("app_name", "Visor de notas"), subtitle="", show_close_button=True)
        self.set_titlebar(self.header)
        self.profile_button = Gtk.Button(label="Perfil: " + (CONFIG.get("current_profile", "Ninguno")))
        self.profile_button.connect("clicked", self.on_profile_clicked)
        self.header.pack_start(self.profile_button)
        self.up_button = Gtk.Button.new_from_icon_name("go-up-symbolic", Gtk.IconSize.BUTTON)
        self.up_button.set_tooltip_text("Subir carpeta")
        self.up_button.connect("clicked", self.on_up_clicked)
        self.header.pack_start(self.up_button)
        self.add_button = Gtk.Button.new_from_icon_name("list-add-symbolic", Gtk.IconSize.BUTTON)
        self.add_button.set_tooltip_text("Añadir archivos")
        self.add_button.connect("clicked", self.on_add_clicked)
        self.header.pack_start(self.add_button)
        self.delete_button = Gtk.Button.new_from_icon_name("user-trash-symbolic", Gtk.IconSize.BUTTON)
        self.delete_button.set_tooltip_text("Eliminar selección")
        self.delete_button.set_sensitive(False)
        self.delete_button.connect("clicked", self.on_delete_clicked)
        self.header.pack_start(self.delete_button)
        self.lock_button = Gtk.Button.new_from_icon_name("changes-prevent-symbolic", Gtk.IconSize.BUTTON)
        self.lock_button.set_tooltip_text("Bloquear")
        self.lock_button.set_sensitive(False)
        self.lock_button.connect("clicked", self.on_lock_clicked)
        self.header.pack_end(self.lock_button)
        menubar = self.build_menu()
        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_placeholder_text("Buscar...")
        self.search_entry.connect("search-changed", self.on_search_changed)
        self.search_entry.set_size_request(200, -1)
        self.header.pack_end(self.search_entry)
        self.filter_combo = Gtk.ComboBoxText()
        self.filter_combo.append("all", "Todos")
        self.filter_combo.append("favorites", "Favoritos")
        self.filter_combo.append("images", "Imágenes")
        self.filter_combo.append("videos", "Vídeos")
        self.filter_combo.append("pdf", "PDF")
        self.filter_combo.append("docs", "Documentos")
        self.filter_combo.set_active_id(CONFIG.get("filter_mode", "all"))
        self.filter_combo.connect("changed", self.on_filter_changed)
        self.header.pack_end(self.filter_combo)
        self.sort_combo = Gtk.ComboBoxText()
        self.sort_combo.append("name", "Nombre")
        self.sort_combo.append("date_new", "Más recientes")
        self.sort_combo.append("date_old", "Más antiguos")
        self.sort_combo.append("size", "Tamaño")
        self.sort_combo.set_active_id(CONFIG.get("sort_mode", "name"))
        self.sort_combo.connect("changed", self.on_sort_changed)
        self.header.pack_end(self.sort_combo)
        self.store = Gtk.ListStore(str, GdkPixbuf.Pixbuf, str, str, str, bool, bool)
        self.iconview = Gtk.IconView(model=self.store)
        self.iconview.set_pixbuf_column(1)
        self.iconview.set_text_column(2)
        self.iconview.set_item_width(200)
        self.iconview.set_selection_mode(Gtk.SelectionMode.MULTIPLE)
        self.iconview.connect("item-activated", self.on_item_activated)
        self.iconview.connect("selection-changed", self.on_selection_changed)
        self.iconview.connect("button-press-event", self.on_iconview_button_press)
        self.iconview.enable_model_drag_source(Gdk.ModifierType.BUTTON1_MASK, [Gtk.TargetEntry.new("text/plain", 0, 0)], Gdk.DragAction.MOVE)
        self.iconview.connect("drag-data-get", self.on_drag_data_get)
        self.iconview.enable_model_drag_dest([Gtk.TargetEntry.new("text/plain", 0, 0)], Gdk.DragAction.MOVE)
        self.iconview.connect("drag-data-received", self.on_drag_data_received)
        self.listbox = Gtk.ListBox()
        self.listbox.set_selection_mode(Gtk.SelectionMode.MULTIPLE)
        self.listbox.connect("row-activated", self.on_listbox_row_activated)
        self.listbox.connect("button-press-event", self.on_listbox_button_press)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self.stack_view = Gtk.Stack()
        self.stack_view.add_named(self.iconview, "icons")
        self.stack_view.add_named(self.listbox, "list")
        scroll.add(self.stack_view)
        self.empty_label = Gtk.Label(label="No hay elementos.")
        self.empty_label.set_halign(Gtk.Align.CENTER)
        self.empty_label.set_valign(Gtk.Align.CENTER)
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.stack.add_named(self.empty_label, "empty")
        self.stack.add_named(scroll, "content")
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        vbox.pack_start(menubar, False, False, 0)
        vbox.pack_end(self.stack, True, True, 0)
        self.add(vbox)
        self.set_view_mode(CONFIG.get("view_mode", "icons"))

    def build_menu(self):
        menubar = Gtk.MenuBar()
        file_item = Gtk.MenuItem.new_with_label("Archivo")
        file_menu = Gtk.Menu()
        file_item.set_submenu(file_menu)
        add_item = Gtk.MenuItem.new_with_label("Añadir archivos")
        add_item.connect("activate", self.on_add_clicked)
        file_menu.append(add_item)
        import_item = Gtk.MenuItem.new_with_label("Importar archivos")
        import_item.connect("activate", lambda w: self.on_import_files())
        file_menu.append(import_item)
        export_item = Gtk.MenuItem.new_with_label("Exportar archivos")
        export_item.connect("activate", lambda w: self.on_export_files())
        file_menu.append(export_item)
        file_menu.append(Gtk.SeparatorMenuItem())
        lock_item = Gtk.MenuItem.new_with_label("Bloquear")
        lock_item.connect("activate", self.on_lock_clicked)
        file_menu.append(lock_item)
        unlock_item = Gtk.MenuItem.new_with_label("Desbloquear / crear")
        unlock_item.connect("activate", lambda w: self.show_unlock_dialog())
        file_menu.append(unlock_item)
        file_menu.append(Gtk.SeparatorMenuItem())
        quit_item = Gtk.MenuItem.new_with_label("Salir")
        quit_item.connect("activate", lambda w: self.destroy())
        file_menu.append(quit_item)
        menubar.append(file_item)
        view_item = Gtk.MenuItem.new_with_label("Ver")
        view_menu = Gtk.Menu()
        view_item.set_submenu(view_menu)
        icons_item = Gtk.RadioMenuItem.new_with_label([], "Vista iconos")
        list_item = Gtk.RadioMenuItem.new_with_label_from_widget(icons_item, "Vista lista")
        icons_item.connect("toggled", lambda w: self.set_view_mode("icons") if w.get_active() else None)
        list_item.connect("toggled", lambda w: self.set_view_mode("list") if w.get_active() else None)
        view_menu.append(icons_item)
        view_menu.append(list_item)
        menubar.append(view_item)
        options_item = Gtk.MenuItem.new_with_label("Opciones")
        options_menu = Gtk.Menu()
        options_item.set_submenu(options_menu)
        general_item = Gtk.MenuItem.new_with_label("Preferencias generales...")
        general_item.connect("activate", lambda w: self.show_general_settings())
        options_menu.append(general_item)
        theme_item = Gtk.MenuItem.new_with_label("Tema")
        theme_menu = Gtk.Menu()
        theme_item.set_submenu(theme_menu)
        themes = [("Por defecto", "default"), ("Claro", "light"), ("Oscuro", "dark"), ("Gris", "gray"), ("Monocromo", "mono")]
        for label, theme in themes:
            item = Gtk.MenuItem.new_with_label(label)
            item.connect("activate", lambda w, t=theme: self.on_theme_menu(t))
            theme_menu.append(item)
        options_menu.append(theme_item)
        options_menu.append(Gtk.SeparatorMenuItem())
        self.fake_item = Gtk.CheckMenuItem.new_with_label("Perfil fake")
        self.fake_item.set_active(CONFIG.get("fake_profile", False))
        self.fake_item.connect("toggled", self.on_toggle_fake)
        options_menu.append(self.fake_item)
        options_menu.append(Gtk.SeparatorMenuItem())
        change_folder_item = Gtk.MenuItem.new_with_label("Cambiar carpeta de la bóveda...")
        change_folder_item.connect("activate", lambda w: self.on_change_vault_folder())
        options_menu.append(change_folder_item)
        destroy_item = Gtk.MenuItem.new_with_label("Destruir perfil actual...")
        destroy_item.connect("activate", lambda w: self.on_destroy_profile())
        options_menu.append(destroy_item)
        menubar.append(options_item)
        help_item = Gtk.MenuItem.new_with_label("Ayuda")
        help_menu = Gtk.Menu()
        help_item.set_submenu(help_menu)
        shortcuts_item = Gtk.MenuItem.new_with_label("Atajos")
        shortcuts_item.connect("activate", lambda w: self.show_help())
        help_menu.append(shortcuts_item)
        about_item = Gtk.MenuItem.new_with_label("Acerca de")
        about_item.connect("activate", lambda w: self.show_about())
        help_menu.append(about_item)
        menubar.append(help_item)
        return menubar

    def apply_window_branding(self):
        name = CONFIG.get("app_name", "Visor de notas")
        icon = CONFIG.get("icon_name", "utilities-text-editor")
        self.set_title(name)
        self.header.set_title(name)
        self.set_icon_name(icon)
        self.profile_button.set_label("Perfil: " + (CONFIG.get("current_profile", "Ninguno")))

    def set_view_mode(self, mode):
        CONFIG["view_mode"] = mode
        save_config()
        self.stack_view.set_visible_child_name(mode)
        self.refresh()

    def on_theme_menu(self, theme):
        CONFIG["theme"] = theme
        save_config()
        apply_theme()

    def on_toggle_fake(self, widget):
        CONFIG["fake_profile"] = widget.get_active()
        save_config()
        self.refresh()

    def on_search_changed(self, widget):
        self.search_text = widget.get_text().strip().lower()
        self.refresh()

    def on_filter_changed(self, widget):
        CONFIG["filter_mode"] = widget.get_active_id()
        save_config()
        self.refresh()

    def on_sort_changed(self, widget):
        CONFIG["sort_mode"] = widget.get_active_id()
        save_config()
        self.refresh()

    def on_key_press(self, widget, event):
        if event.state & Gdk.ModifierType.CONTROL_MASK:
            if event.keyval == Gdk.KEY_u:
                self.show_unlock_dialog()
                return True
            if event.keyval == Gdk.KEY_l and self.app.unlocked:
                self.on_lock_clicked()
                return True
            if event.keyval == Gdk.KEY_a:
                self.on_add_clicked()
                return True
            if event.keyval == Gdk.KEY_n:
                self.on_create_folder()
                return True
            if event.keyval == Gdk.KEY_r:
                self.on_rename_selected()
                return True
            if event.keyval == Gdk.KEY_d:
                self.on_download_selected()
                return True
            if event.keyval == Gdk.KEY_f:
                CONFIG["fake_profile"] = not CONFIG.get("fake_profile", False)
                save_config()
                self.fake_item.set_active(CONFIG["fake_profile"])
                self.refresh()
                return True
        if event.keyval == Gdk.KEY_BackSpace and not self.fake_active():
            self.on_up_clicked()
            return True
        if event.keyval == Gdk.KEY_Escape:
            CONFIG["fake_profile"] = True
            save_config()
            self.fake_item.set_active(True)
            self.refresh()
            self.minimize_to_tray()
            return True
        return False

    def minimize_to_tray(self):
        global STATUS_ICON
        self.hide()
        if STATUS_ICON is None:
            STATUS_ICON = Gtk.StatusIcon()
            STATUS_ICON.set_from_icon_name(CONFIG.get("icon_name", "utilities-text-editor"))
            STATUS_ICON.set_tooltip_text(CONFIG.get("app_name", "Visor de notas"))
            STATUS_ICON.connect("activate", self.on_tray_activate)
            STATUS_ICON.connect("popup-menu", self.on_tray_popup)
            STATUS_ICON.set_visible(True)

    def on_tray_activate(self, icon):
        self.show()
        self.present()

    def on_tray_popup(self, icon, button, time):
        menu = Gtk.Menu()
        show_item = Gtk.MenuItem.new_with_label("Mostrar")
        show_item.connect("activate", lambda w: self.on_tray_activate(icon))
        menu.append(show_item)
        quit_item = Gtk.MenuItem.new_with_label("Salir")
        quit_item.connect("activate", lambda w: Gtk.main_quit())
        menu.append(quit_item)
        menu.show_all()
        menu.popup(None, None, Gtk.StatusIcon.position_menu, icon, button, time)

    def refresh(self):
        self.store.clear()
        for child in self.listbox.get_children():
            self.listbox.remove(child)
        self.header.set_subtitle(self.build_current_path())
        if self.fake_active():
            for fake in FAKE_ITEMS:
                pix = fake_pixbuf(fake["color"], 200)
                self.store.append([fake["id"], pix, fake["name"], "fake", fake["mime"], False, False])
                row = Gtk.ListBoxRow()
                hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
                hbox.pack_start(Gtk.Image.new_from_pixbuf(pix), False, False, 0)
                hbox.pack_start(Gtk.Label(label=fake["name"]), False, False, 0)
                row.add(hbox)
                self.listbox.add(row)
            self.stack.set_visible_child_name("content")
            self.delete_button.set_sensitive(False)
            self.lock_button.set_sensitive(False)
            self.up_button.set_sensitive(False)
            self.listbox.show_all()
            return
        if self.app.unlocked:
            entries = [normalize_entry(e) for e in self.app.entries if e.get("parent", "/") == self.current_parent]
            if self.search_text:
                entries = [e for e in entries if self.search_text in e.get("name", "").lower()]
            filter_mode = CONFIG.get("filter_mode", "all")
            if filter_mode == "favorites":
                entries = [e for e in entries if e.get("favorite", False)]
            elif filter_mode == "images":
                entries = [e for e in entries if e.get("mime", "").startswith("image/")]
            elif filter_mode == "videos":
                entries = [e for e in entries if e.get("mime", "").startswith("video/")]
            elif filter_mode == "pdf":
                entries = [e for e in entries if e.get("mime", "") == "application/pdf"]
            elif filter_mode == "docs":
                entries = [e for e in entries if e.get("mime", "").startswith("text/") or "document" in e.get("mime", "").lower()]
            sort_mode = CONFIG.get("sort_mode", "name")
            if sort_mode == "name":
                entries.sort(key=lambda e: (not e.get("pinned", False), e.get("name", "").lower()))
            elif sort_mode == "date_new":
                entries.sort(key=lambda e: (not e.get("pinned", False), e.get("added", "")), reverse=True)
            elif sort_mode == "date_old":
                entries.sort(key=lambda e: (not e.get("pinned", False), e.get("added", "")))
            elif sort_mode == "size":
                entries.sort(key=lambda e: (not e.get("pinned", False), e.get("size", 0)), reverse=True)
            for entry in entries:
                if entry.get("type") == "folder":
                    thumb = folder_pixbuf(200)
                    mime = "inode/directory"
                else:
                    mime = entry.get("mime", "")
                    thumb = generic_pixbuf(200)
                    if mime.startswith("image/"):
                        try:
                            data = self.app.decrypt_file(entry["id"])
                            thumb = make_thumb(data, 200, blur=CONFIG.get("blur_images", False))
                        except Exception:
                            thumb = generic_pixbuf(200)
                    elif mime.startswith("video/"):
                        thumb = video_pixbuf(200)
                    elif mime == "application/pdf":
                        thumb = pdf_pixbuf(200)
                fav = entry.get("favorite", False)
                pin = entry.get("pinned", False)
                if fav:
                    thumb = add_overlay_icon(thumb, "emblem-favorite", 28, "top-right")
                if pin:
                    thumb = add_overlay_icon(thumb, "emblem-important", 28, "top-left")
                self.store.append([entry.get("id", ""), thumb, entry.get("name", "archivo"), entry.get("type", "file"), mime, fav, pin])
                row = Gtk.ListBoxRow()
                hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
                hbox.pack_start(Gtk.Image.new_from_pixbuf(thumb), False, False, 0)
                label = entry.get("name", "archivo")
                if pin:
                    label = "📌 " + label
                if fav:
                    label = "⭐ " + label
                hbox.pack_start(Gtk.Label(label=label), False, False, 0)
                row.add(hbox)
                self.listbox.add(row)
            self.stack.set_visible_child_name("content" if entries else "empty")
            self.listbox.show_all()
        else:
            self.stack.set_visible_child_name("empty")
        self.delete_button.set_sensitive(False)
        self.lock_button.set_sensitive(self.app.unlocked)
        self.up_button.set_sensitive(self.app.unlocked and self.current_parent != "/")

    def get_entry_by_id(self, entry_id):
        for entry in self.app.entries:
            if entry.get("id") == entry_id:
                return normalize_entry(entry)
        return None

    def get_direct_children(self, parent_id):
        return [normalize_entry(e) for e in self.app.entries if e.get("parent", "/") == parent_id]

    def get_descendant_folder_ids(self, folder_id):
        ids = {folder_id}
        for child in self.get_direct_children(folder_id):
            if child.get("type") == "folder":
                ids.update(self.get_descendant_folder_ids(child["id"]))
        return ids

    def is_descendant_of_any(self, entry_id, ancestor_ids):
        current = entry_id
        seen = set()
        while current and current != "/" and current not in seen:
            if current in ancestor_ids:
                return True
            seen.add(current)
            entry = self.get_entry_by_id(current)
            if not entry:
                break
            current = entry.get("parent", "/")
        return False

    def build_vault_path(self, entry):
        names = []
        current = entry
        seen = set()
        while current and current.get("id") != "/" and current["id"] not in seen:
            names.append(current.get("name", ""))
            seen.add(current["id"])
            parent = current.get("parent", "/")
            if parent == "/":
                current = None
            else:
                current = self.get_entry_by_id(parent)
        return "/" + "/".join(reversed(names))

    def build_current_path(self):
        if self.fake_active():
            return "Perfil fake"
        if self.current_parent == "/":
            return "/"
        entry = self.get_entry_by_id(self.current_parent)
        if entry:
            return self.build_vault_path(entry)
        return "/"

    def calculate_size(self, entry_id):
        entry = self.get_entry_by_id(entry_id)
        if not entry:
            return 0
        if entry.get("type") == "file":
            return int(entry.get("size", 0))
        total = 0
        for child in self.get_direct_children(entry_id):
            total += self.calculate_size(child["id"])
        return total

    def show_message(self, text):
        dialog = Gtk.MessageDialog(transient_for=self, modal=True, message_type=Gtk.MessageType.INFO, buttons=Gtk.ButtonsType.OK)
        dialog.set_property("text", text)
        dialog.run()
        dialog.destroy()

    def ask_yes_no(self, text):
        dialog = Gtk.MessageDialog(transient_for=self, modal=True, message_type=Gtk.MessageType.QUESTION, buttons=Gtk.ButtonsType.YES_NO)
        dialog.set_property("text", text)
        response = dialog.run()
        dialog.destroy()
        return response == Gtk.ResponseType.YES

    def prompt_text(self, title, label, text=""):
        dialog = Gtk.Dialog(title=title, transient_for=self, modal=True)
        dialog.set_resizable(False)
        box = dialog.get_content_area()
        box.set_border_width(12)
        box.set_spacing(8)
        lbl = Gtk.Label(label=label)
        entry = Gtk.Entry()
        entry.set_text(text)
        entry.set_width_chars(38)
        entry.set_activates_default(True)
        box.add(lbl)
        box.add(entry)
        dialog.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        dialog.add_button("Aceptar", Gtk.ResponseType.OK)
        dialog.set_default_response(Gtk.ResponseType.OK)
        dialog.show_all()
        response = dialog.run()
        value = entry.get_text()
        dialog.destroy()
        return response == Gtk.ResponseType.OK, value

    def show_help(self):
        text = """
Atajos:

Ctrl + U: desbloquear / crear bóveda.
Ctrl + L: bloquear.
Ctrl + A: añadir archivos.
Ctrl + N: crear carpeta.
Ctrl + R: renombrar seleccionado.
Ctrl + D: descargar seleccionado.
Ctrl + F: activar/desactivar perfil fake.
Backspace: subir carpeta.
ESC: minimizar a bandeja y activar perfil fake.
Doble clic en imagen: ver dentro de la app.
Doble clic en carpeta: entrar en la carpeta.
Flechas izquierda/derecha en el visor: cambiar imagen.
+ / - en el visor: zoom.
Esc en visor: cerrar visor.

En el reproductor de vídeo:
Espacio: play/pause.
Flecha izquierda/derecha: retroceder/avanzar 10 segundos.
Flecha arriba/abajo: subir/bajar volumen.
M: silenciar/activar sonido.
"""
        self.show_message(text.strip())

    def show_about(self):
        about = Gtk.AboutDialog(transient_for=self, modal=True)
        about.set_program_name(CONFIG.get("app_name", "Visor de notas"))
        about.set_version(APP_VERSION)
        about.set_comments("Bóveda privada con perfiles, modo fake y reproductor de vídeo con sonido.")
        about.set_copyright(f"Creado por {APP_AUTHOR}")
        about.set_authors([APP_AUTHOR])
        about.set_website(APP_WEBSITE)
        about.set_website_label("GitHub de djsemax")
        about.set_license_type(Gtk.License.MIT_X11)
        today = datetime.date.today().isoformat()
        about.add_credit_section("Fechas", [f"Creada: {APP_CREATED_DATE}", f"Última edición: {today}"])
        about.run()
        about.destroy()

    def show_general_settings(self):
        dialog = Gtk.Dialog(title="Preferencias generales", transient_for=self, modal=True)
        dialog.set_resizable(False)
        box = dialog.get_content_area()
        box.set_border_width(12)
        grid = Gtk.Grid()
        grid.set_column_spacing(12)
        grid.set_row_spacing(10)
        app_name = Gtk.Entry()
        app_name.set_text(CONFIG.get("app_name", "Visor de notas"))
        app_name.set_width_chars(34)
        icon_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.icon_preview = Gtk.Image()
        icon_path = CONFIG.get("icon_path", "")
        if icon_path and Path(icon_path).exists():
            try:
                pix = GdkPixbuf.Pixbuf.new_from_file_at_size(icon_path, 48, 48)
                self.icon_preview.set_from_pixbuf(pix)
            except Exception:
                self.icon_preview.set_from_icon_name(CONFIG.get("icon_name", "utilities-text-editor"), Gtk.IconSize.DIALOG)
        else:
            self.icon_preview.set_from_icon_name(CONFIG.get("icon_name", "utilities-text-editor"), Gtk.IconSize.DIALOG)
        icon_box.pack_start(self.icon_preview, False, False, 0)
        browse_button = Gtk.Button(label="Examinar...")
        browse_button.connect("clicked", self.on_browse_icon)
        icon_box.pack_start(browse_button, False, False, 0)
        blur_switch = Gtk.Switch()
        blur_switch.set_active(CONFIG.get("blur_images", False))
        biometric_switch = Gtk.Switch()
        biometric_switch.set_active(CONFIG.get("biometric_unlock", False))
        media_switch = Gtk.Switch()
        media_switch.set_active(CONFIG.get("allow_video_pdf", True))
        grid.attach(Gtk.Label(label="Nombre de la app:"), 0, 0, 1, 1)
        grid.attach(app_name, 1, 0, 1, 1)
        grid.attach(Gtk.Label(label="Icono de la app:"), 0, 1, 1, 1)
        grid.attach(icon_box, 1, 1, 1, 1)
        grid.attach(Gtk.Label(label="Ofuscar imágenes:"), 0, 2, 1, 1)
        grid.attach(blur_switch, 1, 2, 1, 1)
        grid.attach(Gtk.Label(label="Biometría (experimental):"), 0, 3, 1, 1)
        grid.attach(biometric_switch, 1, 3, 1, 1)
        grid.attach(Gtk.Label(label="Permitir vídeos/PDF:"), 0, 4, 1, 1)
        grid.attach(media_switch, 1, 4, 1, 1)
        box.add(grid)
        dialog.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        dialog.add_button("Guardar", Gtk.ResponseType.OK)
        dialog.set_default_response(Gtk.ResponseType.OK)
        dialog.show_all()
        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            CONFIG["app_name"] = app_name.get_text().strip() or "Visor de notas"
            CONFIG["blur_images"] = blur_switch.get_active()
            CONFIG["biometric_unlock"] = biometric_switch.get_active()
            CONFIG["allow_video_pdf"] = media_switch.get_active()
            save_config()
            self.apply_window_branding()
            self.refresh()
        dialog.destroy()

    def on_browse_icon(self, button):
        chooser = Gtk.FileChooserDialog(title="Elegir icono", transient_for=self, action=Gtk.FileChooserAction.OPEN)
        chooser.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        chooser.add_button("Abrir", Gtk.ResponseType.ACCEPT)
        img_filter = Gtk.FileFilter()
        img_filter.set_name("Imágenes")
        img_filter.add_mime_type("image/*")
        chooser.add_filter(img_filter)
        response = chooser.run()
        if response == Gtk.ResponseType.ACCEPT:
            path = chooser.get_filename()
            CONFIG["icon_path"] = path
            save_config()
            try:
                pix = GdkPixbuf.Pixbuf.new_from_file_at_size(path, 48, 48)
                self.icon_preview.set_from_pixbuf(pix)
            except Exception:
                pass
        chooser.destroy()

    def on_change_vault_folder(self):
        chooser = Gtk.FileChooserDialog(title="Elegir carpeta para la bóveda", transient_for=self, action=Gtk.FileChooserAction.SELECT_FOLDER)
        chooser.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        chooser.add_button("Seleccionar", Gtk.ResponseType.ACCEPT)
        response = chooser.run()
        folder = chooser.get_filename() if response == Gtk.ResponseType.ACCEPT else None
        chooser.destroy()
        if response != Gtk.ResponseType.ACCEPT or not folder:
            return
        CONFIG["vault_dir"] = folder
        save_config()
        self.app.lock()
        self.current_parent = "/"
        self.refresh()
        self.show_message("Carpeta de bóveda cambiada. Desbloquea un perfil para continuar.")

    def on_destroy_profile(self):
        if not CONFIG.get("current_profile"):
            self.show_message("No hay perfil activo.")
            return
        ok, value = self.prompt_text("Destruir perfil", f"Escribe BORRAR para eliminar el perfil '{CONFIG['current_profile']}':", "")
        if not ok or value.strip() != "BORRAR":
            self.show_message("No se escribió BORRAR. No se eliminó nada.")
            return
        destroy_profile(CONFIG["current_profile"])
        self.app.lock()
        CONFIG["current_profile"] = ""
        save_config()
        self.current_parent = "/"
        self.refresh()
        self.show_message("Perfil destruido.")

    def ensure_unlocked(self):
        if self.app.unlocked:
            return True
        return self.show_unlock_dialog()

    def show_unlock_dialog(self):
        profiles = list_profiles()
        if not profiles:
            return self.show_create_dialog()
        dialog = Gtk.Dialog(title="Acceso", transient_for=self, modal=True)
        dialog.set_resizable(False)
        box = dialog.get_content_area()
        box.set_border_width(12)
        box.set_spacing(8)
        profile_combo = Gtk.ComboBoxText()
        for p in profiles:
            profile_combo.append_text(p)
        last = CONFIG.get("last_profile", "")
        if last in profiles:
            profile_combo.set_active(profiles.index(last))
        else:
            profile_combo.set_active(0)
        entry = Gtk.Entry()
        entry.set_visibility(False)
        entry.set_invisible_char("•")
        entry.set_activates_default(True)
        entry.set_width_chars(32)
        box.add(Gtk.Label(label="Perfil:"))
        box.add(profile_combo)
        box.add(Gtk.Label(label="Contraseña:"))
        box.add(entry)
        dialog.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        dialog.add_button("Abrir", Gtk.ResponseType.OK)
        dialog.set_default_response(Gtk.ResponseType.OK)
        dialog.show_all()
        response = dialog.run()
        profile_name = profile_combo.get_active_text()
        password = entry.get_text()
        dialog.destroy()
        if response != Gtk.ResponseType.OK:
            return False
        CONFIG["current_profile"] = profile_name
        CONFIG["last_profile"] = profile_name
        save_config()
        ensure_dirs()
        master_key, entries = unlock_vault(profile_name, password)
        if master_key is None:
            self.app.lock()
            self.current_parent = "/"
            self.refresh()
            return False
        self.app.unlock(master_key, entries)
        self.current_parent = "/"
        self.apply_window_branding()
        self.refresh()
        return True

    def show_create_dialog(self):
        dialog = Gtk.Dialog(title="Crear perfil", transient_for=self, modal=True)
        dialog.set_resizable(False)
        box = dialog.get_content_area()
        box.set_border_width(12)
        grid = Gtk.Grid()
        grid.set_column_spacing(10)
        grid.set_row_spacing(8)
        profile_name = Gtk.Entry()
        profile_name.set_text("Perfil 1")
        profile_name.set_width_chars(34)
        p1 = Gtk.Entry()
        p1.set_visibility(False)
        p1.set_invisible_char("•")
        p1.set_activates_default(True)
        p2 = Gtk.Entry()
        p2.set_visibility(False)
        p2.set_invisible_char("•")
        p2.set_activates_default(True)
        grid.attach(Gtk.Label(label="Nombre del perfil:"), 0, 0, 1, 1)
        grid.attach(profile_name, 1, 0, 1, 1)
        grid.attach(Gtk.Label(label="Contraseña:"), 0, 1, 1, 1)
        grid.attach(p1, 1, 1, 1, 1)
        grid.attach(Gtk.Label(label="Repetir contraseña:"), 0, 2, 1, 1)
        grid.attach(p2, 1, 2, 1, 1)
        box.add(grid)
        dialog.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        dialog.add_button("Crear", Gtk.ResponseType.OK)
        dialog.set_default_response(Gtk.ResponseType.OK)
        dialog.show_all()
        response = dialog.run()
        pname = profile_name.get_text().strip()
        pass1 = p1.get_text()
        pass2 = p2.get_text()
        dialog.destroy()
        if response != Gtk.ResponseType.OK:
            return False
        if not pname:
            self.show_message("El nombre del perfil no puede estar vacío.")
            return False
        if not pass1 or pass1 != pass2:
            self.show_message("Las contraseñas deben coincidir y no estar vacías.")
            return False
        master_key = create_vault(pname, pass1)
        self.app.unlock(master_key, [])
        self.current_parent = "/"
        self.apply_window_branding()
        self.refresh()
        return True

    def on_profile_clicked(self, button):
        menu = Gtk.Menu()
        new_item = Gtk.MenuItem.new_with_label("Crear perfil nuevo")
        new_item.connect("activate", lambda w: self.show_create_dialog())
        menu.append(new_item)
        switch_item = Gtk.MenuItem.new_with_label("Cambiar de perfil")
        switch_item.connect("activate", lambda w: self.show_unlock_dialog())
        menu.append(switch_item)
        change_pass_item = Gtk.MenuItem.new_with_label("Cambiar contraseña")
        change_pass_item.connect("activate", lambda w: self.on_change_password())
        menu.append(change_pass_item)
        menu.show_all()
        menu.popup(None, None, None, None, 0, Gtk.get_current_event_time())

    def on_change_password(self):
        if not self.ensure_unlocked():
            return
        dialog = Gtk.Dialog(title="Cambiar contraseña", transient_for=self, modal=True)
        dialog.set_resizable(False)
        box = dialog.get_content_area()
        box.set_border_width(12)
        grid = Gtk.Grid()
        grid.set_column_spacing(10)
        grid.set_row_spacing(8)
        p1 = Gtk.Entry()
        p1.set_visibility(False)
        p1.set_invisible_char("•")
        p1.set_activates_default(True)
        p2 = Gtk.Entry()
        p2.set_visibility(False)
        p2.set_invisible_char("•")
        p2.set_activates_default(True)
        grid.attach(Gtk.Label(label="Nueva contraseña:"), 0, 0, 1, 1)
        grid.attach(p1, 1, 0, 1, 1)
        grid.attach(Gtk.Label(label="Repetir nueva contraseña:"), 0, 1, 1, 1)
        grid.attach(p2, 1, 1, 1, 1)
        box.add(grid)
        dialog.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        dialog.add_button("Cambiar", Gtk.ResponseType.OK)
        dialog.set_default_response(Gtk.ResponseType.OK)
        dialog.show_all()
        response = dialog.run()
        pass1 = p1.get_text()
        pass2 = p2.get_text()
        dialog.destroy()
        if response != Gtk.ResponseType.OK:
            return
        if not pass1 or pass1 != pass2:
            self.show_message("Las contraseñas no coinciden o están vacías.")
            return
        change_password(self.app.master_key, pass1)
        self.show_message("Contraseña cambiada.")

    def choose_and_add_files(self):
        chooser = Gtk.FileChooserDialog(title="Añadir archivos", transient_for=self, action=Gtk.FileChooserAction.OPEN)
        chooser.set_select_multiple(True)
        chooser.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        chooser.add_button("Añadir", Gtk.ResponseType.ACCEPT)
        all_filter = Gtk.FileFilter()
        all_filter.set_name("Todos los archivos")
        all_filter.add_pattern("*")
        chooser.add_filter(all_filter)
        response = chooser.run()
        files = chooser.get_filenames() if response == Gtk.ResponseType.ACCEPT else []
        chooser.destroy()
        if not files:
            return
        added = 0
        for path_str in files:
            try:
                path = Path(path_str)
                data = path.read_bytes()
                entry_id = str(uuid.uuid4())
                write_secure(files_dir() / f"{entry_id}.bin", encrypt_file(self.app.master_key, data))
                mime, _ = Gio.content_type_guess(str(path), data)
                entry = normalize_entry({"id": entry_id, "type": "file", "parent": self.current_parent, "name": path.name, "mime": mime or "application/octet-stream", "size": len(data), "added": datetime.datetime.now().isoformat()})
                self.app.entries.append(entry)
                added += 1
            except Exception as e:
                print(f"No se pudo añadir {path_str}: {e}", file=sys.stderr)
        if added:
            save_manifest(self.app.master_key, self.app.entries)
            self.refresh()

    def on_add_clicked(self, widget=None):
        if not self.ensure_unlocked():
            return
        self.choose_and_add_files()

    def on_import_files(self):
        if not self.ensure_unlocked():
            return
        self.choose_and_add_files()

    def on_export_files(self):
        if not self.ensure_unlocked():
            return
        self.on_download_selected()

    def on_lock_clicked(self, widget=None):
        self.app.lock()
        self.current_parent = "/"
        self.refresh()

    def on_up_clicked(self, widget=None):
        if self.fake_active() or not self.app.unlocked:
            return
        if self.current_parent == "/":
            return
        current = self.get_entry_by_id(self.current_parent)
        if current:
            self.current_parent = current.get("parent", "/")
        else:
            self.current_parent = "/"
        self.refresh()

    def on_selection_changed(self, iconview):
        paths = self.iconview.get_selected_items()
        self.delete_button.set_sensitive(bool(paths) and self.app.unlocked and not self.fake_active())

    def on_item_activated(self, iconview, path):
        if self.fake_active():
            it = self.store.get_iter(path)
            pix = self.store.get_value(it, 1)
            name = self.store.get_value(it, 2)
            big = pix.scale_simple(900, 600, GdkPixbuf.InterpType.BILINEAR)
            FakeViewerWindow(self, name, big)
            return
        if not self.app.unlocked:
            self.show_unlock_dialog()
            return
        it = self.store.get_iter(path)
        entry_id = self.store.get_value(it, 0)
        entry_type = self.store.get_value(it, 3)
        mime = self.store.get_value(it, 4)
        if entry_type == "folder":
            self.current_parent = entry_id
            self.refresh()
            return
        entry = self.get_entry_by_id(entry_id)
        if mime.startswith("image/"):
            ids = [row[0] for row in self.store if row[3] == "file" and row[4].startswith("image/")]
            if entry_id in ids:
                ImageViewerWindow(self, ids, ids.index(entry_id))
        elif mime == "application/pdf" and HAS_POPPLER:
            PDFViewerWindow(self, entry)
        elif mime.startswith("video/") and HAS_GST:
            VideoPlayerWindow(self, entry)
        else:
            self.show_message("Vista previa no disponible para este tipo de archivo.")

    def on_listbox_row_activated(self, listbox, row):
        index = row.get_index()
        if index < len(self.store):
            path = Gtk.TreePath.new_from_indices([index])
            self.on_item_activated(None, path)

    def on_iconview_button_press(self, iconview, event):
        if self.fake_active():
            return False
        if event.button == 3:
            path = iconview.get_path_at_pos(int(event.x), int(event.y))
            if path:
                if not iconview.path_is_selected(path):
                    iconview.unselect_all()
                    iconview.select_path(path)
            else:
                iconview.unselect_all()
            self.show_context_menu(event)
            return True
        return False

    def on_listbox_button_press(self, listbox, event):
        if self.fake_active():
            return False
        if event.button == 3:
            self.show_context_menu(event)
            return True
        return False

    def show_context_menu(self, event):
        selected = self.get_selected_entries()
        menu = Gtk.Menu()
        copy_item = Gtk.MenuItem.new_with_label("Copiar")
        copy_item.set_sensitive(bool(selected))
        copy_item.connect("activate", lambda w: self.on_copy_selected())
        menu.append(copy_item)
        download_item = Gtk.MenuItem.new_with_label("Descargar")
        download_item.set_sensitive(bool(selected))
        download_item.connect("activate", lambda w: self.on_download_selected())
        menu.append(download_item)
        copy_path_item = Gtk.MenuItem.new_with_label("Copiar ruta")
        copy_path_item.set_sensitive(len(selected) == 1)
        copy_path_item.connect("activate", lambda w: self.on_copy_path())
        menu.append(copy_path_item)
        menu.append(Gtk.SeparatorMenuItem())
        rename_item = Gtk.MenuItem.new_with_label("Renombrar")
        rename_item.set_sensitive(len(selected) == 1)
        rename_item.connect("activate", lambda w: self.on_rename_selected())
        menu.append(rename_item)
        move_item = Gtk.MenuItem.new_with_label("Mover a carpeta")
        move_item.set_sensitive(bool(selected))
        move_item.connect("activate", lambda w: self.on_move_selected())
        menu.append(move_item)
        delete_item = Gtk.MenuItem.new_with_label("Eliminar")
        delete_item.set_sensitive(bool(selected))
        delete_item.connect("activate", lambda w: self.on_delete_selected())
        menu.append(delete_item)
        menu.append(Gtk.SeparatorMenuItem())
        if len(selected) == 1:
            entry = selected[0]
            fav_label = "Quitar de favoritos" if entry.get("favorite", False) else "Añadir a favoritos"
            fav_item = Gtk.MenuItem.new_with_label(fav_label)
            fav_item.connect("activate", lambda w: self.on_toggle_favorite(entry))
            menu.append(fav_item)
            pin_label = "Desfijar" if entry.get("pinned", False) else "Fijar con chincheta"
            pin_item = Gtk.MenuItem.new_with_label(pin_label)
            pin_item.connect("activate", lambda w: self.on_toggle_pin(entry))
            menu.append(pin_item)
            menu.append(Gtk.SeparatorMenuItem())
        new_folder_item = Gtk.MenuItem.new_with_label("Crear carpeta")
        new_folder_item.set_sensitive(self.app.unlocked)
        new_folder_item.connect("activate", lambda w: self.on_create_folder())
        menu.append(new_folder_item)
        props_item = Gtk.MenuItem.new_with_label("Propiedades")
        props_item.set_sensitive(len(selected) == 1)
        props_item.connect("activate", lambda w: self.on_properties_selected())
        menu.append(props_item)
        menu.show_all()
        menu.popup(None, None, None, None, event.button, event.time)

    def get_selected_entries(self):
        entries = []
        if self.fake_active():
            return entries
        for path in self.iconview.get_selected_items():
            it = self.store.get_iter(path)
            entry_id = self.store.get_value(it, 0)
            entry = self.get_entry_by_id(entry_id)
            if entry:
                entries.append(entry)
        return entries

    def on_toggle_favorite(self, entry):
        for e in self.app.entries:
            if e.get("id") == entry.get("id"):
                e["favorite"] = not e.get("favorite", False)
                break
        save_manifest(self.app.master_key, self.app.entries)
        self.refresh()

    def on_toggle_pin(self, entry):
        for e in self.app.entries:
            if e.get("id") == entry.get("id"):
                e["pinned"] = not e.get("pinned", False)
                break
        save_manifest(self.app.master_key, self.app.entries)
        self.refresh()

    def on_copy_selected(self):
        selected = self.get_selected_entries()
        if not selected:
            return
        copied = 0
        for entry in selected:
            if entry.get("type") != "file":
                continue
            try:
                old_path = files_dir() / f"{entry['id']}.bin"
                new_id = str(uuid.uuid4())
                new_path = files_dir() / f"{new_id}.bin"
                shutil.copy2(old_path, new_path)
                try:
                    os.chmod(new_path, 0o600)
                except OSError:
                    pass
                new_entry = entry.copy()
                new_entry["id"] = new_id
                new_entry["name"] = "Copia de " + entry.get("name", "archivo")
                new_entry["added"] = datetime.datetime.now().isoformat()
                self.app.entries.append(normalize_entry(new_entry))
                copied += 1
            except Exception as e:
                print(f"Error copiando {entry.get('id')}: {e}", file=sys.stderr)
        if copied:
            save_manifest(self.app.master_key, self.app.entries)
            self.refresh()
        self.show_message(f"Copiados {copied} archivo(s).")

    def export_entry(self, entry, dest_dir: Path) -> int:
        if entry.get("type") == "folder":
            folder_path = unique_path(dest_dir, entry.get("name", "carpeta"))
            folder_path.mkdir(parents=True, exist_ok=True)
            count = 0
            for child in self.get_direct_children(entry["id"]):
                count += self.export_entry(child, folder_path)
            return count
        else:
            data = self.app.decrypt_file(entry["id"])
            out = unique_path(dest_dir, entry.get("name", "archivo"))
            out.write_bytes(data)
            try:
                os.chmod(out, 0o600)
            except OSError:
                pass
            return 1

    def on_download_selected(self):
        selected = self.get_selected_entries()
        if not selected:
            self.show_message("Selecciona primero algún elemento.")
            return
        chooser = Gtk.FileChooserDialog(title="Exportar a carpeta", transient_for=self, action=Gtk.FileChooserAction.SELECT_FOLDER)
        chooser.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        chooser.add_button("Exportar", Gtk.ResponseType.ACCEPT)
        response = chooser.run()
        folder = chooser.get_filename() if response == Gtk.ResponseType.ACCEPT else None
        chooser.destroy()
        if response != Gtk.ResponseType.ACCEPT or not folder:
            return
        dest_dir = Path(folder)
        exported = 0
        for entry in selected:
            try:
                exported += self.export_entry(entry, dest_dir)
            except Exception as e:
                print(f"Error exportando {entry.get('id')}: {e}", file=sys.stderr)
        self.show_message(f"Exportados {exported} archivo(s).\nFuera de la bóveda ya no están protegidos.")

    def on_copy_path(self):
        selected = self.get_selected_entries()
        if len(selected) != 1:
            return
        path_text = "vault://" + self.build_vault_path(selected[0])
        clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        clipboard.set_text(path_text, -1)
        self.show_message(f"Ruta copiada:\n{path_text}")

    def on_rename_selected(self):
        selected = self.get_selected_entries()
        if len(selected) != 1:
            self.show_message("Selecciona un solo elemento para renombrar.")
            return
        entry = selected[0]
        ok, new_name = self.prompt_text("Renombrar", "Nuevo nombre:", entry.get("name", ""))
        if not ok or not new_name.strip():
            return
        for e in self.app.entries:
            if e.get("id") == entry.get("id"):
                e["name"] = new_name.strip()
                break
        save_manifest(self.app.master_key, self.app.entries)
        self.refresh()

    def delete_entry_id(self, entry_id):
        entry = self.get_entry_by_id(entry_id)
        if not entry:
            return
        if entry.get("type") == "folder":
            for child in self.get_direct_children(entry_id):
                self.delete_entry_id(child["id"])
        else:
            try:
                (files_dir() / f"{entry_id}.bin").unlink()
            except Exception:
                pass
        self.app.entries = [e for e in self.app.entries if e.get("id") != entry_id]

    def on_delete_clicked(self, widget=None):
        self.on_delete_selected()

    def on_delete_selected(self):
        selected = self.get_selected_entries()
        if not selected:
            return
        if not self.ask_yes_no(f"¿Eliminar {len(selected)} elemento(s)?\nLas carpetas se eliminan con su contenido."):
            return
        for entry in selected:
            self.delete_entry_id(entry["id"])
        if self.current_parent != "/" and not self.get_entry_by_id(self.current_parent):
            self.current_parent = "/"
        save_manifest(self.app.master_key, self.app.entries)
        self.refresh()

    def on_create_folder(self):
        if not self.ensure_unlocked():
            return
        ok, name = self.prompt_text("Crear carpeta", "Nombre de la carpeta:", "Nueva carpeta")
        if not ok or not name.strip():
            return
        entry = normalize_entry({"id": str(uuid.uuid4()), "type": "folder", "parent": self.current_parent, "name": name.strip(), "mime": "inode/directory", "size": 0, "added": datetime.datetime.now().isoformat()})
        self.app.entries.append(entry)
        save_manifest(self.app.master_key, self.app.entries)
        self.refresh()

    def choose_move_target(self, invalid_folder_ids):
        dialog = Gtk.Dialog(title="Mover a carpeta", transient_for=self, modal=True)
        dialog.set_resizable(False)
        box = dialog.get_content_area()
        box.set_border_width(12)
        box.set_spacing(8)
        combo = Gtk.ComboBoxText()
        choices = [("/", "Raíz")]
        for entry in self.app.entries:
            entry = normalize_entry(entry)
            if entry.get("type") != "folder":
                continue
            folder_id = entry.get("id")
            if folder_id in invalid_folder_ids:
                continue
            if self.is_descendant_of_any(folder_id, invalid_folder_ids):
                continue
            choices.append((folder_id, self.build_vault_path(entry)))
        for folder_id, name in choices:
            combo.append(folder_id, name)
        combo.set_active(0)
        box.add(Gtk.Label(label="Destino:"))
        box.add(combo)
        dialog.add_button("Cancelar", Gtk.ResponseType.CANCEL)
        dialog.add_button("Mover", Gtk.ResponseType.OK)
        dialog.set_default_response(Gtk.ResponseType.OK)
        dialog.show_all()
        response = dialog.run()
        active = combo.get_active_id()
        dialog.destroy()
        if response == Gtk.ResponseType.OK:
            return active
        return None

    def on_move_selected(self):
        selected = self.get_selected_entries()
        if not selected:
            return
        invalid_folder_ids = set()
        for entry in selected:
            if entry.get("type") == "folder":
                invalid_folder_ids.update(self.get_descendant_folder_ids(entry["id"]))
        target = self.choose_move_target(invalid_folder_ids)
        if target is None:
            return
        for entry in selected:
            for e in self.app.entries:
                if e.get("id") == entry.get("id"):
                    e["parent"] = target
                    break
        save_manifest(self.app.master_key, self.app.entries)
        if self.current_parent != "/" and not self.get_entry_by_id(self.current_parent):
            self.current_parent = "/"
        self.refresh()

    def on_drag_data_get(self, widget, context, data, info, time):
        selected = self.get_selected_entries()
        if selected:
            ids = ",".join([e["id"] for e in selected])
            data.set_text(ids, -1)

    def on_drag_data_received(self, widget, context, x, y, data, info, time):
        if self.fake_active() or not self.app.unlocked:
            return
        text = data.get_text()
        if not text:
            return
        ids = text.split(",")
        path = self.iconview.get_path_at_pos(int(x), int(y))
        if not path:
            return
        it = self.store.get_iter(path)
        target_id = self.store.get_value(it, 0)
        target_type = self.store.get_value(it, 3)
        if target_type != "folder":
            return
        for eid in ids:
            for e in self.app.entries:
                if e.get("id") == eid:
                    e["parent"] = target_id
                    break
        save_manifest(self.app.master_key, self.app.entries)
        self.refresh()

    def on_properties_selected(self):
        selected = self.get_selected_entries()
        if len(selected) != 1:
            return
        entry = selected[0]
        entry_type = "Carpeta" if entry.get("type") == "folder" else "Archivo"
        size = self.calculate_size(entry.get("id"))
        size_text = f"{size} bytes"
        if size > 1024 * 1024:
            size_text = f"{size / (1024*1024):.2f} MB"
        elif size > 1024:
            size_text = f"{size / 1024:.2f} KB"
        text = f"""
Nombre: {entry.get('name', '')}
Tipo: {entry_type}
MIME: {entry.get('mime', '')}
Tamaño: {size_text}
Ruta: vault://{self.build_vault_path(entry)}
ID: {entry.get('id', '')}
Añadido: {entry.get('added', '')}
Favorito: {'Sí' if entry.get('favorite', False) else 'No'}
Fijado: {'Sí' if entry.get('pinned', False) else 'No'}
"""
        self.show_message(text.strip())


class VaultApp(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="org.example.visornotas", flags=Gio.ApplicationFlags.FLAGS_NONE)
        self.master_key = None
        self.entries = []
        self.unlocked = False

    def do_activate(self):
        ensure_dirs()
        apply_theme()
        self.win = MainWindow(self)
        self.add_window(self.win)
        self.win.show_all()

    def unlock(self, master_key: bytes, entries):
        self.master_key = master_key
        self.entries = [normalize_entry(e) for e in entries]
        self.unlocked = True

    def lock(self):
        self.master_key = None
        self.entries = []
        self.unlocked = False

    def decrypt_file(self, entry_id: str) -> bytes:
        return decrypt_file(self.master_key, entry_id)


if __name__ == "__main__":
    app = VaultApp()
    sys.exit(app.run(sys.argv))
