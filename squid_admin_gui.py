#!/usr/bin/env python3
import os
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext
from pathlib import Path
import shutil
import threading
import time

# ---------- Configuration (paths) ----------
SQUID_DIR = Path("/etc/squid")
PASSWORDS = SQUID_DIR / "passwords"
BLOCKLIST_GLOBAL = SQUID_DIR / "blocklist_global.txt"
USERS_RULES_DIR = SQUID_DIR / "users_rules"
ACCESS_LOG = Path("/var/log/squid/access.log")
HTPASSWD_CMD = shutil.which("htpasswd") or "/usr/bin/htpasswd"
SYSTEMCTL = shutil.which("systemctl") or "/bin/systemctl"

# ---------- UI Style ----------
COLORS = {
    'primary': '#2c3e50',
    'secondary': '#34495e',
    'accent': '#3498db',
    'success': '#27ae60',
    'warning': '#f39c12',
    'danger': '#e74c3c',
    'light': '#ecf0f1',
    'dark': '#2c3e50',
    'text_light': '#ffffff',
    'text_dark': '#2c3e50'
}

FONTS = {
    'title': ('Segoe UI', 14, 'bold'),
    'heading': ('Segoe UI', 12, 'bold'),
    'normal': ('Segoe UI', 10),
    'small': ('Segoe UI', 9)
}

# ---------- Helpers ----------
def run_cmd(cmd):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True, text=True)
        return out.strip()
    except subprocess.CalledProcessError as e:
        return f"ERROR: {e.output.strip()}"

def ensure_structure():
    SQUID_DIR.mkdir(parents=True, exist_ok=True)
    USERS_RULES_DIR.mkdir(parents=True, exist_ok=True)
    if not BLOCKLIST_GLOBAL.exists():
        BLOCKLIST_GLOBAL.write_text("# global blocklist - one domain per line\n")
    if not PASSWORDS.exists():
        PASSWORDS.write_text("")  # htpasswd will write when needed
    # Ensure ownership/permissions so Squid can read includes
    try:
        run_cmd(f"sudo chown -R root:root {USERS_RULES_DIR}")
        run_cmd(f"sudo chmod 755 {USERS_RULES_DIR}")
    except Exception:
        pass

def restart_squid_action():
    return run_cmd(f"sudo {SYSTEMCTL} restart squid")

def reload_squid_action():
    return run_cmd(f"sudo {SYSTEMCTL} reload squid || sudo {SYSTEMCTL} restart squid")

def status_squid_action():
    return run_cmd(f"{SYSTEMCTL} is-active squid")

def tail_log(lines=50):
    if not ACCESS_LOG.exists():
        return "No access.log found."
    return run_cmd(f"tail -n {lines} {ACCESS_LOG}")

# ---------- Password & user helpers ----------
def add_user(username, password):
    if " " in username:
        return "ERREUR: les espaces ne sont pas autorisés dans le nom d'utilisateur."
    cmd = f"sudo {HTPASSWD_CMD} -b {PASSWORDS} {username} {password}"
    out = run_cmd(cmd)
    # create per-user files & conf if needed
    ensure_user_rulefile(username)
    ensure_user_conf(username)
    reload_squid_action()
    return out

def delete_user(username):
    cmd = f"sudo {HTPASSWD_CMD} -D {PASSWORDS} {username}"
    out = run_cmd(cmd)
    userfile = USERS_RULES_DIR / f"{username}.txt"
    userconf = USERS_RULES_DIR / f"{username}.conf"
    if userfile.exists():
        try:
            userfile.unlink()
        except Exception:
            pass
    if userconf.exists():
        try:
            userconf.unlink()
        except Exception:
            pass
    reload_squid_action()
    return out

def list_users():
    if not PASSWORDS.exists():
        return []
    with PASSWORDS.open("r") as f:
        lines = [l for l in f.readlines() if ":" in l]
    users = [ln.split(":")[0].strip() for ln in lines if ln.strip()]
    return users

# ---------- Blocklists ----------
def add_global_block(domain):
    with BLOCKLIST_GLOBAL.open("a") as f:
        if not domain.startswith("."):
            domain = "." + domain
        f.write(domain + "\n")
    reload_squid_action()
    return "ok"

def remove_global_block(domain):
    if not BLOCKLIST_GLOBAL.exists():
        return "no file"
    lines = BLOCKLIST_GLOBAL.read_text().splitlines()
    new = [l for l in lines if domain not in l]
    BLOCKLIST_GLOBAL.write_text("\n".join(new) + ("\n" if new else ""))
    reload_squid_action()
    return "ok"

def list_global_blocks():
    return BLOCKLIST_GLOBAL.read_text()

# ---------- Per-user rules helpers ----------
def ensure_user_rulefile(username):
    uf = USERS_RULES_DIR / f"{username}.txt"
    if not uf.exists():
        uf.write_text("# user-specific blocked domains\n")
    return uf

def ensure_user_conf(username):
    """
    Create or remove a per-user squid include .conf depending on whether
    the corresponding <username>.txt contains rules.
    """
    rules_file = USERS_RULES_DIR / f"{username}.txt"
    conf_file = USERS_RULES_DIR / f"{username}.conf"

    # If no rules or very small file -> remove conf and return
    try:
        if not rules_file.exists() or rules_file.stat().st_size < 4:
            if conf_file.exists():
                conf_file.unlink()
            return None
    except Exception:
        if conf_file.exists():
            conf_file.unlink()
        return None

    # Create valid conf
    content = (
        f"acl {username} proxy_auth {username}\n"
        f"acl {username}_sites dstdomain \"{rules_file}\"\n"
        f"http_access deny {username} {username}_sites\n"
    )
    conf_file.write_text(content)
    try:
        run_cmd(f"sudo chown root:root {conf_file}")
        run_cmd(f"sudo chmod 644 {conf_file}")
    except Exception:
        pass
    return conf_file

def add_user_block(username, domain):
    uf = ensure_user_rulefile(username)
    if not domain.startswith("."):
        domain = "." + domain
    with uf.open("a") as f:
        f.write(domain + "\n")
    ensure_user_conf(username)
    reload_squid_action()
    return "ok"

def remove_user_block(username, domain):
    uf = USERS_RULES_DIR / f"{username}.txt"
    if not uf.exists():
        return "no file"
    lines = uf.read_text().splitlines()
    new = [l for l in lines if domain not in l]
    uf.write_text("\n".join(new) + ("\n" if new else ""))
    ensure_user_conf(username)
    reload_squid_action()
    return "ok"

def list_user_blocks(username):
    uf = USERS_RULES_DIR / f"{username}.txt"
    if not uf.exists():
        return ""
    return uf.read_text()

# ---------- GUI widgets ----------
class CardFrame(ttk.Frame):
    def __init__(self, parent, title="", **kwargs):
        super().__init__(parent, **kwargs)
        style = ttk.Style()
        style.configure("Card.TFrame", background=COLORS['light'],
                        relief="raised", borderwidth=1)
        if title:
            title_frame = ttk.Frame(self)
            title_frame.pack(fill="x", padx=5, pady=(5, 0))
            title_label = tk.Label(title_frame, text=title, font=FONTS['heading'],
                                   bg=COLORS['light'], fg=COLORS['dark'])
            title_label.pack(anchor="w", padx=5, pady=5)

class HeaderFrame(ttk.Frame):
    def __init__(self, parent, title, subtitle=""):
        super().__init__(parent)
        style = ttk.Style()
        style.configure("Header.TFrame", background=COLORS['primary'])
        title_label = tk.Label(self, text=title, font=FONTS['title'],
                              bg=COLORS['primary'], fg=COLORS['text_light'])
        title_label.pack(side="left", padx=10, pady=8)
        if subtitle:
            subtitle_label = tk.Label(self, text=subtitle, font=FONTS['small'],
                                     bg=COLORS['primary'], fg=COLORS['light'])
            subtitle_label.pack(side="left", padx=10, pady=8)

# ---------- Main Application ----------
class SquidAdminApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Squid Proxy Admin")
        self.geometry("1000x700")
        self.configure(bg=COLORS['light'])

        ensure_structure()
        self.create_widgets()

    def create_widgets(self):
        header = HeaderFrame(self, "Squid Proxy Administrator", "Interface de gestion graphique")
        header.pack(fill="x", padx=0, pady=(0, 8))

        # status bar must be created early
        self.status_bar = tk.Label(self, text="Prêt", bd=0, anchor="w",
                                   font=FONTS['small'], bg=COLORS['secondary'],
                                   fg=COLORS['text_light'], height=1)
        self.status_bar.pack(side="bottom", fill="x")

        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        nb = ttk.Notebook(main_frame)
        nb.pack(fill="both", expand=True)

        # tabs
        t_users = ttk.Frame(nb); self.build_users_tab(t_users); nb.add(t_users, text="Utilisateurs")
        t_global = ttk.Frame(nb); self.build_global_tab(t_global); nb.add(t_global, text="Global")
        t_peruser = ttk.Frame(nb); self.build_peruser_tab(t_peruser); nb.add(t_peruser, text="Par utilisateur")
        t_logs = ttk.Frame(nb); self.build_logs_tab(t_logs); nb.add(t_logs, text="Logs")
        t_ctrl = ttk.Frame(nb); self.build_control_tab(t_ctrl); nb.add(t_ctrl, text="Contrôle")

    def update_status(self, message):
        try:
            self.status_bar.config(text=message)
            self.after(3000, lambda: self.status_bar.config(text="Prêt"))
        except Exception:
            pass

    # Users tab
    def build_users_tab(self, frame):
        card = CardFrame(frame, "Gestion des utilisateurs")
        card.pack(fill="both", expand=True, padx=5, pady=5)

        btn_card = CardFrame(card, "Actions")
        btn_card.pack(fill="x", padx=10, pady=10)
        btn_frame = ttk.Frame(btn_card); btn_frame.pack(fill="x", padx=10, pady=6)

        ttk.Button(btn_frame, text="Ajouter utilisateur", command=self.add_user_dialog).grid(row=0, column=0, padx=6, pady=6)
        ttk.Button(btn_frame, text="Supprimer utilisateur", command=self.del_user_dialog).grid(row=0, column=1, padx=6, pady=6)
        ttk.Button(btn_frame, text="Actualiser", command=self.refresh_user_list).grid(row=0, column=2, padx=6, pady=6)

        list_card = CardFrame(card, "Utilisateurs existants")
        list_card.pack(fill="both", expand=True, padx=10, pady=10)
        self.user_listbox = tk.Listbox(list_card, height=12)
        self.user_listbox.pack(fill="both", padx=6, pady=6, expand=True)
        self.refresh_user_list()

    def add_user_dialog(self):
        u = simpledialog.askstring("Ajouter Utilisateur", "Nom d'utilisateur:")
        if not u:
            return
        if " " in u:
            messagebox.showerror("Erreur", "Les espaces ne sont pas autorisés dans les noms d'utilisateur.")
            return
        p = simpledialog.askstring("Mot de passe", f"Mot de passe pour {u}:", show="*")
        if p is None:
            return
        self.update_status(f"Ajout de {u}...")
        out = add_user(u, p)
        messagebox.showinfo("Résultat", out)
        self.refresh_user_list()
        self.update_status(f"Utilisateur {u} ajouté")

    def del_user_dialog(self):
        sel = self.user_listbox.curselection()
        if sel:
            username = self.user_listbox.get(sel[0]).lstrip("👤 ").strip()
        else:
            username = simpledialog.askstring("Supprimer Utilisateur", "Nom d'utilisateur à supprimer:")
        if not username:
            return
        if messagebox.askyesno("Confirmation", f"Supprimer l'utilisateur '{username}' ?"):
            self.update_status(f"Suppression de {username}...")
            out = delete_user(username)
            messagebox.showinfo("Résultat", out)
            self.refresh_user_list()
            self.update_status(f"Utilisateur {username} supprimé")

    def refresh_user_list(self):
        self.user_listbox.delete(0, tk.END)
        users = list_users()
        for u in users:
            self.user_listbox.insert(tk.END, f"👤 {u}")
        self.update_status(f"{len(users)} utilisateur(s) trouvé(s)")

    # Global tab
    def build_global_tab(self, frame):
        card = CardFrame(frame, "Règles globales")
        card.pack(fill="both", expand=True, padx=5, pady=5)
        btn_frame = ttk.Frame(card); btn_frame.pack(fill="x", padx=10, pady=6)
        ttk.Button(btn_frame, text="Afficher", command=self.show_global_list).grid(row=0, column=0, padx=6, pady=6)
        ttk.Button(btn_frame, text="Ajouter", command=self.add_global_dialog).grid(row=0, column=1, padx=6, pady=6)
        ttk.Button(btn_frame, text="Supprimer", command=self.remove_global_dialog).grid(row=0, column=2, padx=6, pady=6)
        self.global_text = scrolledtext.ScrolledText(card, height=12)
        self.global_text.pack(fill="both", padx=10, pady=8, expand=True)

    def show_global_list(self):
        self.global_text.delete("1.0", tk.END)
        content = list_global_blocks()
        if not content.strip():
            content = "Aucune règle globale"
        self.global_text.insert(tk.END, content)
        self.update_status("Règles globales affichées")

    def add_global_dialog(self):
        d = simpledialog.askstring("Ajouter Domaine Global", "Domaine à bloquer (ex: facebook.com):")
        if not d:
            return
        add_global_block(d.strip())
        messagebox.showinfo("Succès", f"{d} ajouté")
        self.show_global_list()

    def remove_global_dialog(self):
        d = simpledialog.askstring("Supprimer Domaine Global", "Domaine à retirer (ex: facebook.com):")
        if not d:
            return
        remove_global_block(d.strip())
        messagebox.showinfo("Succès", f"{d} retiré")
        self.show_global_list()

    # Per-user tab
    def build_peruser_tab(self, frame):
        card = CardFrame(frame, "Règles par utilisateur")
        card.pack(fill="both", expand=True, padx=5, pady=5)
        controls = ttk.Frame(card); controls.pack(fill="x", padx=10, pady=6)
        ttk.Label(controls, text="Utilisateur:", font=FONTS['normal']).grid(row=0, column=0, padx=6)
        self.user_combo = ttk.Combobox(controls, values=[], width=20)
        self.user_combo.grid(row=0, column=1, padx=6)
        ttk.Button(controls, text="Charger", command=self.populate_user_dropdown).grid(row=0, column=2, padx=6)
        ttk.Button(controls, text="Afficher", command=self.show_user_rules).grid(row=0, column=3, padx=6)
        actions = ttk.Frame(card); actions.pack(fill="x", padx=10, pady=6)
        ttk.Button(actions, text="Ajouter Domaine", command=self.add_user_block_dialog).grid(row=0, column=0, padx=6, pady=6)
        ttk.Button(actions, text="Supprimer Domaine", command=self.remove_user_block_dialog).grid(row=0, column=1, padx=6, pady=6)
        self.userrules_text = scrolledtext.ScrolledText(card, height=12)
        self.userrules_text.pack(fill="both", padx=10, pady=8, expand=True)
        self.populate_user_dropdown()

    def populate_user_dropdown(self):
        users = list_users()
        self.user_combo.config(values=users)
        if users:
            self.user_combo.set(users[0])
        self.update_status(f"{len(users)} utilisateur(s) chargé(s)")

    def show_user_rules(self):
        u = self.user_combo.get()
        if not u:
            messagebox.showwarning("Aucun utilisateur", "Sélectionnez un utilisateur")
            return
        txt = list_user_blocks(u)
        self.userrules_text.delete("1.0", tk.END)
        self.userrules_text.insert(tk.END, txt if txt.strip() else "Aucune règle définie")
        self.update_status(f"Règles affichées pour {u}")

    def add_user_block_dialog(self):
        u = self.user_combo.get()
        if not u:
            messagebox.showwarning("Aucun utilisateur", "Sélectionnez un utilisateur")
            return
        d = simpledialog.askstring("Ajouter Domaine", f"Domaine à bloquer pour {u} (ex: facebook.com):")
        if not d:
            return
        add_user_block(u, d.strip())
        messagebox.showinfo("Succès", f"{d} ajouté pour {u}")
        self.show_user_rules()

    def remove_user_block_dialog(self):
        u = self.user_combo.get()
        if not u:
            messagebox.showwarning("Aucun utilisateur", "Sélectionnez un utilisateur")
            return
        d = simpledialog.askstring("Supprimer Domaine", f"Domaine à retirer pour {u}:")
        if not d:
            return
        remove_user_block(u, d.strip())
        messagebox.showinfo("Succès", f"{d} retiré pour {u}")
        self.show_user_rules()

    # Logs tab
    def build_logs_tab(self, frame):
        card = CardFrame(frame, "Logs")
        card.pack(fill="both", expand=True, padx=5, pady=5)
        btns = ttk.Frame(card); btns.pack(fill="x", padx=10, pady=6)
        ttk.Button(btns, text="Afficher 50 dernières", command=self.show_logs).grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="Start live", command=self.start_log_stream).grid(row=0, column=1, padx=6)
        ttk.Button(btns, text="Stop live", command=self.stop_log_stream).grid(row=0, column=2, padx=6)
        self.log_text = scrolledtext.ScrolledText(card, height=16, font=('Consolas',9))
        self.log_text.pack(fill="both", padx=10, pady=8, expand=True)
        self._streaming = False

    def show_logs(self):
        out = tail_log(50)
        self.log_text.delete("1.0", tk.END)
        self.log_text.insert(tk.END, out)
        self.update_status("Logs affichés")

    def start_log_stream(self):
        if self._streaming:
            return
        self._streaming = True
        threading.Thread(target=self._stream_logs, daemon=True).start()
        self.update_status("Surveillance démarrée")

    def stop_log_stream(self):
        self._streaming = False
        self.update_status("Surveillance arrêtée")

    def _stream_logs(self):
        last = ""
        while self._streaming:
            out = tail_log(50)
            if out != last:
                self.log_text.delete("1.0", tk.END)
                self.log_text.insert(tk.END, out)
                last = out
                self.log_text.see(tk.END)
            time.sleep(2)

    # Control tab
    def build_control_tab(self, frame):
        card = CardFrame(frame, "Contrôle Squid")
        card.pack(fill="both", expand=True, padx=5, pady=5)
        btns = ttk.Frame(card); btns.pack(fill="x", padx=10, pady=6)
        ttk.Button(btns, text="Redémarrer Squid", command=self.restart_squid_gui).grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="Statut Squid", command=self.status_squid_gui).grid(row=0, column=1, padx=6)
        ttk.Button(btns, text="Vider cache", command=self.purge_cache).grid(row=0, column=2, padx=6)
        ttk.Button(btns, text="Recharger config", command=self.reload_squid).grid(row=0, column=3, padx=6)
        self.ctrl_text = scrolledtext.ScrolledText(card, height=12, font=('Consolas',9))
        self.ctrl_text.pack(fill="both", padx=10, pady=8, expand=True)

    def restart_squid_gui(self):
        self.update_status("Redémarrage Squid...")
        out = restart_squid_action()
        self.ctrl_text.insert(tk.END, f"{out}\n")
        self.ctrl_text.see(tk.END)
        self.update_status("Squid redémarré")

    def status_squid_gui(self):
        out = status_squid_action()
        self.ctrl_text.insert(tk.END, f"{out}\n")
        self.ctrl_text.see(tk.END)

    def purge_cache(self):
        out = run_cmd("sudo squid -k rotate || true")
        self.ctrl_text.insert(tk.END, f"{out}\n")
        self.ctrl_text.see(tk.END)

    def reload_squid(self):
        out = reload_squid_action()
        self.ctrl_text.insert(tk.END, f"{out}\n")
        self.ctrl_text.see(tk.END)

# ---------- Main ----------
if __name__ == "__main__":
    if os.geteuid() != 0:
        try:
            root = tk.Tk()
            root.withdraw()
            answer = messagebox.askyesno("Privilegès root", "Ce programme doit être lancé en root (sudo). Continuer quand même ?")
            root.destroy()
            if not answer:
                exit()
        except Exception:
            print("Warning: run as root (sudo) recommended.")
    app = SquidAdminApp()
    app.mainloop()
