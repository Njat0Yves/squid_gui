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

# ---------- Style Configuration ----------
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
def ensure_structure():
    SQUID_DIR.mkdir(parents=True, exist_ok=True)
    USERS_RULES_DIR.mkdir(parents=True, exist_ok=True)
    if not BLOCKLIST_GLOBAL.exists():
        BLOCKLIST_GLOBAL.write_text("# global blocklist - one domain per line\n")
    if not PASSWORDS.exists():
        PASSWORDS.write_text("")  # htpasswd will write when needed

def run_cmd(cmd):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True, text=True)
        return out.strip()
    except subprocess.CalledProcessError as e:
        return f"ERROR: {e.output.strip()}"

def restart_squid_action():
    out = run_cmd(f"sudo {SYSTEMCTL} restart squid")
    return out

def reload_squid_action():
    out = run_cmd(f"sudo {SYSTEMCTL} reload squid || sudo {SYSTEMCTL} restart squid")
    return out

def status_squid_action():
    return run_cmd(f"{SYSTEMCTL} is-active squid")

def tail_log(lines=50):
    if not ACCESS_LOG.exists():
        return "No access.log found."
    return run_cmd(f"tail -n {lines} {ACCESS_LOG}")

def ensure_user_rulefile(username):
    uf = USERS_RULES_DIR / f"{username}.txt"
    if not uf.exists():
        uf.write_text("# user-specific blocked domains\n")
    return uf

def ensure_user_conf(username):
    """
    Create a per-user squid include .conf that tells Squid to deny
    the domains listed in users_rules/<username>.txt for that user.
    """
    conf_file = USERS_RULES_DIR / f"{username}.conf"
    rules_file = USERS_RULES_DIR / f"{username}.txt"
    content = (
        f"acl {username} proxy_auth {username}\n"
        f"acl {username}_sites dstdomain \"{rules_file}\"\n"
        f"http_access deny {username} {username}_sites\n"
    )
    conf_file.write_text(content)
    # ensure ownership/permissions (optional but recommended)
    try:
        run_cmd(f"sudo chown root:root {conf_file}")
        run_cmd(f"sudo chmod 644 {conf_file}")
    except Exception:
        pass
    return conf_file

def add_user(username, password):
    # create user with htpasswd (-b to pass password)
    cmd = f"sudo {HTPASSWD_CMD} -b {PASSWORDS} {username} {password}"
    out = run_cmd(cmd)
    # create per-user files
    ensure_user_rulefile(username)
    ensure_user_conf(username)
    # reload squid to take new ACL into account
    reload_squid_action()
    return out

def delete_user(username):
    # use htpasswd -D
    cmd = f"sudo {HTPASSWD_CMD} -D {PASSWORDS} {username}"
    out = run_cmd(cmd)
    # remove per-user rules files if exist
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
    # reload squid to remove rules
    reload_squid_action()
    return out

def list_users():
    if not PASSWORDS.exists():
        return []
    with PASSWORDS.open("r") as f:
        lines = [l for l in f.readlines() if ":" in l]
    users = [ln.split(":")[0].strip() for ln in lines if ln.strip()]
    return users

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

def add_user_block(username, domain):
    uf = ensure_user_rulefile(username)
    if not domain.startswith("."):
        domain = "." + domain
    with uf.open("a") as f:
        f.write(domain + "\n")
    # ensure the per-user .conf exists so Squid applies it
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
    # update the conf (not strictly necessary but safe)
    ensure_user_conf(username)
    reload_squid_action()
    return "ok"

def list_user_blocks(username):
    uf = USERS_RULES_DIR / f"{username}.txt"
    if not uf.exists():
        return ""
    return uf.read_text()

# ---------- Modern GUI Components ----------
class HeaderFrame(ttk.Frame):
    def __init__(self, parent, title, subtitle=""):
        super().__init__(parent)
        self.configure(style="Header.TFrame")
        style = ttk.Style()
        style.configure("Header.TFrame", background=COLORS['primary'])
        
        title_label = tk.Label(self, text=title, font=FONTS['title'],
                              bg=COLORS['primary'], fg=COLORS['text_light'])
        title_label.pack(side="left", padx=10, pady=8)
        
        if subtitle:
            subtitle_label = tk.Label(self, text=subtitle, font=FONTS['small'],
                                    bg=COLORS['primary'], fg=COLORS['light'])
            subtitle_label.pack(side="left", padx=10, pady=8)

class CardFrame(ttk.Frame):
    def __init__(self, parent, title="", **kwargs):
        super().__init__(parent, **kwargs)
        self.configure(style="Card.TFrame")
        
        if title:
            title_frame = ttk.Frame(self, style="Card.TFrame")
            title_frame.pack(fill="x", padx=5, pady=(5, 0))
            
            title_label = tk.Label(title_frame, text=title, font=FONTS['heading'],
                                  bg=COLORS['light'], fg=COLORS['dark'])
            title_label.pack(anchor="w", padx=5, pady=5)

# ---------- Main Application ----------
class SquidAdminApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Squid Proxy Admin - Interface de Gestion")
        self.geometry("1000x700")
        self.configure(bg=COLORS['light'])
        
        # Configure styles
        self.configure_styles()
        ensure_structure()
        
        # Create status bar first
        self.status_bar = tk.Label(self, text="Prêt", bd=1, relief="sunken", 
                                  anchor="w", font=FONTS['small'],
                                  bg=COLORS['secondary'], fg=COLORS['text_light'])
        self.status_bar.pack(side="bottom", fill="x")
        
        self.create_widgets()

    def configure_styles(self):
        style = ttk.Style()
        
        # Configure notebook style
        style.configure("TNotebook", background=COLORS['light'])
        style.configure("TNotebook.Tab", 
                       font=FONTS['normal'],
                       padding=(15, 8),
                       background=COLORS['light'],
                       foreground=COLORS['dark'])
        style.map("TNotebook.Tab",
                 background=[('selected', COLORS['accent'])],
                 foreground=[('selected', COLORS['text_light'])])

        # Configure frame styles
        style.configure("TFrame", background=COLORS['light'])
        style.configure("Header.TFrame", background=COLORS['primary'])
        style.configure("Card.TFrame", background=COLORS['light'], relief="raised", borderwidth=1)
        
        # Configure button styles
        style.configure("Accent.TButton",
                       padding=(12, 6),
                       background=COLORS['accent'],
                       foreground=COLORS['text_light'],
                       font=FONTS['normal'])
        style.map("Accent.TButton",
                 background=[('active', COLORS['primary']),
                           ('pressed', COLORS['secondary'])])

    def create_widgets(self):
        # Header
        header = HeaderFrame(self, "Squid Proxy Administrator", "Interface de gestion graphique")
        header.pack(fill="x", padx=0, pady=(0, 10))
        
        # Main notebook
        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        nb = ttk.Notebook(main_frame)
        nb.pack(fill="both", expand=True)

        # Users tab
        t_users = ttk.Frame(nb)
        self.build_users_tab(t_users)
        nb.add(t_users, text="👥 Utilisateurs")

        # Global rules tab
        t_global = ttk.Frame(nb)
        self.build_global_tab(t_global)
        nb.add(t_global, text="🌐 Règles Globales")

        # Per-user rules
        t_peruser = ttk.Frame(nb)
        self.build_peruser_tab(t_peruser)
        nb.add(t_peruser, text="🔒 Règles par Utilisateur")

        # Logs tab
        t_logs = ttk.Frame(nb)
        self.build_logs_tab(t_logs)
        nb.add(t_logs, text="📊 Logs & Monitoring")

        # Control tab
        t_ctrl = ttk.Frame(nb)
        self.build_control_tab(t_ctrl)
        nb.add(t_ctrl, text="⚙️ Contrôle Proxy")

    def update_status(self, message):
        self.status_bar.config(text=message)
        self.after(3000, lambda: self.status_bar.config(text="Prêt"))

    # ------------ Users Tab ------------
    def build_users_tab(self, frame):
        # Main card
        card = CardFrame(frame, "Gestion des Utilisateurs")
        card.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Button panel
        btn_card = CardFrame(card, "Actions")
        btn_card.pack(fill="x", padx=10, pady=10)
        
        btn_frame = ttk.Frame(btn_card)
        btn_frame.pack(fill="x", padx=10, pady=10)

        ttk.Button(btn_frame, text="➕ Ajouter Utilisateur", 
                  command=self.add_user_dialog, style="Accent.TButton").grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(btn_frame, text="🗑️ Supprimer Utilisateur", 
                  command=self.del_user_dialog, style="Accent.TButton").grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(btn_frame, text="🔄 Actualiser la Liste", 
                  command=self.refresh_user_list, style="Accent.TButton").grid(row=0, column=2, padx=5, pady=5)

        # List panel
        list_card = CardFrame(card, "Utilisateurs Existants")
        list_card.pack(fill="both", expand=True, padx=10, pady=10)
        
        list_frame = ttk.Frame(list_card)
        list_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Add scrollbar to listbox
        listbox_frame = ttk.Frame(list_frame)
        listbox_frame.pack(fill="both", expand=True)
        
        scrollbar = ttk.Scrollbar(listbox_frame)
        scrollbar.pack(side="right", fill="y")
        
        self.user_listbox = tk.Listbox(listbox_frame, yscrollcommand=scrollbar.set,
                                      font=FONTS['normal'], bg="white", relief="flat")
        self.user_listbox.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.user_listbox.yview)
        
        self.refresh_user_list()

    def add_user_dialog(self):
        u = simpledialog.askstring("Ajouter Utilisateur", "Nom d'utilisateur:")
        if not u:
            return
        p = simpledialog.askstring("Mot de passe", f"Mot de passe pour {u}:", show="*")
        if p is None:
            return
        self.update_status(f"Ajout de l'utilisateur {u}...")
        out = add_user(u, p)
        messagebox.showinfo("Résultat", out)
        self.refresh_user_list()
        self.update_status(f"Utilisateur {u} ajouté avec succès")

    def del_user_dialog(self):
        sel = self.user_listbox.curselection()
        if sel:
            username = self.user_listbox.get(sel[0])
            # Remove the emoji prefix if present
            if " " in username:
                username = username.split(" ", 1)[1]
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

    # ------------ Global Tab ------------
    def build_global_tab(self, frame):
        card = CardFrame(frame, "Règles de Blocage Globales")
        card.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Button panel
        btn_card = CardFrame(card, "Actions")
        btn_card.pack(fill="x", padx=10, pady=10)
        
        btn_frame = ttk.Frame(btn_card)
        btn_frame.pack(fill="x", padx=10, pady=10)

        ttk.Button(btn_frame, text="📋 Afficher Règles", 
                  command=self.show_global_list, style="Accent.TButton").grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(btn_frame, text="➕ Ajouter Domaine", 
                  command=self.add_global_dialog, style="Accent.TButton").grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(btn_frame, text="🗑️ Supprimer Domaine", 
                  command=self.remove_global_dialog, style="Accent.TButton").grid(row=0, column=2, padx=5, pady=5)

        # Text area
        text_card = CardFrame(card, "Domaines Bloqués Globalement")
        text_card.pack(fill="both", expand=True, padx=10, pady=10)
        
        text_frame = ttk.Frame(text_card)
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.global_text = scrolledtext.ScrolledText(text_frame, height=15, font=FONTS['normal'])
        self.global_text.pack(fill="both", expand=True)

    def show_global_list(self):
        self.global_text.delete("1.0", tk.END)
        content = list_global_blocks()
        if not content.strip():
            content = "Aucune règle globale définie"
        self.global_text.insert(tk.END, content)
        self.update_status("Règles globales affichées")

    def add_global_dialog(self):
        d = simpledialog.askstring("Ajouter Domaine Global", "Domaine à bloquer (ex: facebook.com):")
        if not d:
            return
        self.update_status(f"Ajout du domaine {d} aux règles globales...")
        add_global_block(d.strip())
        messagebox.showinfo("Succès", f"Le domaine '{d}' a été ajouté aux règles globales")
        self.show_global_list()
        self.update_status(f"Domaine {d} bloqué globalement")

    def remove_global_dialog(self):
        d = simpledialog.askstring("Supprimer Domaine Global", "Domaine à retirer (ex: facebook.com):")
        if not d:
            return
        self.update_status(f"Retrait du domaine {d} des règles globales...")
        remove_global_block(d.strip())
        messagebox.showinfo("Succès", f"Le domaine '{d}' a été retiré des règles globales")
        self.show_global_list()
        self.update_status(f"Domaine {d} retiré des règles globales")

    # ------------ Per-user Tab ------------
    def build_peruser_tab(self, frame):
        card = CardFrame(frame, "Règles de Blocage par Utilisateur")
        card.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Controls panel
        controls_card = CardFrame(card, "Sélection et Actions")
        controls_card.pack(fill="x", padx=10, pady=10)
        
        controls_frame = ttk.Frame(controls_card)
        controls_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Label(controls_frame, text="Utilisateur:", font=FONTS['normal']).grid(row=0, column=0, padx=5, pady=5)
        
        self.user_combo = ttk.Combobox(controls_frame, values=[], font=FONTS['normal'], width=20)
        self.user_combo.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(controls_frame, text="🔄 Charger", 
                  command=self.populate_user_dropdown, style="Accent.TButton").grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(controls_frame, text="📋 Afficher Règles", 
                  command=self.show_user_rules, style="Accent.TButton").grid(row=0, column=3, padx=5, pady=5)

        # Actions panel
        actions_card = CardFrame(card, "Gestion des Règles")
        actions_card.pack(fill="x", padx=10, pady=10)
        
        actions_frame = ttk.Frame(actions_card)
        actions_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Button(actions_frame, text="➕ Ajouter Domaine", 
                  command=self.add_user_block_dialog, style="Accent.TButton").grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(actions_frame, text="🗑️ Supprimer Domaine", 
                  command=self.remove_user_block_dialog, style="Accent.TButton").grid(row=0, column=1, padx=5, pady=5)

        # Text area
        text_card = CardFrame(card, "Domaines Bloqués pour l'Utilisateur")
        text_card.pack(fill="both", expand=True, padx=10, pady=10)
        
        text_frame = ttk.Frame(text_card)
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.userrules_text = scrolledtext.ScrolledText(text_frame, height=15, font=FONTS['normal'])
        self.userrules_text.pack(fill="both", expand=True)
        
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
            messagebox.showwarning("Aucun Utilisateur", "Veuillez sélectionner un utilisateur")
            return
        txt = list_user_blocks(u)
        self.userrules_text.delete("1.0", tk.END)
        self.userrules_text.insert(tk.END, txt if txt.strip() else "Aucune règle définie pour cet utilisateur")
        self.update_status(f"Règles affichées pour {u}")

    def add_user_block_dialog(self):
        u = self.user_combo.get()
        if not u:
            messagebox.showwarning("Aucun Utilisateur", "Veuillez sélectionner un utilisateur")
            return
        d = simpledialog.askstring("Ajouter Domaine", f"Domaine à bloquer pour {u} (ex: facebook.com):")
        if not d:
            return
        self.update_status(f"Ajout du domaine {d} pour {u}...")
        add_user_block(u, d.strip())
        messagebox.showinfo("Succès", f"Le domaine '{d}' a été ajouté pour l'utilisateur {u}")
        self.show_user_rules()
        self.update_status(f"Domaine {d} bloqué pour {u}")

    def remove_user_block_dialog(self):
        u = self.user_combo.get()
        if not u:
            messagebox.showwarning("Aucun Utilisateur", "Veuillez sélectionner un utilisateur")
            return
        d = simpledialog.askstring("Supprimer Domaine", f"Domaine à retirer pour {u}:")
        if not d:
            return
        self.update_status(f"Retrait du domaine {d} pour {u}...")
        remove_user_block(u, d.strip())
        messagebox.showinfo("Succès", f"Le domaine '{d}' a été retiré pour l'utilisateur {u}")
        self.show_user_rules()
        self.update_status(f"Domaine {d} retiré pour {u}")

    # ------------ Logs Tab ------------
    def build_logs_tab(self, frame):
        card = CardFrame(frame, "Journal d'Activité du Proxy")
        card.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Controls panel
        controls_card = CardFrame(card, "Contrôles des Logs")
        controls_card.pack(fill="x", padx=10, pady=10)
        
        controls_frame = ttk.Frame(controls_card)
        controls_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Button(controls_frame, text="📄 Afficher 50 Dernières Lignes", 
                  command=self.show_logs, style="Accent.TButton").grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(controls_frame, text="▶️ Démarrer Surveillance Temps Réel", 
                  command=self.start_log_stream, style="Accent.TButton").grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(controls_frame, text="⏹️ Arrêter Surveillance", 
                  command=self.stop_log_stream, style="Accent.TButton").grid(row=0, column=2, padx=5, pady=5)

        # Text area
        text_card = CardFrame(card, "Journal d'Accès Squid")
        text_card.pack(fill="both", expand=True, padx=10, pady=10)
        
        text_frame = ttk.Frame(text_card)
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.log_text = scrolledtext.ScrolledText(text_frame, height=20, font=('Consolas', 9))
        self.log_text.pack(fill="both", expand=True)
        self._streaming = False

    def show_logs(self):
        self.update_status("Chargement des logs...")
        out = tail_log(50)
        self.log_text.delete("1.0", tk.END)
        self.log_text.insert(tk.END, out)
        self.update_status("50 dernières lignes affichées")

    def start_log_stream(self):
        if self._streaming:
            return
        self._streaming = True
        self.update_status("Surveillance temps réel démarrée")
        threading.Thread(target=self._stream_logs, daemon=True).start()

    def stop_log_stream(self):
        self._streaming = False
        self.update_status("Surveillance temps réel arrêtée")

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

    # ------------ Control Tab ------------
    def build_control_tab(self, frame):
        card = CardFrame(frame, "Contrôle du Service Squid")
        card.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Controls panel
        controls_card = CardFrame(card, "Actions de Service")
        controls_card.pack(fill="x", padx=10, pady=10)
        
        controls_frame = ttk.Frame(controls_card)
        controls_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Button(controls_frame, text="🔄 Redémarrer Squid", 
                  command=self.restart_squid_gui, style="Accent.TButton").grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(controls_frame, text="📊 Statut Squid", 
                  command=self.status_squid_gui, style="Accent.TButton").grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(controls_frame, text="🧹 Vider Cache", 
                  command=self.purge_cache, style="Accent.TButton").grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(controls_frame, text="🔄 Recharger Configuration", 
                  command=self.reload_squid, style="Accent.TButton").grid(row=0, column=3, padx=5, pady=5)

        # Output area
        output_card = CardFrame(card, "Sortie des Commandes")
        output_card.pack(fill="both", expand=True, padx=10, pady=10)
        
        output_frame = ttk.Frame(output_card)
        output_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.ctrl_text = scrolledtext.ScrolledText(output_frame, height=12, font=('Consolas', 9))
        self.ctrl_text.pack(fill="both", expand=True)

    def restart_squid_gui(self):
        self.update_status("Redémarrage de Squid...")
        out = restart_squid_action()
        self.ctrl_text.insert(tk.END, f"=== Redémarrage Squid ===\n{out}\n\n")
        self.ctrl_text.see(tk.END)
        self.update_status("Squid redémarré")

    def status_squid_gui(self):
        self.update_status("Vérification du statut de Squid...")
        out = status_squid_action()
        self.ctrl_text.insert(tk.END, f"=== Statut Squid ===\n{out}\n\n")
        self.ctrl_text.see(tk.END)
        self.update_status("Statut vérifié")

    def purge_cache(self):
        self.update_status("Nettoyage du cache...")
        out = run_cmd("sudo squid -k rotate || true")
        self.ctrl_text.insert(tk.END, f"=== Rotation/Nettoyage Cache ===\n{out}\n\n")
        self.ctrl_text.see(tk.END)
        self.update_status("Cache nettoyé")

    def reload_squid(self):
        self.update_status("Rechargement de la configuration...")
        out = reload_squid_action()
        self.ctrl_text.insert(tk.END, f"=== Rechargement Configuration ===\n{out}\n\n")
        self.ctrl_text.see(tk.END)
        self.update_status("Configuration rechargée")

# ---------- Main ----------
if __name__ == "__main__":
    if os.geteuid() != 0:
        try:
            root = tk.Tk()
            root.withdraw()
            answer = messagebox.askyesno("Privilèges Root Requis", 
                                       "Ce programme doit être lancé avec les privilèges root pour fonctionner correctement.\n\n"
                                       "Voulez-vous continuer malgré tout ?")
            root.destroy()
            if not answer:
                exit()
        except Exception:
            print("Attention: Il est recommandé de lancer ce script en tant que root (sudo).")
    
    app = SquidAdminApp()
    app.mainloop()