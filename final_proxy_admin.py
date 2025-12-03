#!/usr/bin/env python3
import os
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext
from pathlib import Path
import shutil
import threading
import time

# ---------- Configuration ----------
SQUID_DIR = Path("/etc/squid")
PASSWORDS = SQUID_DIR / "passwords"
BLOCKLIST_GLOBAL = SQUID_DIR / "blocklist_global.txt"
USERS_RULES_DIR = SQUID_DIR / "users_rules"
ACCESS_LOG = Path("/var/log/squid/access.log")

HTPASSWD_CMD = shutil.which("htpasswd") or "/usr/bin/htpasswd"
SYSTEMCTL = shutil.which("systemctl") or "/bin/systemctl"

# ---------- Design & Palette (Thème Squid) ----------
COLORS = {
    'bg_main':      '#ecf0f1',
    'header_bg':    '#2c3e50',
    'header_text':  '#ffffff',
    'accent':       '#17a7f4',
    'accent_dark':  '#0d8ddb',
    'card_bg':      '#ffffff',
    'text_main':    '#34495e',
    'success':      '#27ae60',
    'danger':       '#e74c3c',
    'border':       '#bdc3c7'
}

FONTS = {
    'title':    ('Segoe UI', 16, 'bold'),
    'subtitle': ('Segoe UI', 10, 'italic'),
    'heading':  ('Segoe UI', 11, 'bold'),
    'body':     ('Segoe UI', 10),
    'mono':     ('Consolas', 9),
    'small':    ('Segoe UI', 8)
}


# ---------- Logique Backend (Inchangée) ----------

def run_cmd(cmd):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True, text=True)
        return out.strip()
    except subprocess.CalledProcessError as e:
        return f"ERREUR: {e.output.strip()}"

def ensure_structure():
    SQUID_DIR.mkdir(parents=True, exist_ok=True)
    USERS_RULES_DIR.mkdir(parents=True, exist_ok=True)
    if not BLOCKLIST_GLOBAL.exists():
        BLOCKLIST_GLOBAL.write_text("")
    if not PASSWORDS.exists():
        PASSWORDS.write_text("")
    # Permissions
    try:
        run_cmd(f"chown -R proxy:proxy {USERS_RULES_DIR}")
        run_cmd(f"chmod 755 {USERS_RULES_DIR}")
    except Exception:
        pass

def reload_squid_action():
    return run_cmd(f"{SYSTEMCTL} reload squid || {SYSTEMCTL} restart squid")

def tail_log(lines=50):
    if not ACCESS_LOG.exists(): return "Fichier access.log introuvable."
    return run_cmd(f"tail -n {lines} {ACCESS_LOG}")

# Gestion Utilisateurs
def add_user(username, password):
    if " " in username: return "Erreur: Espaces interdits."
    run_cmd(f"{HTPASSWD_CMD} -b {PASSWORDS} {username} {password}")
    ensure_user_files(username)
    reload_squid_action()
    return "Utilisateur ajouté/mis à jour."

def delete_user(username):
    run_cmd(f"{HTPASSWD_CMD} -D {PASSWORDS} {username}")
    for ext in ['.txt', '.conf']:
        f = USERS_RULES_DIR / f"{username}{ext}"
        if f.exists(): f.unlink()
    reload_squid_action()
    return "Utilisateur supprimé."

def list_users():
    if not PASSWORDS.exists(): return []
    with PASSWORDS.open("r") as f:
        return [l.split(":")[0] for l in f if ":" in l]

# Gestion Règles
def ensure_user_files(username):
    txt = USERS_RULES_DIR / f"{username}.txt"
    conf = USERS_RULES_DIR / f"{username}.conf"
    
    if not txt.exists(): txt.write_text("")
    
    # Si le fichier txt est vide, on supprime le conf pour ne pas charger de règle vide
    if txt.stat().st_size < 2:
        if conf.exists(): conf.unlink()
        return

    # Création de la règle Squid
    config_content = (
        f"acl rule_{username} proxy_auth {username}\n"
        f"acl sites_{username} dstdomain \"{txt}\"\n"
        f"http_access deny rule_{username} sites_{username}\n"
    )
    conf.write_text(config_content)

def modify_blocklist(target_file, domain, action="add"):
    # Gestion fichier global ou user
    p = Path(target_file)
    if not p.exists(): p.write_text("")
    
    lines = p.read_text().splitlines()
    clean_lines = [l for l in lines if l.strip()]
    
    if not domain.startswith("."): domain = "." + domain
    
    if action == "add":
        if domain not in clean_lines:
            clean_lines.append(domain)
    elif action == "remove":
        clean_lines = [l for l in clean_lines if domain not in l]
        
    p.write_text("\n".join(clean_lines) + "\n")

# ---------- Interface Graphique ----------

class ModernButton(tk.Button):
    def __init__(self, parent, text, command, variant="primary", **kwargs):
        bg = COLORS['accent'] if variant == "primary" else COLORS['bg_main']
        fg = "#ffffff" if variant == "primary" else COLORS['text_main']
        super().__init__(parent, text=text, command=command, 
                         bg=bg, fg=fg, font=('Segoe UI', 9, 'bold'),
                         relief="flat", activebackground=COLORS['accent_dark'], 
                         activeforeground="#ffffff", bd=0, padx=15, pady=8, **kwargs)

class Card(tk.Frame):
    def __init__(self, parent, title):
        super().__init__(parent, bg=COLORS['card_bg'], bd=1, relief="solid")
        self.configure(highlightbackground=COLORS['border'], highlightthickness=1)
        
        # Titre de la carte
        lbl = tk.Label(self, text=title, font=FONTS['heading'], 
                       bg=COLORS['card_bg'], fg=COLORS['header_bg'], anchor="w")
        lbl.pack(fill="x", padx=15, pady=(10, 5))
        
        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=10, pady=5)
        
        self.content = tk.Frame(self, bg=COLORS['card_bg'])
        self.content.pack(fill="both", expand=True, padx=15, pady=10)

class SquidApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Administration Squid Proxy")
        self.geometry("1000x650")
        self.configure(bg=COLORS['bg_main'])
        
        ensure_structure()
        self.setup_styles()
        self.create_ui()
        
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configuration des onglets
        style.configure("TNotebook", background=COLORS['bg_main'], borderwidth=0)
        style.configure("TNotebook.Tab", font=FONTS['body'], padding=[15, 10], 
                        background=COLORS['bg_main'], foreground=COLORS['text_main'])
        style.map("TNotebook.Tab", background=[("selected", COLORS['accent'])], 
                  foreground=[("selected", "#ffffff")])
        
        style.configure("TFrame", background=COLORS['bg_main'])

    def create_ui(self):
        # --- Header ---
        header = tk.Frame(self, bg=COLORS['header_bg'], height=70)
        header.pack(fill="x", side="top")
        
        lbl_logo = tk.Label(header, text="🦑", font=("Segoe UI Emoji", 24), 
                            bg=COLORS['header_bg'], fg=COLORS['accent'])
        lbl_logo.pack(side="left", padx=(20, 10))
        
        lbl_title = tk.Label(header, text="Squid Proxy Manager", font=FONTS['title'], 
                             bg=COLORS['header_bg'], fg="#ffffff")
        lbl_title.pack(side="left", pady=20)
        
        self.status_lbl = tk.Label(header, text="Système prêt", font=FONTS['small'], 
                                   bg=COLORS['header_bg'], fg=COLORS['accent'])
        self.status_lbl.pack(side="right", padx=20)

        # --- Tabs ---
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=20, pady=20)
        
        self.tab_users = ttk.Frame(nb); nb.add(self.tab_users, text=" 👥 Utilisateurs ")
        self.tab_global = ttk.Frame(nb); nb.add(self.tab_global, text=" 🌍 Blocage Global ")
        self.tab_per_user = ttk.Frame(nb); nb.add(self.tab_per_user, text=" 🔒 Règles par User ")
        self.tab_logs = ttk.Frame(nb); nb.add(self.tab_logs, text=" 📜 Logs ")
        self.tab_ctrl = ttk.Frame(nb); nb.add(self.tab_ctrl, text=" ⚙️ Serveur ")

        self.build_users_tab()
        self.build_global_tab()
        self.build_per_user_tab()
        self.build_logs_tab()
        self.build_ctrl_tab()

    # --- Onglet Utilisateurs ---
    def build_users_tab(self):
        f = tk.Frame(self.tab_users, bg=COLORS['bg_main'])
        f.pack(fill="both", expand=True)
        
        # Colonne Gauche : Actions
        left_col = tk.Frame(f, bg=COLORS['bg_main'])
        left_col.pack(side="left", fill="y", padx=10, pady=10)
        
        card_actions = Card(left_col, "Actions Utilisateur")
        card_actions.pack(fill="x", pady=5)
        
        ModernButton(card_actions.content, "➕ Ajouter / Modifier", self.act_add_user).pack(fill="x", pady=5)
        ModernButton(card_actions.content, "❌ Supprimer", self.act_del_user, variant="danger").pack(fill="x", pady=5)
        ModernButton(card_actions.content, "🔄 Actualiser", self.refresh_users, variant="secondary").pack(fill="x", pady=5)

        # Colonne Droite : Liste
        right_col = tk.Frame(f, bg=COLORS['bg_main'])
        right_col.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        
        card_list = Card(right_col, "Utilisateurs Enregistrés")
        card_list.pack(fill="both", expand=True)
        
        self.user_listbox = tk.Listbox(card_list.content, font=FONTS['body'], 
                                       bd=0, highlightthickness=0, selectbackground=COLORS['accent'])
        self.user_listbox.pack(fill="both", expand=True)
        self.refresh_users()

    def act_add_user(self):
        u = simpledialog.askstring("Nouveau", "Nom d'utilisateur:")
        if u:
            p = simpledialog.askstring("Mot de passe", "Mot de passe:", show="*")
            if p:
                res = add_user(u, p)
                messagebox.showinfo("Info", res)
                self.refresh_users()

    def act_del_user(self):
        sel = self.user_listbox.curselection()
        if not sel: return
        u = self.user_listbox.get(sel[0]).replace("👤 ", "")
        if messagebox.askyesno("Confirmer", f"Supprimer {u} ?"):
            delete_user(u)
            self.refresh_users()

    def refresh_users(self):
        self.user_listbox.delete(0, tk.END)
        for u in list_users():
            self.user_listbox.insert(tk.END, f"👤 {u}")

    # --- Onglet Global ---
    def build_global_tab(self):
        card = Card(self.tab_global, "Liste Noire Globale (Interdit pour tous)")
        card.pack(fill="both", expand=True, padx=10, pady=10)
        
        btns = tk.Frame(card.content, bg="#ffffff")
        btns.pack(fill="x", pady=10)
        
        ModernButton(btns, "➕ Ajouter Domaine", lambda: self.mod_global("add")).pack(side="left", padx=5)
        ModernButton(btns, "❌ Retirer Domaine", lambda: self.mod_global("remove"), variant="danger").pack(side="left", padx=5)
        
        self.global_txt = scrolledtext.ScrolledText(card.content, height=15)
        self.global_txt.pack(fill="both", expand=True)
        self.refresh_global()

    def mod_global(self, action):
        d = simpledialog.askstring("Domaine", "Domaine (ex: facebook.com):")
        if d:
            modify_blocklist(BLOCKLIST_GLOBAL, d, action)
            reload_squid_action()
            self.refresh_global()

    def refresh_global(self):
        self.global_txt.delete('1.0', tk.END)
        if BLOCKLIST_GLOBAL.exists():
            self.global_txt.insert(tk.END, BLOCKLIST_GLOBAL.read_text())

    # --- Onglet Par User ---
    def build_per_user_tab(self):
        # Sélection User
        top_frame = tk.Frame(self.tab_per_user, bg=COLORS['bg_main'])
        top_frame.pack(fill="x", padx=10, pady=10)
        
        tk.Label(top_frame, text="Sélectionner l'utilisateur :", bg=COLORS['bg_main']).pack(side="left")
        self.combo_users = ttk.Combobox(top_frame, values=list_users())
        self.combo_users.pack(side="left", padx=10)
        ModernButton(top_frame, "Charger règles", self.load_user_rules).pack(side="left")

        card = Card(self.tab_per_user, "Domaines bloqués pour cet utilisateur")
        card.pack(fill="both", expand=True, padx=10)
        
        btns = tk.Frame(card.content, bg="#ffffff")
        btns.pack(fill="x", pady=5)
        ModernButton(btns, "➕ Bloquer Domaine", lambda: self.mod_user_rule("add")).pack(side="left", padx=5)
        ModernButton(btns, "❌ Autoriser Domaine", lambda: self.mod_user_rule("remove"), variant="danger").pack(side="left", padx=5)

        self.user_rules_txt = scrolledtext.ScrolledText(card.content)
        self.user_rules_txt.pack(fill="both", expand=True)

    def load_user_rules(self):
        u = self.combo_users.get()
        if not u: return
        f = USERS_RULES_DIR / f"{u}.txt"
        self.user_rules_txt.delete('1.0', tk.END)
        if f.exists():
            self.user_rules_txt.insert(tk.END, f.read_text())

    def mod_user_rule(self, action):
        u = self.combo_users.get()
        if not u: return
        d = simpledialog.askstring("Domaine", "Domaine:")
        if d:
            f = USERS_RULES_DIR / f"{u}.txt"
            modify_blocklist(f, d, action)
            ensure_user_files(u) # Regen .conf
            reload_squid_action()
            self.load_user_rules()

    # --- Logs ---
    def build_logs_tab(self):
        card = Card(self.tab_logs, "Logs d'accès en temps réel")
        card.pack(fill="both", expand=True, padx=10, pady=10)
        
        btns = tk.Frame(card.content, bg="#ffffff")
        btns.pack(fill="x", pady=5)
        ModernButton(btns, "Actualiser", self.refresh_logs).pack(side="left")
        
        self.log_view = scrolledtext.ScrolledText(card.content, bg="#2c3e50", fg="#ecf0f1", font=FONTS['mono'])
        self.log_view.pack(fill="both", expand=True)

    def refresh_logs(self):
        self.log_view.delete('1.0', tk.END)
        self.log_view.insert(tk.END, tail_log(50))

    # --- Contrôle ---
    def build_ctrl_tab(self):
        card = Card(self.tab_ctrl, "État du Serveur")
        card.pack(fill="x", padx=10, pady=10)
        
        ModernButton(card.content, "🛑 Redémarrer Service Squid", 
                     lambda: messagebox.showinfo("Output", run_cmd(f"sudo {SYSTEMCTL} restart squid")),
                     variant="primary").pack(fill="x", pady=5)
        
        ModernButton(card.content, "🧹 Vider le cache", 
                     lambda: messagebox.showinfo("Output", run_cmd("sudo squid -k rotate")),
                     variant="secondary").pack(fill="x", pady=5)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Ce script doit être lancé avec sudo.")
        exit(1)
    app = SquidApp()
    app.mainloop()
