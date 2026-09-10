"""Small desktop console for testing LabOrchestrator on Windows."""

from __future__ import annotations

import queue
import re
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk


ROOT = Path(__file__).resolve().parent.parent
POLICY_DEFAULT = ROOT / "policies" / "default.json"
AGENT_PATTERN = re.compile(r"\[([^]]+)\]\s+(.+?)\s+@\s+([^:]+):(\d+)")


class LabConsole(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("S.C.A.C | Console de teste")
        self.geometry("980x650")
        self.minsize(820, 540)
        self.configure(bg="#eef2f5")

        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.agents: dict[str, dict[str, str]] = {}
        self.agent_process: subprocess.Popen[str] | None = None
        self.target_var = tk.StringVar()
        self.policy_var = tk.StringVar(value=str(POLICY_DEFAULT))
        self.profile_var = tk.StringVar(value="Programacao")
        self.status_var = tk.StringVar(value="Pronto para testar")
        self.build_interface()
        self.after(120, self.process_events)

    def build_interface(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background="#eef2f5")
        style.configure("Panel.TFrame", background="#ffffff")
        style.configure("TLabel", background="#eef2f5", foreground="#263238")
        style.configure("Title.TLabel", background="#eef2f5", foreground="#17324d", font=("Segoe UI", 21, "bold"))
        style.configure("Muted.TLabel", background="#eef2f5", foreground="#60717d")
        style.configure("Treeview", rowheight=32, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        style.configure("Accent.TButton", background="#147d92", foreground="white", font=("Segoe UI", 10, "bold"))

        header = ttk.Frame(self)
        header.pack(fill="x", padx=28, pady=(24, 14))
        ttk.Label(header, text="LabOrchestrator", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header, text="Console visual para discovery, políticas e reset", style="Muted.TLabel").pack(anchor="w", pady=(3, 0))

        controls = ttk.Frame(self, style="Panel.TFrame", padding=16)
        controls.pack(fill="x", padx=28, pady=(0, 12))
        controls.columnconfigure(1, weight=1)
        ttk.Label(controls, text="Executáveis").grid(row=0, column=0, sticky="w", padx=(0, 10), pady=5)
        self.admin_label = ttk.Label(controls, text=self.find_binary("admin", "labadmin.exe"), foreground="#60717d")
        self.admin_label.grid(row=0, column=1, sticky="w", pady=5)
        self.agent_button = ttk.Button(controls, text="Iniciar agente local", command=self.toggle_agent)
        self.agent_button.grid(row=0, column=2, padx=(12, 0), pady=5)
        ttk.Label(controls, text="Política").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=5)
        ttk.Entry(controls, textvariable=self.policy_var).grid(row=1, column=1, sticky="ew", pady=5)
        ttk.Button(controls, text="Escolher...", command=self.choose_policy).grid(row=1, column=2, padx=(12, 0), pady=5)

        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, padx=28)
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)
        left = ttk.Frame(body, style="Panel.TFrame", padding=14)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.rowconfigure(1, weight=1)
        left.columnconfigure(0, weight=1)
        top = ttk.Frame(left, style="Panel.TFrame")
        top.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        ttk.Label(top, text="Agentes encontrados", font=("Segoe UI", 13, "bold"), background="#ffffff").pack(side="left")
        ttk.Button(top, text="Descobrir na LAN", style="Accent.TButton", command=self.discover).pack(side="right")
        columns = ("id", "host", "ip", "port")
        self.agent_tree = ttk.Treeview(left, columns=columns, show="headings", selectmode="browse")
        for col, text, width in (("id", "ID", 170), ("host", "Hostname", 170), ("ip", "IP", 125), ("port", "Porta", 65)):
            self.agent_tree.heading(col, text=text)
            self.agent_tree.column(col, width=width, anchor="w")
        self.agent_tree.grid(row=1, column=0, sticky="nsew")
        self.agent_tree.bind("<<TreeviewSelect>>", self.select_agent)

        right = ttk.Frame(body, style="Panel.TFrame", padding=14)
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        ttk.Label(right, text="Ações do agente", font=("Segoe UI", 13, "bold"), background="#ffffff").pack(anchor="w")
        ttk.Label(right, text="Alvo selecionado ou IP informado", background="#ffffff", foreground="#60717d").pack(anchor="w", pady=(3, 8))
        ttk.Entry(right, textvariable=self.target_var).pack(fill="x", pady=(0, 16))
        ttk.Button(right, text="Consultar status", command=lambda: self.run_admin("status", self.target_var.get())).pack(fill="x", pady=3)
        ttk.Button(right, text="Enviar política", command=self.push_policy).pack(fill="x", pady=3)
        profile_row = ttk.Frame(right, style="Panel.TFrame")
        profile_row.pack(fill="x", pady=3)
        ttk.Combobox(profile_row, textvariable=self.profile_var, values=("Aluno", "Programacao", "Redes"), state="readonly").pack(side="left", fill="x", expand=True)
        ttk.Button(profile_row, text="Trocar perfil", command=self.switch_profile).pack(side="left", padx=(7, 0))
        ttk.Button(right, text="Disparar reset", command=self.reset_agent).pack(fill="x", pady=3)

        output = ttk.Frame(self, style="Panel.TFrame", padding=12)
        output.pack(fill="both", expand=False, padx=28, pady=(12, 24))
        output.columnconfigure(0, weight=1)
        ttk.Label(output, text="Log da operação", font=("Segoe UI", 11, "bold"), background="#ffffff").grid(row=0, column=0, sticky="w")
        self.log = tk.Text(output, height=7, state="disabled", bg="#18252d", fg="#d7e5e8", insertbackground="white", relief="flat", font=("Consolas", 9))
        self.log.grid(row=1, column=0, sticky="ew", pady=(7, 0))
        ttk.Label(self, textvariable=self.status_var, anchor="w", padding=(28, 0, 28, 9)).pack(fill="x")

    def find_binary(self, component: str, name: str) -> str:
        for folder in (ROOT / "build", ROOT / "build-local", ROOT / "build-hackathon1"):
            candidate = folder / component / "Release" / name
            if candidate.exists():
                return str(candidate)
        return str(ROOT / "build" / component / "Release" / name)

    def choose_policy(self) -> None:
        selected = filedialog.askopenfilename(initialdir=str(ROOT / "policies"), filetypes=(("JSON", "*.json"), ("Todos", "*.*")))
        if selected:
            self.policy_var.set(selected)

    def selected_target(self) -> str:
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("Alvo ausente", "Selecione um agente ou informe um IP.")
        return target

    def select_agent(self, _event: object) -> None:
        selection = self.agent_tree.selection()
        if selection:
            self.target_var.set(self.agent_tree.item(selection[0], "values")[2])

    def discover(self) -> None:
        self.run_admin("discover", "--timeout", "3", on_done=self.parse_discovery)

    def parse_discovery(self, text: str) -> None:
        found = 0
        for line in text.splitlines():
            match = AGENT_PATTERN.search(line)
            if not match:
                continue
            agent_id, hostname, ip, port = match.groups()
            self.agents[ip] = {"id": agent_id, "host": hostname, "ip": ip, "port": port}
            found += 1
        for item in self.agent_tree.get_children():
            self.agent_tree.delete(item)
        for agent in self.agents.values():
            self.agent_tree.insert("", "end", values=(agent["id"], agent["host"], agent["ip"], agent["port"]))
        self.status_var.set(f"{found} agente(s) encontrados")

    def push_policy(self) -> None:
        target = self.selected_target()
        if target and Path(self.policy_var.get()).exists():
            self.run_admin("push", target, self.policy_var.get())
        elif target:
            messagebox.showerror("Política não encontrada", self.policy_var.get())

    def switch_profile(self) -> None:
        target = self.selected_target()
        if target:
            self.run_admin("switch", target, self.profile_var.get())

    def reset_agent(self) -> None:
        target = self.selected_target()
        if target and messagebox.askyesno("Confirmar reset", f"Restaurar o ambiente de {target}?"):
            self.run_admin("reset", target)

    def run_admin(self, *arguments: str, on_done=None) -> None:
        binary = Path(self.admin_label.cget("text"))
        if not binary.exists():
            messagebox.showerror("LabAdmin ausente", "Compile o projeto antes de abrir a GUI:\n\npowershell scripts/build.ps1")
            return
        self.status_var.set("Executando operação...")
        self.write_log(f"> labadmin {' '.join(arguments)}")
        threading.Thread(target=self.worker, args=(binary, arguments, on_done), daemon=True).start()

    def worker(self, binary: Path, arguments: tuple[str, ...], on_done) -> None:
        try:
            result = subprocess.run([str(binary), *arguments], cwd=ROOT, capture_output=True, text=True, timeout=20, check=False)
            output = (result.stdout + result.stderr).strip()
            self.events.put(("command", (result.returncode, output, on_done)))
        except (OSError, subprocess.TimeoutExpired) as error:
            self.events.put(("command", (-1, str(error), on_done)))

    def toggle_agent(self) -> None:
        if self.agent_process and self.agent_process.poll() is None:
            self.agent_process.terminate()
            self.agent_process = None
            self.agent_button.configure(text="Iniciar agente local")
            self.status_var.set("Agente local encerrado")
            return
        binary = Path(self.find_binary("agent", "labagent.exe"))
        if not binary.exists():
            messagebox.showerror("LabAgent ausente", "Compile o projeto antes de iniciar o agente.")
            return
        creationflags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
        self.agent_process = subprocess.Popen([str(binary), "--key", "keys/shared.key"], cwd=ROOT, creationflags=creationflags)
        self.agent_button.configure(text="Parar agente local")
        self.status_var.set("Agente local iniciado")

    def write_log(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def process_events(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind != "command":
                    continue
                code, output, callback = payload
                if output:
                    self.write_log(output)
                self.status_var.set("Operação concluída" if code == 0 else f"Operação terminou com código {code}")
                if callback:
                    callback(output)
        except queue.Empty:
            pass
        self.after(120, self.process_events)


if __name__ == "__main__":
    if sys.platform != "win32":
        print("Esta GUI foi preparada para Windows, onde os binários C são gerados.")
    app = LabConsole()
    app.mainloop()
