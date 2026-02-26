"""
Main application window with four tabs:
  1. File Encryption / Decryption
  2. Text Encryption / Decryption
  3. Password Manager
  4. Secure File Deletion
"""

import io
import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

import pyotp
import qrcode
from PIL import Image, ImageTk

from app.crypto.algorithms import (
    ALGORITHMS as CRYPTO_ALGORITHMS,
    decrypt_file,
    decrypt_text,
    encrypt_file,
    encrypt_text,
    file_checksum,
    verify_file_integrity,
)
from app.password_manager.vault import (
    PasswordVault,
    TwoFactorRequiredError,
    VaultError,
    WrongPasswordError,
    generate_password,
)
from app.secure_delete.shredder import ALGORITHMS as DELETE_ALGORITHMS, secure_delete

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FONT = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_TITLE = ("Segoe UI", 12, "bold")
PAD = {"padx": 8, "pady": 4}


def _pw_dialog(title: str, prompt: str) -> str | None:
    """Show a password entry dialog."""
    dlg = tk.Toplevel()
    dlg.title(title)
    dlg.resizable(False, False)
    dlg.grab_set()
    result = [None]

    tk.Label(dlg, text=prompt, font=FONT).pack(padx=16, pady=(14, 4))
    entry = tk.Entry(dlg, show="*", font=FONT, width=28)
    entry.pack(padx=16, pady=4)
    entry.focus_set()

    def ok(_event=None):
        result[0] = entry.get()
        dlg.destroy()

    def cancel():
        dlg.destroy()

    btn_frame = tk.Frame(dlg)
    btn_frame.pack(pady=(4, 12))
    tk.Button(btn_frame, text="OK", command=ok, font=FONT, width=8).pack(side="left", padx=4)
    tk.Button(btn_frame, text="Cancel", command=cancel, font=FONT, width=8).pack(side="left", padx=4)
    entry.bind("<Return>", ok)
    dlg.wait_window()
    return result[0]


# ---------------------------------------------------------------------------
# Tab 1 – File Encryption
# ---------------------------------------------------------------------------

class FileEncryptionTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self._src = tk.StringVar()
        self._dst = tk.StringVar()
        self._algo = tk.StringVar(value=CRYPTO_ALGORITHMS[0])
        self._checksum_var = tk.StringVar()
        self._build()

    def _build(self):
        tk.Label(self, text="File Encryption & Decryption", font=FONT_TITLE).grid(
            row=0, column=0, columnspan=3, pady=(12, 6), sticky="w", padx=12
        )

        # Source file
        tk.Label(self, text="Source file:", font=FONT).grid(row=1, column=0, sticky="e", **PAD)
        tk.Entry(self, textvariable=self._src, font=FONT, width=42).grid(row=1, column=1, sticky="ew", **PAD)
        tk.Button(self, text="Browse…", command=self._browse_src, font=FONT).grid(row=1, column=2, **PAD)

        # Destination file
        tk.Label(self, text="Destination file:", font=FONT).grid(row=2, column=0, sticky="e", **PAD)
        tk.Entry(self, textvariable=self._dst, font=FONT, width=42).grid(row=2, column=1, sticky="ew", **PAD)
        tk.Button(self, text="Browse…", command=self._browse_dst, font=FONT).grid(row=2, column=2, **PAD)

        # Algorithm
        tk.Label(self, text="Algorithm:", font=FONT).grid(row=3, column=0, sticky="e", **PAD)
        algo_cb = ttk.Combobox(
            self, textvariable=self._algo, values=CRYPTO_ALGORITHMS, state="readonly", font=FONT, width=18
        )
        algo_cb.grid(row=3, column=1, sticky="w", **PAD)
        self._file_algo_warn = tk.Label(self, text="", font=("Segoe UI", 9), fg="#c0392b")
        self._file_algo_warn.grid(row=3, column=2, sticky="w", **PAD)
        self._algo.trace_add("write", self._on_file_algo_change)

        # Buttons
        btn_frame = tk.Frame(self)
        btn_frame.grid(row=4, column=0, columnspan=3, pady=8)
        tk.Button(btn_frame, text="🔒  Encrypt", command=self._encrypt, font=FONT_BOLD, bg="#4CAF50", fg="white", width=14).pack(side="left", padx=6)
        tk.Button(btn_frame, text="🔓  Decrypt", command=self._decrypt, font=FONT_BOLD, bg="#2196F3", fg="white", width=14).pack(side="left", padx=6)

        # Integrity check section
        sep = ttk.Separator(self, orient="horizontal")
        sep.grid(row=5, column=0, columnspan=3, sticky="ew", padx=12, pady=8)
        tk.Label(self, text="File Integrity Check", font=FONT_TITLE).grid(row=6, column=0, columnspan=3, sticky="w", padx=12)

        tk.Label(self, text="File:", font=FONT).grid(row=7, column=0, sticky="e", **PAD)
        self._integrity_path = tk.StringVar()
        tk.Entry(self, textvariable=self._integrity_path, font=FONT, width=42).grid(row=7, column=1, sticky="ew", **PAD)
        tk.Button(self, text="Browse…", command=self._browse_integrity, font=FONT).grid(row=7, column=2, **PAD)

        tk.Label(self, text="Expected SHA-256:", font=FONT).grid(row=8, column=0, sticky="e", **PAD)
        tk.Entry(self, textvariable=self._checksum_var, font=FONT, width=42).grid(row=8, column=1, sticky="ew", **PAD)

        btn2 = tk.Frame(self)
        btn2.grid(row=9, column=0, columnspan=3, pady=4)
        tk.Button(btn2, text="Compute SHA-256", command=self._compute_hash, font=FONT, width=18).pack(side="left", padx=6)
        tk.Button(btn2, text="Verify Integrity", command=self._verify_integrity, font=FONT, width=18).pack(side="left", padx=6)

        self.columnconfigure(1, weight=1)

    # ------------------------------------------------------------------
    def _on_file_algo_change(self, *_):
        algo = self._algo.get()
        if algo in ("3DES", "Blowfish"):
            self._file_algo_warn.config(text="⚠ Weak algorithm")
        else:
            self._file_algo_warn.config(text="")

    def _browse_src(self):
        p = filedialog.askopenfilename(title="Select source file")
        if p:
            self._src.set(p)

    def _browse_dst(self):
        p = filedialog.asksaveasfilename(title="Select destination file")
        if p:
            self._dst.set(p)

    def _browse_integrity(self):
        p = filedialog.askopenfilename(title="Select file for integrity check")
        if p:
            self._integrity_path.set(p)

    def _encrypt(self):
        src, dst = self._src.get(), self._dst.get()
        if not src or not dst:
            messagebox.showerror("Error", "Please select source and destination files.")
            return
        pw = _pw_dialog("Encryption Password", "Enter encryption password:")
        if not pw:
            return
        try:
            encrypt_file(src, dst, pw, self._algo.get())
            checksum = file_checksum(dst)
            messagebox.showinfo("Success", f"File encrypted successfully!\n\nSHA-256 of encrypted file:\n{checksum}")
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def _decrypt(self):
        src, dst = self._src.get(), self._dst.get()
        if not src or not dst:
            messagebox.showerror("Error", "Please select source and destination files.")
            return
        pw = _pw_dialog("Decryption Password", "Enter decryption password:")
        if not pw:
            return
        try:
            algo = decrypt_file(src, dst, pw)
            messagebox.showinfo("Success", f"File decrypted successfully!\n\nAlgorithm used: {algo}")
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def _compute_hash(self):
        p = self._integrity_path.get()
        if not p:
            messagebox.showerror("Error", "Please select a file.")
            return
        try:
            h = file_checksum(p)
            self._checksum_var.set(h)
            messagebox.showinfo("SHA-256", f"SHA-256 checksum:\n{h}")
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def _verify_integrity(self):
        p = self._integrity_path.get()
        expected = self._checksum_var.get().strip()
        if not p or not expected:
            messagebox.showerror("Error", "Please select a file and enter the expected checksum.")
            return
        try:
            ok = verify_file_integrity(p, expected)
            if ok:
                messagebox.showinfo("Integrity OK", "✅ File integrity verified. Checksums match.")
            else:
                messagebox.showwarning("Integrity FAILED", "❌ Checksums do NOT match. File may be corrupted or tampered with.")
        except Exception as exc:
            messagebox.showerror("Error", str(exc))


# ---------------------------------------------------------------------------
# Tab 2 – Text Encryption
# ---------------------------------------------------------------------------

class TextEncryptionTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self._algo = tk.StringVar(value=CRYPTO_ALGORITHMS[0])
        self._build()

    def _build(self):
        tk.Label(self, text="Text Encryption & Decryption", font=FONT_TITLE).grid(
            row=0, column=0, columnspan=2, pady=(12, 6), sticky="w", padx=12
        )

        tk.Label(self, text="Algorithm:", font=FONT).grid(row=1, column=0, sticky="e", **PAD)
        algo_frame = tk.Frame(self)
        algo_frame.grid(row=1, column=1, sticky="w")
        ttk.Combobox(
            algo_frame, textvariable=self._algo, values=CRYPTO_ALGORITHMS, state="readonly", font=FONT, width=18
        ).pack(side="left")
        self._text_algo_warn = tk.Label(algo_frame, text="", font=("Segoe UI", 9), fg="#c0392b")
        self._text_algo_warn.pack(side="left", padx=6)
        self._algo.trace_add("write", self._on_text_algo_change)

        tk.Label(self, text="Plain text:", font=FONT).grid(row=2, column=0, sticky="ne", **PAD)
        self._plain = tk.Text(self, height=7, font=FONT, wrap="word")
        self._plain.grid(row=2, column=1, sticky="ew", **PAD)

        btn_frame = tk.Frame(self)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=6)
        tk.Button(btn_frame, text="🔒  Encrypt", command=self._encrypt, font=FONT_BOLD, bg="#4CAF50", fg="white", width=14).pack(side="left", padx=6)
        tk.Button(btn_frame, text="🔓  Decrypt", command=self._decrypt, font=FONT_BOLD, bg="#2196F3", fg="white", width=14).pack(side="left", padx=6)
        tk.Button(btn_frame, text="Clear", command=self._clear, font=FONT, width=8).pack(side="left", padx=6)

        tk.Label(self, text="Cipher text\n(Base64):", font=FONT).grid(row=4, column=0, sticky="ne", **PAD)
        self._cipher = tk.Text(self, height=7, font=("Courier", 9), wrap="word")
        self._cipher.grid(row=4, column=1, sticky="ew", **PAD)

        self.columnconfigure(1, weight=1)

    def _on_text_algo_change(self, *_):
        algo = self._algo.get()
        if algo in ("3DES", "Blowfish"):
            self._text_algo_warn.config(text="⚠ Weak algorithm")
        else:
            self._text_algo_warn.config(text="")

    def _encrypt(self):
        plaintext = self._plain.get("1.0", "end").rstrip("\n")
        if not plaintext:
            messagebox.showerror("Error", "Please enter text to encrypt.")
            return
        pw = _pw_dialog("Encryption Password", "Enter encryption password:")
        if not pw:
            return
        try:
            import base64
            blob = encrypt_text(plaintext, pw, self._algo.get())
            self._cipher.delete("1.0", "end")
            self._cipher.insert("end", base64.b64encode(blob).decode())
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def _decrypt(self):
        import base64
        b64 = self._cipher.get("1.0", "end").strip()
        if not b64:
            messagebox.showerror("Error", "Please enter cipher text (Base64).")
            return
        pw = _pw_dialog("Decryption Password", "Enter decryption password:")
        if not pw:
            return
        try:
            blob = base64.b64decode(b64)
            plaintext = decrypt_text(blob, pw, self._algo.get())
            self._plain.delete("1.0", "end")
            self._plain.insert("end", plaintext)
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def _clear(self):
        self._plain.delete("1.0", "end")
        self._cipher.delete("1.0", "end")


# ---------------------------------------------------------------------------
# Tab 3 – Password Manager
# ---------------------------------------------------------------------------

class PasswordManagerTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self._vault: PasswordVault | None = None
        self._vault_path = tk.StringVar()
        self._build()

    def _build(self):
        # Top bar
        top = tk.Frame(self)
        top.pack(fill="x", padx=12, pady=(10, 0))
        tk.Label(top, text="Password Manager", font=FONT_TITLE).pack(side="left")

        # Vault file row
        vf = tk.Frame(self)
        vf.pack(fill="x", padx=12, pady=4)
        tk.Label(vf, text="Vault file:", font=FONT).pack(side="left")
        tk.Entry(vf, textvariable=self._vault_path, font=FONT, width=36).pack(side="left", padx=4)
        tk.Button(vf, text="Browse", command=self._browse_vault, font=FONT).pack(side="left", padx=2)

        # Action buttons
        bf = tk.Frame(self)
        bf.pack(fill="x", padx=12, pady=4)
        tk.Button(bf, text="Create New Vault", command=self._create_vault, font=FONT, bg="#4CAF50", fg="white").pack(side="left", padx=4)
        tk.Button(bf, text="Open Vault", command=self._open_vault, font=FONT, bg="#2196F3", fg="white").pack(side="left", padx=4)
        tk.Button(bf, text="Lock Vault", command=self._lock_vault, font=FONT, bg="#FF9800", fg="white").pack(side="left", padx=4)
        tk.Button(bf, text="Toggle 2FA", command=self._toggle_2fa, font=FONT).pack(side="left", padx=4)

        sep = ttk.Separator(self, orient="horizontal")
        sep.pack(fill="x", padx=12, pady=6)

        # Entry list + buttons
        mid = tk.Frame(self)
        mid.pack(fill="both", expand=True, padx=12)

        # Listbox
        list_frame = tk.Frame(mid)
        list_frame.pack(side="left", fill="both", expand=True)
        tk.Label(list_frame, text="Entries:", font=FONT_BOLD).pack(anchor="w")
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")
        self._listbox = tk.Listbox(list_frame, font=FONT, yscrollcommand=scrollbar.set, activestyle="dotbox")
        self._listbox.pack(fill="both", expand=True)
        scrollbar.config(command=self._listbox.yview)
        self._listbox.bind("<<ListboxSelect>>", self._on_select)

        # Detail panel
        detail = tk.Frame(mid, padx=8)
        detail.pack(side="left", fill="both", expand=True)

        labels = ["Name:", "Username:", "Password:", "URL:", "Notes:"]
        self._detail_vars = {k: tk.StringVar() for k in ["name", "username", "password", "url", "notes"]}
        field_keys = ["name", "username", "password", "url", "notes"]
        for i, (lbl, key) in enumerate(zip(labels, field_keys)):
            tk.Label(detail, text=lbl, font=FONT_BOLD, anchor="e").grid(row=i, column=0, sticky="e", pady=2, padx=(0, 4))
            if key == "notes":
                t = tk.Text(detail, height=3, width=28, font=FONT, wrap="word")
                t.grid(row=i, column=1, sticky="ew", pady=2)
                self._notes_widget = t
            elif key == "password":
                pw_frame = tk.Frame(detail)
                pw_frame.grid(row=i, column=1, sticky="ew", pady=2)
                self._pw_entry = tk.Entry(pw_frame, textvariable=self._detail_vars[key], font=FONT, width=20, show="*")
                self._pw_entry.pack(side="left")
                self._show_pw = tk.BooleanVar()
                tk.Checkbutton(pw_frame, text="Show", variable=self._show_pw, command=self._toggle_pw_show, font=FONT).pack(side="left", padx=4)
            else:
                tk.Entry(detail, textvariable=self._detail_vars[key], font=FONT, width=26).grid(row=i, column=1, sticky="ew", pady=2)
        detail.columnconfigure(1, weight=1)

        # Password generator sub-frame
        gen_frame = tk.LabelFrame(detail, text="Password Generator", font=FONT, padx=6, pady=4)
        gen_frame.grid(row=len(labels), column=0, columnspan=2, sticky="ew", pady=8)
        tk.Label(gen_frame, text="Length:", font=FONT).pack(side="left")
        self._gen_len = tk.IntVar(value=16)
        tk.Spinbox(gen_frame, from_=4, to=128, textvariable=self._gen_len, width=5, font=FONT).pack(side="left", padx=4)
        self._use_upper = tk.BooleanVar(value=True)
        self._use_lower = tk.BooleanVar(value=True)
        self._use_digits = tk.BooleanVar(value=True)
        self._use_symbols = tk.BooleanVar(value=True)
        tk.Checkbutton(gen_frame, text="A-Z", variable=self._use_upper, font=FONT).pack(side="left")
        tk.Checkbutton(gen_frame, text="a-z", variable=self._use_lower, font=FONT).pack(side="left")
        tk.Checkbutton(gen_frame, text="0-9", variable=self._use_digits, font=FONT).pack(side="left")
        tk.Checkbutton(gen_frame, text="!@#", variable=self._use_symbols, font=FONT).pack(side="left")
        tk.Button(gen_frame, text="Generate", command=self._generate_password, font=FONT).pack(side="left", padx=4)

        # CRUD buttons
        crud = tk.Frame(self)
        crud.pack(fill="x", padx=12, pady=6)
        tk.Button(crud, text="Add / Update Entry", command=self._add_entry, font=FONT, bg="#4CAF50", fg="white").pack(side="left", padx=4)
        tk.Button(crud, text="Delete Entry", command=self._delete_entry, font=FONT, bg="#f44336", fg="white").pack(side="left", padx=4)
        tk.Button(crud, text="Copy Password", command=self._copy_password, font=FONT).pack(side="left", padx=4)

    # ------------------------------------------------------------------
    def _browse_vault(self):
        p = filedialog.asksaveasfilename(
            title="Select or create vault file",
            defaultextension=".vault",
            filetypes=[("Vault files", "*.vault"), ("All files", "*.*")],
        )
        if p:
            self._vault_path.set(p)

    def _create_vault(self):
        path = self._vault_path.get()
        if not path:
            messagebox.showerror("Error", "Please select a vault file path.")
            return
        pw = _pw_dialog("Create Vault", "Enter a master password for the new vault:")
        if not pw:
            return
        pw2 = _pw_dialog("Confirm Password", "Confirm master password:")
        if pw != pw2:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        enable_2fa = messagebox.askyesno("2FA", "Enable two-factor authentication (2FA) for this vault?")
        try:
            vault = PasswordVault(path)
            uri = vault.create(pw, enable_2fa=enable_2fa)
            self._vault = vault
            if uri:
                self._show_qr(uri)
            messagebox.showinfo("Success", "Vault created and opened.")
            self._refresh_list()
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def _open_vault(self):
        path = self._vault_path.get()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Error", "Please select an existing vault file.")
            return
        pw = _pw_dialog("Open Vault", "Enter master password:")
        if not pw:
            return
        try:
            vault = PasswordVault(path)
            # Try without 2FA first to detect if it's needed
            try:
                vault.open(pw)
            except TwoFactorRequiredError:
                code = simpledialog.askstring("2FA Code", "Enter your 6-digit TOTP code:", parent=self)
                if not code:
                    return
                vault.open(pw, totp_code=code)
            self._vault = vault
            messagebox.showinfo("Success", "Vault opened.")
            self._refresh_list()
        except WrongPasswordError as exc:
            messagebox.showerror("Authentication Failed", str(exc))
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def _lock_vault(self):
        if self._vault:
            self._vault.close()
            self._vault = None
        self._listbox.delete(0, "end")
        self._clear_detail()
        messagebox.showinfo("Locked", "Vault has been locked.")

    def _toggle_2fa(self):
        if not self._vault or not self._vault.is_open():
            messagebox.showerror("Error", "Please open a vault first.")
            return
        if self._vault.has_2fa():
            if messagebox.askyesno("Disable 2FA", "2FA is currently enabled. Disable it?"):
                self._vault.disable_2fa()
                messagebox.showinfo("2FA", "Two-factor authentication disabled.")
        else:
            if messagebox.askyesno("Enable 2FA", "Enable two-factor authentication for this vault?"):
                uri = self._vault.enable_2fa()
                self._show_qr(uri)
                messagebox.showinfo("2FA", "Two-factor authentication enabled.")

    def _show_qr(self, uri: str):
        """Show a QR code dialog for the TOTP provisioning URI."""
        win = tk.Toplevel(self)
        win.title("Scan QR Code for 2FA")
        win.resizable(False, False)
        win.grab_set()

        img = qrcode.make(uri)
        img = img.resize((240, 240), Image.LANCZOS)
        photo = ImageTk.PhotoImage(img)

        tk.Label(win, text="Scan with your authenticator app:", font=FONT_BOLD).pack(padx=16, pady=(12, 4))
        lbl = tk.Label(win, image=photo)
        lbl.image = photo  # keep reference
        lbl.pack(padx=16, pady=4)
        tk.Label(win, text=uri, font=("Courier", 7), wraplength=300).pack(padx=16, pady=(0, 4))
        tk.Button(win, text="Close", command=win.destroy, font=FONT, width=10).pack(pady=(0, 12))

    def _refresh_list(self):
        self._listbox.delete(0, "end")
        if self._vault and self._vault.is_open():
            for name in self._vault.list_entries():
                self._listbox.insert("end", name)

    def _on_select(self, _event=None):
        sel = self._listbox.curselection()
        if not sel or not self._vault:
            return
        name = self._listbox.get(sel[0])
        try:
            entry = self._vault.get_entry(name)
            self._detail_vars["name"].set(name)
            self._detail_vars["username"].set(entry.get("username", ""))
            self._detail_vars["password"].set(entry.get("password", ""))
            self._detail_vars["url"].set(entry.get("url", ""))
            self._notes_widget.delete("1.0", "end")
            self._notes_widget.insert("end", entry.get("notes", ""))
        except Exception:
            pass

    def _clear_detail(self):
        for v in self._detail_vars.values():
            v.set("")
        self._notes_widget.delete("1.0", "end")

    def _toggle_pw_show(self):
        self._pw_entry.config(show="" if self._show_pw.get() else "*")

    def _generate_password(self):
        try:
            pw = generate_password(
                length=self._gen_len.get(),
                use_upper=self._use_upper.get(),
                use_lower=self._use_lower.get(),
                use_digits=self._use_digits.get(),
                use_symbols=self._use_symbols.get(),
            )
            self._detail_vars["password"].set(pw)
        except ValueError as exc:
            messagebox.showerror("Error", str(exc))

    def _add_entry(self):
        if not self._vault or not self._vault.is_open():
            messagebox.showerror("Error", "Please open a vault first.")
            return
        name = self._detail_vars["name"].get().strip()
        password = self._detail_vars["password"].get()
        if not name:
            messagebox.showerror("Error", "Entry name is required.")
            return
        if not password:
            messagebox.showerror("Error", "Password is required.")
            return
        try:
            self._vault.add_entry(
                name=name,
                password=password,
                username=self._detail_vars["username"].get(),
                url=self._detail_vars["url"].get(),
                notes=self._notes_widget.get("1.0", "end").rstrip("\n"),
            )
            self._refresh_list()
            messagebox.showinfo("Saved", f"Entry '{name}' saved.")
        except Exception as exc:
            messagebox.showerror("Error", str(exc))

    def _delete_entry(self):
        sel = self._listbox.curselection()
        if not sel or not self._vault:
            messagebox.showerror("Error", "Please select an entry to delete.")
            return
        name = self._listbox.get(sel[0])
        if messagebox.askyesno("Confirm Delete", f"Delete entry '{name}'?"):
            try:
                self._vault.delete_entry(name)
                self._refresh_list()
                self._clear_detail()
            except Exception as exc:
                messagebox.showerror("Error", str(exc))

    def _copy_password(self):
        pw = self._detail_vars["password"].get()
        if not pw:
            messagebox.showerror("Error", "No password to copy.")
            return
        self.clipboard_clear()
        self.clipboard_append(pw)
        messagebox.showinfo("Copied", "Password copied to clipboard.")


# ---------------------------------------------------------------------------
# Tab 4 – Secure Delete
# ---------------------------------------------------------------------------

class SecureDeleteTab(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self._file_path = tk.StringVar()
        self._algo = tk.StringVar(value=DELETE_ALGORITHMS[0])
        self._status = tk.StringVar(value="")
        self._progress = tk.DoubleVar(value=0.0)
        self._build()

    def _build(self):
        tk.Label(self, text="Secure File Deletion", font=FONT_TITLE).grid(
            row=0, column=0, columnspan=3, pady=(12, 6), sticky="w", padx=12
        )

        tk.Label(self, text="File to delete:", font=FONT).grid(row=1, column=0, sticky="e", **PAD)
        tk.Entry(self, textvariable=self._file_path, font=FONT, width=42).grid(row=1, column=1, sticky="ew", **PAD)
        tk.Button(self, text="Browse…", command=self._browse, font=FONT).grid(row=1, column=2, **PAD)

        tk.Label(self, text="Algorithm:", font=FONT).grid(row=2, column=0, sticky="e", **PAD)
        ttk.Combobox(
            self, textvariable=self._algo, values=DELETE_ALGORITHMS, state="readonly", font=FONT, width=28
        ).grid(row=2, column=1, sticky="w", **PAD)

        tk.Button(
            self, text="🗑  Securely Delete File", command=self._delete,
            font=FONT_BOLD, bg="#f44336", fg="white", width=24
        ).grid(row=3, column=0, columnspan=3, pady=10)

        ttk.Progressbar(self, variable=self._progress, maximum=100, length=400).grid(
            row=4, column=0, columnspan=3, pady=4, padx=12, sticky="ew"
        )
        tk.Label(self, textvariable=self._status, font=FONT, fg="#555").grid(
            row=5, column=0, columnspan=3, sticky="w", padx=12
        )

        # Info box
        sep = ttk.Separator(self, orient="horizontal")
        sep.grid(row=6, column=0, columnspan=3, sticky="ew", padx=12, pady=10)
        tk.Label(self, text="Algorithm Information", font=FONT_TITLE).grid(row=7, column=0, columnspan=3, sticky="w", padx=12)
        info = (
            "DoD 5220.22-M (7-pass): US Department of Defense standard.\n"
            "  Passes: 0x00, 0xFF, random, 0x96, random, random, random.\n\n"
            "Gutmann (35-pass): Peter Gutmann's algorithm.\n"
            "  4 random passes + 27 specific patterns + 4 random passes.\n"
            "  Designed to defeat magnetic-force microscopy recovery.\n\n"
            "⚠ Note: On SSDs/flash storage, overwrite-based deletion may not fully\n"
            "  sanitize data due to wear levelling. Consider full-disk encryption."
        )
        tk.Label(self, text=info, font=("Segoe UI", 9), justify="left", anchor="w",
                 relief="groove", padx=10, pady=8, bg="#f9f9f9").grid(
            row=8, column=0, columnspan=3, sticky="ew", padx=12, pady=4
        )
        self.columnconfigure(1, weight=1)

    def _browse(self):
        p = filedialog.askopenfilename(title="Select file to securely delete")
        if p:
            self._file_path.set(p)

    def _delete(self):
        path = self._file_path.get()
        if not path:
            messagebox.showerror("Error", "Please select a file to delete.")
            return
        if not os.path.isfile(path):
            messagebox.showerror("Error", f"File not found: {path}")
            return
        algo = self._algo.get()
        passes = 35 if "Gutmann" in algo else 7
        if not messagebox.askyesno(
            "Confirm Secure Delete",
            f"Permanently and securely delete:\n{path}\n\nAlgorithm: {algo}\n\nThis CANNOT be undone!"
        ):
            return

        self._status.set("Deleting…")
        self._progress.set(0)

        def run():
            try:
                # We run in a thread and update progress via a simple approximation
                self.after(100, lambda: self._progress.set(10))
                secure_delete(path, algo)
                self.after(200, lambda: self._progress.set(100))
                self.after(300, lambda: self._status.set("✅ File securely deleted."))
                self.after(400, lambda: messagebox.showinfo("Done", f"File securely deleted using {algo}."))
                self._file_path.set("")
            except Exception as exc:
                self.after(0, lambda: messagebox.showerror("Error", str(exc)))
                self.after(0, lambda: self._status.set("❌ Error."))

        threading.Thread(target=run, daemon=True).start()


# ---------------------------------------------------------------------------
# Main Window
# ---------------------------------------------------------------------------

class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Data Encryption App")
        self.geometry("760x620")
        self.minsize(680, 540)
        self._build()

    def _build(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=8, pady=8)

        tab1 = FileEncryptionTab(notebook)
        tab2 = TextEncryptionTab(notebook)
        tab3 = PasswordManagerTab(notebook)
        tab4 = SecureDeleteTab(notebook)

        notebook.add(tab1, text="  File Encryption  ")
        notebook.add(tab2, text="  Text Encryption  ")
        notebook.add(tab3, text="  Password Manager  ")
        notebook.add(tab4, text="  Secure Delete  ")


def run():
    app = MainWindow()
    app.mainloop()
