import customtkinter as ctk

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")


class WarningPopup(ctk.CTk):
    def __init__(
        self,
        threat_type,
        threat_desc,
        on_allow,
        on_block,
        on_sanitize,
        risk_level="MEDIUM",
        explanation: str | None = None,
        policy_enforcement: str | None = None,
    ):
        super().__init__()

        self.on_allow_callback = on_allow
        self.on_block_callback = on_block
        self.on_sanitize_callback = on_sanitize
        self.risk_level = (risk_level or "MEDIUM").upper()
        self.policy_enforcement = (policy_enforcement or "BLOCK").upper()
        self.explanation = explanation or ""

        # Risk-based header colors
        risk_colors = {
            "CRITICAL": ("#7f1d1d", "#fecaca"),
            "HIGH": ("#78350f", "#fed7aa"),
            "MEDIUM": ("#1e3a8a", "#bfdbfe"),
            "LOW": ("#047857", "#bbf7d0"),
        }
        header_bg, header_text = risk_colors.get(self.risk_level, ("#450a0a", "#fca5a5"))

        # Window Setup
        self.title("Blip Security Alert")
        self.geometry("480x380")
        self.resizable(False, False)
        self.attributes("-topmost", True)
        self.lift()
        self.focus_force()

        # 1. Header
        self.header = ctk.CTkFrame(self, fg_color=header_bg, height=60, corner_radius=0)
        self.header.pack(fill="x", side="top")

        header_text_label = f"⚠️  {self.risk_level} RISK DETECTED ({self.policy_enforcement})"

        self.label_header = ctk.CTkLabel(
            self.header,
            text=header_text_label,
            text_color=header_text,
            font=("Roboto", 14, "bold"),
        )
        self.label_header.place(relx=0.5, rely=0.5, anchor="center")

        # 2. Content
        self.content = ctk.CTkFrame(self, fg_color="transparent")
        self.content.pack(expand=True, fill="both", padx=20, pady=10)

        self.info_label = ctk.CTkLabel(
            self.content,
            text=(
                "Blip has intercepted sensitive content on your clipboard.\n\n"
                f"Type: {threat_type}\n"
                f"Risk: {self.risk_level}\n"
                f"Detail: {threat_desc}"
            ),
            font=("Arial", 13),
            text_color="white",
            justify="left",
            wraplength=430,
        )
        self.info_label.pack(pady=(0, 6), anchor="w")

        if self.explanation:
            self.expl_label = ctk.CTkLabel(
                self.content,
                text=self.explanation,
                font=("Arial", 11),
                text_color="#9ca3af",
                justify="left",
                wraplength=430,
            )
            self.expl_label.pack(pady=(4, 4), anchor="w")

        # 3. Actions
        self.actions = ctk.CTkFrame(self, height=100, fg_color="transparent")
        self.actions.pack(fill="x", side="bottom", pady=20, padx=20)

        self.btn_sanitize = ctk.CTkButton(
            self.actions,
            text="✨ SANITIZE & PASTE",
            fg_color="#3b82f6",
            hover_color="#2563eb",
            font=("Arial", 12, "bold"),
            command=self.sanitize_action,
            width=430,
        )
        self.btn_sanitize.pack(side="top", pady=(0, 10))

        self.bottom_row = ctk.CTkFrame(self.actions, fg_color="transparent")
        self.bottom_row.pack(side="top", fill="x")

        self.btn_cancel = ctk.CTkButton(
            self.bottom_row,
            text="BLOCK",
            fg_color="#ef4444",
            hover_color="#b91c1c",
            font=("Arial", 12, "bold"),
            command=self.block_action,
            width=210,
        )
        self.btn_cancel.pack(side="left")

        self.btn_allow = ctk.CTkButton(
            self.bottom_row,
            text="ALLOW",
            fg_color="transparent",
            border_width=1,
            border_color="#94a3b8",
            text_color="#94a3b8",
            hover_color="#334155",
            font=("Arial", 12),
            command=self.allow_action,
            width=210,
        )
        self.btn_allow.pack(side="right")

    def _close(self):
        """Helper to close cleanly"""
        self.quit()  # Stop the mainloop first
        self.destroy()  # Then kill the window

    def block_action(self):
        self.on_block_callback()
        self._close()

    def allow_action(self):
        self.on_allow_callback()
        self._close()

    def sanitize_action(self):
        self.on_sanitize_callback()
        self._close()


def show_alert(
    threat_type,
    threat_desc,
    on_allow,
    on_block,
    on_sanitize,
    risk_level=None,
    explanation: str | None = None,
    policy_enforcement: str | None = None,
):
    app = WarningPopup(
        threat_type,
        threat_desc,
        on_allow,
        on_block,
        on_sanitize,
        risk_level=risk_level or "MEDIUM",
        explanation=explanation,
        policy_enforcement=policy_enforcement,
    )
    try:
        app.mainloop()
    except KeyboardInterrupt:
        app.destroy()