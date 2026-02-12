import customtkinter as ctk
import sys

# Configuration for the UI
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

class WarningPopup(ctk.CTk):
    def __init__(self, threat_type, threat_desc, on_allow, on_block):
        super().__init__()

        self.on_allow_callback = on_allow
        self.on_block_callback = on_block

        # Window Setup
        self.title("Blip Security Alert")
        self.geometry("400x250")
        self.resizable(False, False)
        
        # Make it stay on top of everything (The "System Modal" effect)
        self.attributes("-topmost", True)
        self.lift()
        self.focus_force()

        # --- UI LAYOUT ---
        
        # 1. Header (Red Warning)
        self.header = ctk.CTkFrame(self, fg_color="#450a0a", height=50, corner_radius=0)
        self.header.pack(fill="x", side="top")
        
        self.label_header = ctk.CTkLabel(
            self.header, 
            text="⚠️  SECURITY VIOLATION DETECTED", 
            text_color="#fca5a5",
            font=("Roboto", 14, "bold")
        )
        self.label_header.place(relx=0.5, rely=0.5, anchor="center")

        # 2. Content (Threat Details)
        self.content = ctk.CTkFrame(self, fg_color="transparent")
        self.content.pack(expand=True, fill="both", padx=20, pady=20)

        self.info_label = ctk.CTkLabel(
            self.content,
            text=f"Blip has intercepted sensitive content on your clipboard.\n\nType: {threat_type}\nDetail: {threat_desc}",
            font=("Arial", 13),
            text_color="white",
            justify="left",
            wraplength=360
        )
        self.info_label.pack(pady=10)

        # 3. Buttons (Action Bar)
        self.actions = ctk.CTkFrame(self, height=60, fg_color="transparent")
        self.actions.pack(fill="x", side="bottom", pady=15, padx=20)

        # Button: CANCEL (Block)
        self.btn_cancel = ctk.CTkButton(
            self.actions,
            text="BLOCK & DELETE",
            fg_color="#ef4444",
            hover_color="#b91c1c",
            font=("Arial", 12, "bold"),
            command=self.block_action,
            width=170
        )
        self.btn_cancel.pack(side="left", padx=(0, 10))

        # Button: ALLOW (Risk)
        self.btn_allow = ctk.CTkButton(
            self.actions,
            text="ALLOW ONCE",
            fg_color="transparent",
            border_width=1,
            border_color="#94a3b8",
            text_color="#94a3b8",
            hover_color="#334155",
            font=("Arial", 12),
            command=self.allow_action,
            width=170
        )
        self.btn_allow.pack(side="right")

    def block_action(self):
        """User chose to Block"""
        self.on_block_callback()
        self.destroy()

    def allow_action(self):
        """User chose to Allow (Dangerous)"""
        self.on_allow_callback()
        self.destroy()

# Helper function to launch the popup easily from other files
def show_alert(threat_type, threat_desc, on_allow, on_block):
    app = WarningPopup(threat_type, threat_desc, on_allow, on_block)
    app.mainloop()