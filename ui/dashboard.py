import json
import os
from collections import Counter
from datetime import datetime, timedelta

import customtkinter as ctk

from utils.logger import LOG_FILE


class AdminDashboard(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Blip Admin Dashboard")
        self.geometry("1000x650")
        self.resizable(True, True)
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("dark-blue")

        # Data cache
        self._all_logs = []

        self._build_ui()
        self._load_data()

    def _build_ui(self):
        # Header
        header = ctk.CTkFrame(self, fg_color="#020617")
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            header,
            text="🛡️ Blip Endpoint Sentinel – Admin View",
            font=("Roboto", 18, "bold"),
        )
        title.grid(row=0, column=0, padx=20, pady=(10, 0), sticky="w")

        subtitle = ctk.CTkLabel(
            header,
            text="Live overview of clipboard security incidents across this endpoint.",
            font=("Roboto", 12),
            text_color="#9ca3af",
        )
        subtitle.grid(row=1, column=0, padx=20, pady=(0, 6), sticky="w")

        # Filter row
        filter_row = ctk.CTkFrame(header, fg_color="transparent")
        filter_row.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="ew")
        for i in range(4):
            filter_row.grid_columnconfigure(i, weight=1)

        self.user_filter = ctk.CTkOptionMenu(
            filter_row,
            values=["All"],
            command=lambda _v: self._apply_filters(),
        )
        self.user_filter.set("All")
        self.user_filter.grid(row=0, column=0, padx=(0, 8), pady=4, sticky="ew")

        self.action_filter = ctk.CTkOptionMenu(
            filter_row,
            values=["All", "BLOCKED", "ALLOWED", "SANITIZED", "LOGGED"],
            command=lambda _v: self._apply_filters(),
        )
        self.action_filter.set("All")
        self.action_filter.grid(row=0, column=1, padx=8, pady=4, sticky="ew")

        self.source_filter = ctk.CTkOptionMenu(
            filter_row,
            values=["All", "text", "image"],
            command=lambda _v: self._apply_filters(),
        )
        self.source_filter.set("All")
        self.source_filter.grid(row=0, column=2, padx=8, pady=4, sticky="ew")

        self.time_filter = ctk.CTkOptionMenu(
            filter_row,
            values=["All time", "Last 24h", "Last 7 days", "Last 30 days"],
            command=lambda _v: self._apply_filters(),
        )
        self.time_filter.set("All time")
        self.time_filter.grid(row=0, column=3, padx=(8, 0), pady=4, sticky="ew")

        # Main content layout
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=1, column=0, sticky="nsew", padx=16, pady=16)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)

        # Top stats row
        stats_row = ctk.CTkFrame(main, fg_color="#020617")
        stats_row.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        for i in range(4):
            stats_row.grid_columnconfigure(i, weight=1)

        self.stat_total = self._stat_card(stats_row, 0, "Total Incidents", "0")
        self.stat_blocked = self._stat_card(stats_row, 1, "Blocked", "0", accent="#ef4444")
        self.stat_allowed = self._stat_card(stats_row, 2, "Allowed", "0", accent="#22c55e")
        self.stat_sanitized = self._stat_card(stats_row, 3, "Sanitized", "0", accent="#3b82f6")

        # Middle row: breakdowns + timeline
        middle = ctk.CTkFrame(main, fg_color="transparent")
        middle.grid(row=1, column=0, sticky="nsew")
        middle.grid_columnconfigure(0, weight=1)
        middle.grid_columnconfigure(1, weight=2)
        middle.grid_rowconfigure(0, weight=1)

        # Breakdown panel
        breakdown = ctk.CTkFrame(middle, fg_color="#020617")
        breakdown.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        breakdown.grid_rowconfigure(3, weight=1)
        breakdown.grid_columnconfigure(0, weight=1)

        lbl_breakdown = ctk.CTkLabel(
            breakdown, text="Breakdown", font=("Roboto", 14, "bold")
        )
        lbl_breakdown.grid(row=0, column=0, padx=12, pady=(10, 0), sticky="w")

        self.lbl_users = ctk.CTkLabel(
            breakdown,
            text="Users: -",
            font=("Roboto", 12),
            text_color="#9ca3af",
            justify="left",
        )
        self.lbl_users.grid(row=1, column=0, padx=12, pady=(4, 0), sticky="w")

        self.lbl_types = ctk.CTkLabel(
            breakdown,
            text="Top Threat Types:\n-",
            font=("Roboto", 12),
            text_color="#9ca3af",
            justify="left",
        )
        self.lbl_types.grid(row=2, column=0, padx=12, pady=(4, 0), sticky="nw")

        self.lbl_policy = ctk.CTkLabel(
            breakdown,
            text="Policy Enforcement Mix:\n-",
            font=("Roboto", 12),
            text_color="#9ca3af",
            justify="left",
        )
        self.lbl_policy.grid(row=3, column=0, padx=12, pady=(4, 12), sticky="nw")

        # Recent incidents table
        table_frame = ctk.CTkFrame(middle, fg_color="#020617")
        table_frame.grid(row=0, column=1, sticky="nsew")
        table_frame.grid_rowconfigure(1, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        lbl_recent = ctk.CTkLabel(
            table_frame, text="Recent Incidents", font=("Roboto", 14, "bold")
        )
        lbl_recent.grid(row=0, column=0, padx=12, pady=(10, 0), sticky="w")

        self.table = ctk.CTkScrollableFrame(table_frame, fg_color="transparent")
        self.table.grid(row=1, column=0, sticky="nsew", padx=12, pady=8)

    def _stat_card(self, parent, col, title, value, accent="#6366f1"):
        card = ctk.CTkFrame(parent, fg_color="#020617", corner_radius=10)
        card.grid(row=0, column=col, padx=6, pady=8, sticky="nsew")

        lbl_title = ctk.CTkLabel(
            card, text=title, font=("Roboto", 12), text_color="#9ca3af"
        )
        lbl_title.pack(anchor="w", padx=12, pady=(10, 0))

        lbl_value = ctk.CTkLabel(
            card, text=value, font=("Roboto", 20, "bold"), text_color=accent
        )
        lbl_value.pack(anchor="w", padx=12, pady=(0, 10))

        return lbl_value

    def _load_data(self):
        if not os.path.exists(LOG_FILE):
            self._all_logs = []
            self._populate_ui([])
            return

        try:
            with open(LOG_FILE, "r") as f:
                content = f.read().strip()
                self._all_logs = json.loads(content) if content else []
        except Exception:
            self._all_logs = []

        # Initialize user filter options
        users = sorted(
            {
                f"{entry.get('username', 'unknown')}@{entry.get('hostname', '-')}"
                for entry in self._all_logs
            }
        )
        self.user_filter.configure(values=["All"] + users)

        self._apply_filters()

    def _apply_filters(self):
        logs = list(self._all_logs)

        # User filter
        user_val = self.user_filter.get()
        if user_val and user_val != "All":
            def matches_user(entry):
                user = entry.get("username", "unknown")
                host = entry.get("hostname", "-")
                return f"{user}@{host}" == user_val

            logs = [e for e in logs if matches_user(e)]

        # Action filter
        action_val = self.action_filter.get()
        if action_val and action_val != "All":
            logs = [e for e in logs if e.get("action_taken") == action_val]

        # Source filter
        source_val = self.source_filter.get()
        if source_val and source_val != "All":
            logs = [e for e in logs if e.get("source") == source_val]

        # Time filter
        range_val = self.time_filter.get()
        if range_val != "All time":
            now = datetime.now()
            if range_val == "Last 24h":
                cutoff = now - timedelta(hours=24)
            elif range_val == "Last 7 days":
                cutoff = now - timedelta(days=7)
            else:
                cutoff = now - timedelta(days=30)

            def in_range(entry):
                ts = entry.get("timestamp")
                try:
                    dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                    return dt >= cutoff
                except Exception:
                    return True

            logs = [e for e in logs if in_range(e)]

        self._populate_ui(logs)

    def _populate_ui(self, logs):
        total = len(logs)
        by_action = Counter(entry.get("action_taken", "UNKNOWN") for entry in logs)
        by_user = Counter(
            f"{entry.get('username', 'unknown')}@{entry.get('hostname', '-')}"
            for entry in logs
        )
        by_type = Counter(entry.get("threat_type", "Unknown") for entry in logs)
        by_policy = Counter(
            entry.get("policy_enforcement", "BLOCK") for entry in logs
        )

        self.stat_total.configure(text=str(total))
        self.stat_blocked.configure(text=str(by_action.get("BLOCKED", 0)))
        self.stat_allowed.configure(text=str(by_action.get("ALLOWED", 0)))
        self.stat_sanitized.configure(text=str(by_action.get("SANITIZED", 0)))

        # Users summary
        top_users = by_user.most_common(3)
        users_text_lines = [
            "Top Users (by incidents):",
        ]
        if top_users:
            for user, count in top_users:
                users_text_lines.append(f"- {user}: {count}")
        else:
            users_text_lines.append("- No incidents logged yet.")
        self.lbl_users.configure(text="\n".join(users_text_lines))

        # Threat types summary
        top_types = by_type.most_common(5)
        types_text_lines = ["Top Threat Types:"]
        if top_types:
            max_count = top_types[0][1]
            for t, count in top_types:
                bar = "█" * max(1, int((count / max_count) * 10))
                types_text_lines.append(f"- {t}: {count} {bar}")
        else:
            types_text_lines.append("- No incidents logged yet.")
        self.lbl_types.configure(text="\n".join(types_text_lines))

        # Policy enforcement mix
        policy_lines = ["Policy Enforcement Mix:"]
        if by_policy:
            total_p = sum(by_policy.values())
            for mode, count in by_policy.items():
                pct = (count / total_p) * 100 if total_p else 0
                policy_lines.append(f"- {mode}: {count} ({pct:.0f}%)")
        else:
            policy_lines.append("- No incidents logged yet.")
        self.lbl_policy.configure(text="\n".join(policy_lines))

        # Recent incidents table (latest first)
        for widget in self.table.winfo_children():
            widget.destroy()

        headers = ["Time", "User", "Action", "Type", "Risk", "Source", "Policy"]
        for col, h in enumerate(headers):
            lbl = ctk.CTkLabel(
                self.table,
                text=h,
                font=("Roboto", 11, "bold"),
                text_color="#e5e7eb",
            )
            lbl.grid(row=0, column=col, padx=4, pady=(0, 4), sticky="w")

        for row_idx, entry in enumerate(reversed(logs[-200:]), start=1):
            user = entry.get("username", "unknown")
            host = entry.get("hostname", "-")
            cells = [
                entry.get("timestamp", ""),
                f"{user}@{host}",
                entry.get("action_taken", ""),
                entry.get("threat_type", ""),
                entry.get("risk_level", "-"),
                entry.get("source", "-"),
                entry.get("policy_enforcement", "-"),
            ]
            for col_idx, value in enumerate(cells):
                lbl = ctk.CTkLabel(
                    self.table,
                    text=str(value),
                    font=("Roboto", 11),
                    text_color="#d1d5db",
                    anchor="w",
                )
                lbl.grid(row=row_idx, column=col_idx, padx=4, pady=1, sticky="w")


def launch_dashboard():
    app = AdminDashboard()
    app.mainloop()


if __name__ == "__main__":
    launch_dashboard()


