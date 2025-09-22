import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import sqlite3
import csv
import matplotlib.pyplot as plt
from collections import defaultdict
import pandas as pd
import hashlib

# ---------- DATABASE ----------
def init_db():
    with sqlite3.connect("inventory.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                price REAL NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        """)
init_db()

# ---------- HASHING ----------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ---------- LOGIN WINDOW ----------
class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Login - Inventory Management")
        self.root.geometry("400x280")

        tk.Label(root, text="Username").pack(pady=5)
        self.username_var = tk.StringVar()
        tk.Entry(root, textvariable=self.username_var).pack()

        tk.Label(root, text="Password").pack(pady=5)
        self.password_var = tk.StringVar()
        tk.Entry(root, textvariable=self.password_var, show="*").pack()

        tk.Button(root, text="Login", command=self.login).pack(pady=10)
        tk.Button(root, text="Register", command=self.open_register).pack()
        tk.Button(root, text="Forgot Password?", command=self.open_forgot).pack(pady=10)



    def login(self):
        username = self.username_var.get()
        password = hash_password(self.password_var.get())

        with sqlite3.connect("inventory.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
            user = cursor.fetchone()

        if user:
            messagebox.showinfo("Login Success", f"Welcome {username} ({user[3]})")
            role = user[3]
            self.root.destroy()
            main_root = tk.Tk()
            InventoryApp(main_root, role)
            main_root.mainloop()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def open_register(self):
        RegisterApp()

    def open_forgot(self):
        ForgotPasswordApp()

# ---------- REGISTER WINDOW ----------
class RegisterApp:
    def __init__(self):
        self.win = tk.Toplevel()
        self.win.title("Register - Inventory Management")
        self.win.geometry("400x300")

        tk.Label(self.win, text="Username").pack(pady=5)
        self.username_var = tk.StringVar()
        tk.Entry(self.win, textvariable=self.username_var).pack()

        tk.Label(self.win, text="Password").pack(pady=5)
        self.password_var = tk.StringVar()
        tk.Entry(self.win, textvariable=self.password_var, show="*").pack()

        tk.Label(self.win, text="Confirm Password").pack(pady=5)
        self.confirm_var = tk.StringVar()
        tk.Entry(self.win, textvariable=self.confirm_var, show="*").pack()

        tk.Label(self.win, text="Role").pack(pady=5)
        self.role_var = tk.StringVar()
        role_combo = ttk.Combobox(self.win, textvariable=self.role_var, values=["Admin", "Staff"], state="readonly")
        role_combo.current(1)
        role_combo.pack()

        tk.Button(self.win, text="Register", command=self.register).pack(pady=10)

    def register(self):
        username = self.username_var.get()
        password = self.password_var.get()
        confirm = self.confirm_var.get()
        role = self.role_var.get()

        if not username or not password or not role:
            messagebox.showwarning("Input Error", "All fields are required")
            return
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return

        try:
            with sqlite3.connect("inventory.db") as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                               (username, hash_password(password), role))
                conn.commit()
            messagebox.showinfo("Success", "Registration successful! Please login.")
            self.win.destroy()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists")

# ---------- FORGOT PASSWORD ----------
class ForgotPasswordApp:
    def __init__(self):
        self.win = tk.Toplevel()
        self.win.title("Reset Password")
        self.win.geometry("400x220")

        tk.Label(self.win, text="Username").pack(pady=5)
        self.username_var = tk.StringVar()
        tk.Entry(self.win, textvariable=self.username_var).pack()

        tk.Label(self.win, text="New Password").pack(pady=5)
        self.new_pass_var = tk.StringVar()
        tk.Entry(self.win, textvariable=self.new_pass_var, show="*").pack()

        tk.Label(self.win, text="Confirm Password").pack(pady=5)
        self.confirm_var = tk.StringVar()
        tk.Entry(self.win, textvariable=self.confirm_var, show="*").pack()

        tk.Button(self.win, text="Reset Password", command=self.reset_password).pack(pady=10)

    def reset_password(self):
        username = self.username_var.get()
        new_pass = self.new_pass_var.get()
        confirm = self.confirm_var.get()

        if not username or not new_pass:
            messagebox.showwarning("Input Error", "All fields are required")
            return
        if new_pass != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return

        with sqlite3.connect("inventory.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username=?", (username,))
            user = cursor.fetchone()

            if not user:
                messagebox.showerror("Error", "Username not found")
                return

            cursor.execute("UPDATE users SET password=? WHERE username=?", 
                           (hash_password(new_pass), username))
            conn.commit()

        messagebox.showinfo("Success", "Password reset successful! You can login now.")
        self.win.destroy()

# ---------- INVENTORY APP ----------
class InventoryApp:
    def __init__(self, root, role):
        self.root = root
        self.role = role
        self.root.title("Inventory Management System")
        self.root.geometry("950x600")

        # Variables
        self.name_var = tk.StringVar()
        self.category_var = tk.StringVar()
        self.quantity_var = tk.StringVar()
        self.price_var = tk.StringVar()
        self.search_var = tk.StringVar()
        self.filter_var = tk.StringVar()

        # ---------- INPUT FRAME ----------
        input_frame = tk.LabelFrame(root, text="Manage Product", padx=10, pady=10)
        input_frame.pack(side=tk.TOP, fill="x", padx=10, pady=5)

        tk.Label(input_frame, text="Name").grid(row=0, column=0)
        tk.Entry(input_frame, textvariable=self.name_var).grid(row=0, column=1, padx=5)

        tk.Label(input_frame, text="Category").grid(row=0, column=2)
        categories = ["Electronics", "Grocery", "Clothing", "Stationery", "Other"]
        self.category_combo = ttk.Combobox(input_frame, textvariable=self.category_var, values=categories, state="readonly")
        self.category_combo.grid(row=0, column=3, padx=5)

        tk.Label(input_frame, text="Quantity").grid(row=0, column=4)
        tk.Entry(input_frame, textvariable=self.quantity_var).grid(row=0, column=5, padx=5)

        tk.Label(input_frame, text="Price").grid(row=0, column=6)
        tk.Entry(input_frame, textvariable=self.price_var).grid(row=0, column=7, padx=5)

        tk.Button(input_frame, text="Add", command=self.add_item, bg="lightgreen").grid(row=1, column=0, pady=5)

        # Admin-only buttons
        self.update_btn = tk.Button(input_frame, text="Update", command=self.update_item, bg="lightblue")
        self.update_btn.grid(row=1, column=1, pady=5)
        self.delete_btn = tk.Button(input_frame, text="Delete", command=self.delete_item, bg="salmon")
        self.delete_btn.grid(row=1, column=2, pady=5)

        tk.Button(input_frame, text="Clear", command=self.clear_inputs).grid(row=1, column=3, pady=5)

        # ---------- SEARCH & FILTER ----------
        filter_frame = tk.LabelFrame(root, text="Search & Filter", padx=10, pady=10)
        filter_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(filter_frame, text="Search by Name").grid(row=0, column=0)
        tk.Entry(filter_frame, textvariable=self.search_var).grid(row=0, column=1, padx=5)
        tk.Button(filter_frame, text="Search", command=self.search_item).grid(row=0, column=2, padx=5)

        tk.Label(filter_frame, text="Filter by Category").grid(row=0, column=3)
        self.filter_combo = ttk.Combobox(filter_frame, textvariable=self.filter_var, values=["All", "Electronics", "Grocery", "Clothing", "Stationery", "Other"], state="readonly")
        self.filter_combo.current(0)
        self.filter_combo.grid(row=0, column=4, padx=5)
        tk.Button(filter_frame, text="Apply Filter", command=self.filter_items).grid(row=0, column=5, padx=5)

        # ---------- TABLE ----------
        table_frame = tk.Frame(root)
        table_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.tree = ttk.Treeview(table_frame, columns=("ID", "Name", "Category", "Quantity", "Price"), show="headings")
        self.tree.heading("ID", text="ID")
        self.tree.heading("Name", text="Name")
        self.tree.heading("Category", text="Category")
        self.tree.heading("Quantity", text="Quantity")
        self.tree.heading("Price", text="Price")
        self.tree.pack(fill="both", expand=True)

        self.tree.bind("<ButtonRelease-1>", self.load_selected)

        # ---------- DASHBOARD ----------
        dashboard_frame = tk.LabelFrame(root, text="Dashboard", padx=10, pady=10)
        dashboard_frame.pack(fill="x", padx=10, pady=5)

        self.total_label = tk.Label(dashboard_frame, text="Total Inventory Value: ₹0", font=("Arial", 12, "bold"))
        self.total_label.pack(side=tk.LEFT, padx=10)

        self.chart_btn = tk.Button(dashboard_frame, text="Show Category Chart", command=self.show_chart)
        self.chart_btn.pack(side=tk.RIGHT, padx=10)

        # ---------- EXPORT ----------
        export_frame = tk.Frame(root)
        export_frame.pack(fill="x", padx=10, pady=5)

        self.export_csv_btn = tk.Button(export_frame, text="Export to CSV", command=self.export_csv)
        self.export_csv_btn.pack(side=tk.LEFT, padx=5)
        self.export_excel_btn = tk.Button(export_frame, text="Export to Excel", command=self.export_excel)
        self.export_excel_btn.pack(side=tk.LEFT, padx=5)

        self.load_items()

        # Restrict features for Staff
        if self.role == "Staff":
            self.update_btn.config(state="disabled")
            self.delete_btn.config(state="disabled")
            self.chart_btn.config(state="disabled")
            self.export_csv_btn.config(state="disabled")
            self.export_excel_btn.config(state="disabled")

    # ---------- FUNCTIONS ----------
    def execute_db(self, query, params=()):
        with sqlite3.connect("inventory.db") as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return cursor

    def add_item(self):
        if not self.name_var.get() or not self.category_var.get() or not self.quantity_var.get() or not self.price_var.get():
            messagebox.showwarning("Input Error", "Please fill all fields")
            return
        try:
            qty = int(self.quantity_var.get())
            price = float(self.price_var.get())
        except:
            messagebox.showwarning("Input Error", "Quantity must be integer and Price must be number")
            return
        self.execute_db("INSERT INTO inventory (name, category, quantity, price) VALUES (?, ?, ?, ?)",
                        (self.name_var.get(), self.category_var.get(), qty, price))
        self.load_items()
        self.clear_inputs()

    def load_items(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        rows = self.execute_db("SELECT * FROM inventory").fetchall()
        for row in rows:
            self.tree.insert("", tk.END, values=row)
        self.update_dashboard()

    def load_selected(self, event):
        selected = self.tree.focus()
        if not selected:
            return
        data = self.tree.item(selected, "values")
        if data:
            self.name_var.set(data[1])
            self.category_var.set(data[2])
            self.quantity_var.set(data[3])
            self.price_var.set(data[4])

    def update_item(self):
        if self.role != "Admin":
            messagebox.showerror("Permission Denied", "Only Admin can update items")
            return
        selected = self.tree.focus()
        if not selected:
            messagebox.showwarning("Selection Error", "No item selected")
            return
        data = self.tree.item(selected, "values")
        self.execute_db("UPDATE inventory SET name=?, category=?, quantity=?, price=? WHERE id=?",
                        (self.name_var.get(), self.category_var.get(), int(self.quantity_var.get()), float(self.price_var.get()), data[0]))
        self.load_items()
        self.clear_inputs()

    def delete_item(self):
        if self.role != "Admin":
            messagebox.showerror("Permission Denied", "Only Admin can delete items")
            return
        selected = self.tree.focus()
        if not selected:
            messagebox.showwarning("Selection Error", "No item selected")
            return
        data = self.tree.item(selected, "values")
        self.execute_db("DELETE FROM inventory WHERE id=?", (data[0],))
        self.load_items()
        self.clear_inputs()

    def clear_inputs(self):
        self.name_var.set("")
        self.category_var.set("")
        self.quantity_var.set("")
        self.price_var.set("")

    def search_item(self):
        query = f"%{self.search_var.get()}%"
        rows = self.execute_db("SELECT * FROM inventory WHERE name LIKE ?", (query,)).fetchall()
        self.display_rows(rows)

    def filter_items(self):
        if self.filter_var.get() == "All":
            self.load_items()
        else:
            rows = self.execute_db("SELECT * FROM inventory WHERE category=?", (self.filter_var.get(),)).fetchall()
            self.display_rows(rows)

    def display_rows(self, rows):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for row in rows:
            self.tree.insert("", tk.END, values=row)
        self.update_dashboard()

    def update_dashboard(self):
        rows = self.execute_db("SELECT category, quantity, price FROM inventory").fetchall()
        total_value = 0
        category_values = defaultdict(float)
        for category, qty, price in rows:
            value = qty * price
            total_value += value
            category_values[category] += value
        self.total_label.config(text=f"Total Inventory Value: ₹{total_value:.2f}")
        self.category_values = category_values

    def show_chart(self):
        if not hasattr(self, "category_values") or not self.category_values:
            messagebox.showinfo("No Data", "No inventory data to show")
            return
        categories = list(self.category_values.keys())
        values = list(self.category_values.values())
        plt.figure(figsize=(6,4))
        plt.bar(categories, values, color="skyblue")
        plt.title("Category-wise Inventory Value")
        plt.xlabel("Category")
        plt.ylabel("Value (₹)")
        plt.show()

    def export_csv(self):
        if self.role != "Admin":
            messagebox.showerror("Permission Denied", "Only Admin can export data")
            return
        rows = self.execute_db("SELECT * FROM inventory").fetchall()
        if not rows:
            messagebox.showinfo("No Data", "Nothing to export")
            return
        file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv")])
        if file:
            with open(file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["ID","Name","Category","Quantity","Price"])
                writer.writerows(rows)
            messagebox.showinfo("Export Success", f"Data exported to {file}")

    def export_excel(self):
        if self.role != "Admin":
            messagebox.showerror("Permission Denied", "Only Admin can export data")
            return
        rows = self.execute_db("SELECT * FROM inventory").fetchall()
        if not rows:
            messagebox.showinfo("No Data", "Nothing to export")
            return
        df = pd.DataFrame(rows, columns=["ID","Name","Category","Quantity","Price"])
        file = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files","*.xlsx")])
        if file:
            df.to_excel(file, index=False)
            messagebox.showinfo("Export Success", f"Data exported to {file}")


# ---------- RUN ----------
if __name__ == "__main__":
    root = tk.Tk()
    LoginApp(root)
    root.mainloop()

