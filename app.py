import os
import re
import io
from cs50 import SQL
from datetime import date
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
import datetime
import pytz
from tzlocal import get_localzone

from PIL import Image
from helpers import apology, login_required
import base64



# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite databse
db = SQL("sqlite:///inventory.db")

current_date = date.today().strftime('%Y-%m-%d')

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Shorten request.form.get
def getback(key):
    return request.form.get(key)

# Purify tag
def tags_std(tags):
    while tags.startswith((',', ' ', '，', '、')) or tags.endswith((',', ' ', '，', '、')):
        tags = tags.strip(' ,，、')
    tags = re.sub(r'[,，\s、]+',',', tags)
    tags = tags.split(',')
    tags = ', '.join(tags)
    return tags

# Convert binary to url
def btou(image_file):
    img_data_base64 = base64.b64encode(image_file).decode('utf-8')
    img_data_url = f"data:image/jpeg;base64,{img_data_base64}"
    return img_data_url

def reduce_size(binary_img, width, height):
    img = Image.open(io.BytesIO(binary_img))
    img = img.resize((width, height))
    buffer = io.BytesIO()
    img.save(buffer, format='JPEG')
    return buffer.getvalue()



# Get UTC and local time
def utc_time ():
    return datetime.datetime.now(datetime.UTC)


#Get current year
current_year = datetime.datetime.now().year


# Get Local time from UTC
def utc_to_local(utc_string):
    # Convert the UTC string to a datetime object
    utc_dt = datetime.datetime.strptime(utc_string, '%Y-%m-%d %H:%M:%S')

    # Convert to local time
    local_dt = utc_dt.replace(tzinfo=pytz.utc).astimezone('Asia/Tokyo')

    # Format the local time as a string
    local_time_str = local_dt.strftime('%Y-%m-%d')
    return local_time_str + "JST"



@app.route("/")
@login_required
def index():
    # Create list of dictionaries
    rows = db.execute("SELECT * FROM items")
    # Iterate over each list
    for row in rows:
        # Resize
        row["img"] = reduce_size(row["img"], 150, 150)
        row["img"] = btou(row["img"])
    return render_template("index.html", rows = rows)

@app.route("/search")
@login_required
def search():
    query = request.args.get('q').strip().split()
    query = [element.lower() for element in query]
    all_row = db.execute("SELECT * FROM items")

    result_list = []

    for each in all_row:
        match = 0
        for element in query:
            if element == str(each['id']) or element in each['item_name'].lower() or element in each['tags'].lower():
                match += 1
        if match == len(query):
            result_list.append(each['id'])
    return jsonify(result_list)



@app.route("/item/<int:item_id>", methods=["GET", "POST"])
def item(item_id):
    if request.method == "POST":
        # Get Time
        utc = utc_time()
        # Set user_id
        user_id = session["user_id"]
        # If edit form
        if getback("formUsage") == "edit":
            item_name, stocks, tags, material = getback("item_name"), getback("stocks"), getback("tags"), getback("material")
            # Get tags and clean it
            if getback("tags"):
                tags = getback("tags")
                tags = tags_std(tags)
            else:
                tags = None
            # Get img
            img_file = request.files.get('item_img')
            if img_file:
                item_img = img_file.read()
                item_img = reduce_size(item_img, 600, 600)
            else:
                item_img = None
            # Validate the inputs and update database
            if not item_name or not material or not stocks or int(stocks) < 0 or material not in (["ceramic", "glass", "metal", "wood", "rattan", "fabric", "others"]):
                flash('Blank or invalid inputs', 'danger')
                return redirect(f"/item/{item_id}")
            else:
                db.execute("UPDATE items SET item_name = ?, stocks = ?, tags = ?, material = ? WHERE id = ?", item_name, stocks, tags, material, item_id)
            if item_img:
                db.execute("UPDATE items SET img = ? WHERE id = ?", item_img, item_id)
            return redirect(f"/item/{item_id}")

        # If buy or sell form or edit transaction
        elif getback("formUsage") == "buy" or getback("formUsage") == "sell" or getback("formUsage") == "edit_transaction":
            qty, price, total, note, currency = getback("quantity"), getback("price"), getback("total"), getback("notes"), getback("currency")

            # Check input existence
            if not qty or not price or not total:
                flash('Blank inputs', 'danger')
                return redirect(f"/item/{item_id}")
            # Convert to numbers
            qty = int(qty)
            if float(price) == int(float(price)):
                price = int(float(price))
            else:
                price = round(float(price), 2)
            if float(total) == int(float(total)):
                total = int(float(total))
            else:
                total = round(float(total), 2)
            # Validate input
            if qty < 1 or price < 0 or total < 0:
                flash('invalid inputs', 'danger')
                return redirect(f"/item/{item_id}")

            if note != "" or note != None:
                db.execute("INSERT INTO notes (item_id, note, timestamp) VALUES (?, ?, ?)", item_id, note, utc)

            if getback("formUsage") == "buy":
                db.execute("INSERT INTO transactions (item_id, type, price, quantity, timestamp, person, currency) VALUES (?, 'buy', ?, ?, ?, ?, ?)", item_id, price, qty, utc, user_id, currency)
                db.execute("UPDATE items SET stocks = stocks + ? WHERE id = ?", qty, item_id)
                return redirect(f"/item/{item_id}")
            elif getback("formUsage") == "sell":
                db.execute("INSERT INTO transactions (item_id, type, price, quantity, timestamp, person) VALUES (?, 'sell', ?, ?, ?, ?)", item_id, price, qty, utc, user_id)
                db.execute("UPDATE items SET stocks = stocks - ? WHERE id = ?", qty, item_id)
                return redirect(f"/item/{item_id}")
            else:
                # Get transaction ID
                transaction_id = getback("formName")
                qty_before = db.execute("SELECT quantity FROM transactions WHERE id = ?", transaction_id)[0]["quantity"]
                qty_difference = int(qty_before) - int(qty)
                transaction_type = db.execute("SELECT type FROM transactions WHERE id = ?", transaction_id)[0]["type"]
                db.execute("UPDATE transactions SET status = 'edited' WHERE id = ?", transaction_id)
                db.execute("UPDATE transactions SET price = ?, quantity = ? WHERE id = ?", price, qty, transaction_id)
                if transaction_type == "buy":
                    db.execute("UPDATE items SET stocks = stocks - ? WHERE id = ?", qty_difference, item_id)
                    return redirect(f"/item/{item_id}")
                if transaction_type == "sell":
                    db.execute("UPDATE items SET stocks = stocks + ? WHERE id = ?", qty_difference, item_id)
                    return redirect(f"/item/{item_id}")

        elif getback("formUsage") == "reverse_transaction":
            transaction_id = getback("transactionId")
            transaction_qty = getback("formQty")
            db.execute("UPDATE transactions SET status = 'reversed' WHERE id = ?", transaction_id)
            transaction_type = db.execute("SELECT type FROM transactions WHERE id = ?", transaction_id)[0]["type"]
            if transaction_type == "buy":
                db.execute("UPDATE items SET stocks = stocks - ? WHERE id = ?", transaction_qty, item_id)
                return redirect(f"/item/{item_id}")
            if transaction_type == "sell":
                db.execute("UPDATE items SET stocks = stocks + ? WHERE id = ?", transaction_qty, item_id)
                return redirect(f"/item/{item_id}")

        elif getback("formUsage") == "add_notes":

            note = getback("note_input")
            print(f"note content: ", note)
            if note == None or note == "":
                flash('Blank input', 'danger')
                return redirect(f"/item/{item_id}")
            else:
                db.execute("INSERT INTO notes (item_id, note, timestamp) VALUES (?, ?, ?)", item_id, note, utc)
                return redirect(f"/item/{item_id}")
        else:
            return redirect(f"/item/{item_id}")

    else:
        item = db.execute("SELECT * FROM items JOIN transactions ON items.id = transactions.item_id WHERE items.id == ?", item_id)
        item[0]['img'] = btou(item[0]['img'])

        transactions = db.execute("SELECT transactions.id, type, price, quantity, timestamp, currency, status, contact FROM transactions JOIN users ON transactions.person = users.id WHERE transactions.item_id = ? ORDER BY timestamp DESC", item_id)
        for transaction in transactions:
            transaction['timestamp'] = utc_to_local(transaction['timestamp'])

        notes = db.execute("SELECT * FROM notes WHERE item_id = ? ORDER BY timestamp DESC", item_id)
        for note in notes:
            note['note'] = note['note'] + "\n"
            note['timestamp'] = utc_to_local(note['timestamp'])

        return render_template("item.html", item = item, item_id = item_id, transactions = transactions, notes = notes, current_year = current_year)


@app.route("/login", methods=["GET", "POST"])
def login():

    # Forget any user_id
    if session.get("user_id") != None:
        session.clear()

    # User reached route via POST
    if request.method == "POST":
        # Ensure username was submitted
        if not getback("username"):
            flash('Must Provide Username', 'danger')
            return render_template("login.html")

        # Ensure password ^^
        if not getback("password"):
            flash('Must Provide Password', 'danger')
            return render_template("login.html")

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", getback("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], getback("password")
        ):
            flash('Invalid username and/or password', 'danger')
            return render_template("login.html")

        # Ensure user is approved
        if rows[0]["is_approved"] != True:
            flash('Account not approved by admin', 'danger')
            return render_template("login.html")

        # Remember which user logged in and whether if is admin
        session["user_id"] = rows[0]["id"]
        if db.execute("SELECT admin FROM users WHERE id = ?", session["user_id"])[0]['admin'] == True:
            session["admin"] = True

        # Redirect to home page
        flash('login successful', 'primary')
        return redirect("/")

    else:
        return render_template("login.html")


@app.route("/logout")
def logout():

    # Forget user_id
    session.clear()

    return redirect("/")

@app.route("/transactions", methods=["GET", "POST"])
@login_required
def transactions():
    if request.method == "POST":

        type, currency, price = getback("typeSelect"), getback("currencySelect"), getback("priceInput")
        if (type != 'expense' and type != 'revenue') or (currency != 'yen' and currency != 'yuan') or not price:
            flash('Blank or invalid input', 'danger')
            return redirect("/transactions")


        db.execute("INSERT INTO transactions (type, price, quantity, timestamp, person, currency) VALUES (?, ?, 1, ?, ?, ?)", type, price, utc_time(), session["user_id"], currency)
        return redirect("/transactions")

    else:
        transactions = db.execute(
                "SELECT transactions.id, transactions.item_id, transactions.type, transactions.quantity, transactions.price, transactions.timestamp, transactions.currency, transactions.person, transactions.status, items.item_name FROM transactions LEFT JOIN items ON transactions.item_id = items.id ORDER BY timestamp DESC")
        for transaction in transactions:
                transaction['timestamp'] = utc_to_local(transaction['timestamp'])

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            query = request.args.get('q').strip().split()
            query = [element.lower() for element in query]

            result_list = []

            for each in transactions:
                if not each['item_name']:
                    each['item_name'] = 'others'
                match = 0
                for element in query:
                    if element == str(each['id']) or element in each['item_name'].lower():
                        match += 1
                if match == len(query):
                    result_list.append(each['id'])
            return jsonify(result_list)
        else:
            return render_template("transactions.html", transactions = transactions, current_year = current_year)


@app.route("/add_new", methods=["GET", "POST"])
@login_required
def add_new():

    if request.method == "POST":
        # Get Time
        utc = utc_time()
        # Retrieve form data and get user_id
        item_name, price, quantity, material, user_id = getback("item_name"), getback("price"), getback("quantity"), getback("material"), session["user_id"]

        # Get tags and clean it
        if getback("tags"):
            tags = getback("tags")
            tags = tags_std(tags)
        else:
            tags = None


        # Store img to variable
        img_file = request.files.get('item_img')
        if img_file:
            item_img = img_file.read()
            item_img = reduce_size(item_img, 600, 600)

        else:
            item_img = None


        # Check if relevant data exist and valid
        if not item_name or not price or not quantity or material not in ["ceramic", "glass", "metal", "wood", "rattan", "fabric", "others"]:
            flash('All fields marked with * are required', 'danger')
            return redirect("/add_new")
        else:
            # Add to items table
            db.execute(
                "INSERT INTO items (item_name, img, tags, stocks, material) VALUES(?, ?, ?, ?, ?)", item_name, item_img, tags, quantity, material)
            item_id = db.execute("SELECT last_insert_rowid()")[0]['last_insert_rowid()']
            # Add to transactions table
            db.execute(
                "INSERT INTO transactions (item_id, type, price, quantity, person, timestamp) VALUES (?, ?, ?, ?, ?, ?)", item_id, "buy", price, quantity, user_id, utc)
            flash('Successfully added', 'success')
            return redirect("/")
    else:
        return render_template("add_new.html")




@app.route("/registrants", methods=["GET", "POST"])
@login_required
def registrants():
    admin = db.execute("SELECT admin FROM users WHERE id = ?", session["user_id"])[0]['admin']
    if admin != 1:
        session.clear()
        return redirect("/")

    if request.method == "POST":
        person_id = getback("person_id")
        access = getback("access")

        if access == "user":
            db.execute("UPDATE users SET admin = 0, is_approved = 1 WHERE id = ?", person_id)
            return redirect("/registrants")
        elif access == "admin":
            db.execute("UPDATE users SET admin = 1, is_approved = 1 WHERE id = ?", person_id)
            return redirect("/registrants")
        elif access == "delete":
            db.execute("DELETE FROM users WHERE id = ?", person_id)
            return redirect("/registrants")
        else:
            flash('Invalid submission', 'danger')
            return redirect("/registrants")

    else:
        all = db.execute("SELECT id, username, admin, contact FROM users WHERE is_approved = 1 ORDER BY id DESC")
        new = db.execute("SELECT id, username, admin, contact FROM users WHERE is_approved = 0 ORDER BY id DESC")
        return render_template("registrants.html", all = all, new = new)






@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        # Create variable for user's input username
        username = getback("username")
        # Select same username from database
        same_username = db.execute("SELECT * FROM users WHERE username = ?", username)

        # If user did not enter a username
        if not username:
            flash('Please choose a username', 'danger')
            return render_template("register.html")
        # If username already existed and valid length
        elif same_username:
            flash('Username already exists', 'danger')
            return render_template("register.html")
        elif len(username) < 5 or len(username) > 15:
            flash('Invalid username length', 'danger')
            return render_template("register.html")

        # Create variable for user's password input and check if password exist and valid length
        password = getback("password")
        if not password:
            flash('Please enter a password', 'danger')
            return render_template("register.html")
        elif len(password) < 5 or len(password) > 15:
            flash('Invalid password length', 'danger')
            return render_template("register.html")

        # Check if confirmation password exists and matches
        confirmation =getback("confirmation")
        if not confirmation:
            flash('Please reEnter your password for confimation', 'danger')
            return render_template("register.html")
        elif confirmation != password:
            flash('Passwords does not match', 'danger')

        # Hash the password and add registrants to database
        hash = generate_password_hash(password)
        contact = getback("contact")
        db.execute("INSERT INTO users (username, hash, contact) VALUES (?, ?, ?)", username, hash, contact)
        flash('Registered! You can log in once admin approves your registration', 'primary')
        return redirect("/login")
    else:
        return render_template("register.html")




