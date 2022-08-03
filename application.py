import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Show portfolio of stocks"""
    # User reached route via GET (as by clicking a link or via redirect)
    if request.method== "POST":
        return render_template("change.html")
    else:
        # Update the latest price information for the existing stock
        user_id = session["user_id"]
        stock_list = db.execute("SELECT stock_id, stock_symbol, shares, unit_price, total_price FROM stocks WHERE owner_name == %s", session["user_id"])
        # Iterate through dictionaries in the results (list of rows(dicts))
        length = len(stock_list)
        for i in range(length):
            stock_id = stock_list[i]["stock_id"]
            symbol = stock_list[i]["stock_symbol"]
            amount = stock_list[i]["shares"]
            price_dict = lookup(symbol)
            price = price_dict["price"]
            total = price * amount

            # Update stocks table for the logged in user
            db.execute("UPDATE stocks SET unit_price = ?, total_price = ? WHERE stock_id = ?", price, total, stock_id)

        # Extract updated data and display in the template
        rows = db.execute("SELECT stock_symbol, stock_name, shares, unit_price, total_price FROM stocks WHERE owner_name == %s", session["user_id"])
        rows2 = db.execute("SELECT cash FROM users WHERE username == %s", session["user_id"])

        assets_list = db.execute("SELECT total_price FROM stocks WHERE owner_name == %s", session["user_id"])
        stock_assets = 0.00
        cash_asset_list = db.execute("SELECT cash FROM users WHERE username == %s", session["user_id"])
        cash_asset = cash_asset_list[0]["cash"]
        for i in range(len(assets_list)):
            stock_assets = stock_assets + assets_list[i]["total_price"]

        net_assets = stock_assets + cash_asset

        return render_template("index.html", rows=rows, rows2=rows2, net_assets=net_assets)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # User reached route via GET (as by clicking a link or via redirect)
    if request.method== "GET":
        return render_template("buy.html")
    # User reached route via POST (as by submitting a form via POST)
    else:
        share_dict = lookup(request.form.get("symbol"))
        shares = int(request.form.get("shares"))

        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)
        elif not request.form.get("shares"):
            return apology("must provide number", 403)

        owner_name = session["user_id"]
        symbol = share_dict["symbol"]
        stock_name = share_dict["name"]
        price_unit = share_dict["price"]
        total = float(shares) * price_unit

        # Finding the balance of the user
        cash_list = db.execute("SELECT cash FROM users WHERE username=:username", username=owner_name)
        cash_dict = cash_list[0]
        balance = cash_dict["cash"]

        # If user don't have enough cash
        if balance < total:
            return apology("don't have enough cash")
        # If user has enough cash
        else:
            cash = balance - total
            db.execute("UPDATE users SET cash = ?", cash)
            db.execute("INSERT INTO history (user_name, symbol, amount, t_price, t_type) VALUES (:user_name, :symbol, :amount, :t_price, :t_type)", user_name=owner_name, symbol=symbol, amount=shares, t_price=price_unit, t_type="Purchase")

            existing = db.execute("SELECT stock_symbol FROM stocks WHERE owner_name = ? AND stock_symbol = ?", owner_name, symbol)
            if len(existing) > 0:

                existing_shares_list = db.execute("SELECT shares, total_price FROM stocks WHERE owner_name = ? AND stock_symbol = ?", owner_name, symbol)
                shares = shares + existing_shares_list[0]["shares"]
                total_price = total + existing_shares_list[0]["total_price"]

                db.execute("UPDATE stocks SET shares = ?, total_price = ?", shares, total)

            else:
                db.execute("INSERT INTO stocks (owner_name, stock_symbol, stock_name, shares, unit_price, total_price) VALUES (:owner_name, :stock_symbol, :stock_name, :shares, :unit_price, :total_price)", owner_name=owner_name, stock_symbol=symbol, stock_name=stock_name, shares=shares, unit_price=price_unit, total_price=total)
        return redirect("/")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = db.execute("SELECT symbol, amount, t_price, t_type, t_date FROM history WHERE user_name == %s ORDER BY t_date DESC", session["user_id"])

    return render_template("history.html", rows=rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["username"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # User reached route via GET (as by clicking on the menu)
    if request.method == "GET":
        return render_template("quote.html")

    # User reached route via POST (as by filling the search box)
    else:
        my_dict = lookup(request.form.get("symbol"))
        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)

        # Check if symbol exists
        if my_dict == None:
            return apology("sorry no results")
        else:
            return render_template("quoted.html", my_dict=my_dict)

    #return apology("TODO")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Ensure password was submitted
        elif not request.form.get("password2"):
            return apology("must re-type password", 403)

        # Check the password match
        if request.form.get("password") != request.form.get("password2"):
            return apology("your passwords didn't match")

        # Query database for existing usernames
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

        # Ensure username not exists
        if len(rows) == 1:
            return apology("username exists, please select another")

        # Otherwise insert the user to the users TABLE
        else:
            hashed_pass = generate_password_hash((request.form.get("password")), method='pbkdf2:sha256', salt_length=len(request.form.get("password")))
            db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
                        username=request.form.get("username"), hash=hashed_pass)

        # Return apology if cannot register
        # Query database for username to check
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

        if len(rows) != 1:
            return apology("Sorry something went wrong, please try again")

        # If register succesful
        else:
            return redirect("/login")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # User reached route via GET (as by clicking a link or via redirect)
    if request.method== "GET":
        stock_rows = db.execute("SELECT stock_symbol FROM stocks WHERE owner_name == %s", session["user_id"])
        return render_template("sell.html", stock_rows=stock_rows)
    # User reached route via POST (as by submitting a form via POST)
    else:
        share_dict = lookup(request.form.get("symbol"))
        shares = int(request.form.get("shares"))

        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)
        elif not request.form.get("shares"):
            return apology("must provide number", 403)

        owner_name = session["user_id"]
        symbol = share_dict["symbol"]

        stock_check = db.execute("SELECT stock_id, stock_symbol, shares FROM stocks WHERE owner_name = ? AND stock_symbol = ?", owner_name, symbol)
        if stock_check == 0:
            return apology("You don't have this stock")
        elif stock_check[0]["shares"] < shares:
            return apology("You don't have enough of this stock")
        else:
            price_unit = share_dict["price"]
            total = float(shares) * price_unit
            cash_list = db.execute("SELECT cash FROM users WHERE username=:username", username=owner_name)
            cash_balance = cash_list[0]["cash"]
            balance = cash_balance + total
            db.execute("UPDATE users SET cash = ?", balance)
            db.execute("INSERT INTO history (user_name, symbol, amount, t_price, t_type) VALUES (:user_name, :symbol, :amount, :t_price, :t_type)", user_name=owner_name, symbol=symbol, amount=shares, t_price=price_unit, t_type="Sale")

            if stock_check[0]["shares"] == shares:
                stock_id = stock_check[0]["stock_id"]
                db.execute("DELETE FROM stocks WHERE stock_id = ?", stock_id)
            else:
                balance_shares = stock_check[0]["shares"] - shares
                db.execute("UPDATE stocks SET shares = ?", balance_shares)

        return redirect("/")

@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    """Change Pasword"""
    # User reached route via GET (as by clicking a link or via redirect)
    if request.method== "GET":
        return render_template("change.html")
    else:
        # Ensure new password was submitted
        if not request.form.get("new_password"):
            return apology("must provide password", 403)

        # Ensure new password was submitted
        elif not request.form.get("new_password2"):
            return apology("must re-type password", 403)

        username = session["user_id"]

        hashed_pass = generate_password_hash((request.form.get("new_password")), method='pbkdf2:sha256', salt_length=len(request.form.get("new_password")))
        db.execute("UPDATE users SET hash = ? WHERE username = ?", hashed_pass, username)

        return redirect("/")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)