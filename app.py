import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # grab username, company, and number of shares
    entries = db.execute(
        "SELECT id, company, shares FROM portfolio WHERE id = ?", session["user_id"]
    )

    # grab user cash amount
    cash = float(
        db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    )
    grandtotal = cash

    # find currrent price of each company stock owned
    for entry in entries:
        price = lookup(entry["company"])
        entry["price"] = usd(price["price"])

        # find the total value of the stock bought in each company
        entry["total"] = float(price["price"] * entry["shares"])

        # add that value to the grand total of all funds
        grandtotal += entry["total"]

        # recast the value of the stocks to usd
        entry["total"] = usd(entry["total"])

    return render_template(
        "index.html", entries=entries, cash=usd(cash), grandtotal=usd(grandtotal)
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # When there are inputs into the form
    if request.method == "POST":
        # Get company name
        symbol = request.form.get("symbol")

        # Error catching
        if not symbol:
            return apology("Please enter a company symbol")

        # Find company name and price
        try:
            price = lookup(symbol)["price"]
            company = lookup(symbol)["symbol"]

        # Error catching
        except:
            return apology("Company does not exist")

        # Get number of shares
        try:
            share = int(request.form.get("shares"))
        except:
            return apology("Please enter the number of shares")

        # Error catching
        if int(share) <= 0:
            return apology("Please enter the number of shares")

        # Check users cash
        bpower = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[
            0
        ]["cash"]

        # If not enough cash
        if (price * share) > bpower:
            return apology("Insufficient funds")

        # Otherwise subtract the cost from the cash
        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?",
            bpower - (price * share),
            session["user_id"],
        )

        # Check if the stock has been bought before
        check = db.execute(
            "SELECT * FROM portfolio WHERE id = ? AND company = ?",
            session["user_id"],
            company,
        )

        # If hasn't been bought then create new table
        if len(check) != 1:
            db.execute(
                "INSERT INTO portfolio (id, company, shares) VALUES (?,?,0)",
                session["user_id"],
                company,
            )

        # get previous number of shares owned
        old = db.execute(
            "SELECT shares FROM portfolio WHERE id = ? AND company = ?",
            session["user_id"],
            company,
        )
        old = old[0]["shares"]

        # add purchased shares to previous share number
        new = old + share

        # update shares in portfolio table
        db.execute(
            "UPDATE portfolio SET shares = ? WHERE id = ? AND company = ?",
            new,
            session["user_id"],
            company,
        )

        # update transactions table
        db.execute(
            "INSERT INTO transactions (id, company, shares, type, price) VALUES (?, ?, ?, ?, ?)",
            session["user_id"],
            company,
            share,
            "buy",
            price,
        )

        return redirect("/")

    # Render the template page
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    histories = db.execute(
        "SELECT * FROM transactions WHERE id = ?", session["user_id"]
    )
    return render_template("history.html", histories=histories)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

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
    if request.method == "POST":
        symbol = request.form.get("symbol")
        try:
            price = lookup(symbol)["price"]
            company = lookup(symbol)["symbol"]
        except:
            return apology("Stock does not exist")
        return render_template("quoted.html", price=price, company=company)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # error checking
        check = db.execute("SELECT id FROM users WHERE username = ?", username)
        if len(check) != 0:
            return apology("Username already exists")
        if username == "":
            return apology("Please type in a username")
        if password == "":
            return apology("Please type in a password")

        if password == confirmation:
            hashed = generate_password_hash(password)
            db.execute(
                "INSERT INTO users (username, hash) VALUES(?, ?)", username, hashed
            )
        else:
            return apology("Please ensure your passwords match")
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # When there are inputs into the form
    if request.method == "POST":
        # Get company name
        symbol = request.form.get("symbol")

        # Error catching
        if not symbol:
            return apology("Please enter a company symbol")

        # Find company name and price
        try:
            price = lookup(symbol)["price"]
            company = lookup(symbol)["symbol"]

        # Error catching
        except:
            return apology("Company does not exist")

        # Get number of shares
        try:
            share = int(request.form.get("shares"))
        except:
            return apology("Please enter the number of shares")

        # Error catching
        if int(share) <= 0:
            return apology("Please enter the number of shares")

        # Check number of shares owned
        check = db.execute(
            "SELECT shares FROM portfolio WHERE id = ? AND company = ?",
            session["user_id"],
            company,
        )

        # If never bought before or
        # no shares or
        # trying to sell more shares than owned
        # then not then not possible to sell
        if check[0]["shares"] == 0 or len(check) != 1 or check[0]["shares"] - share < 0:
            return apology("No shares to sell")

        # Grab users cash
        bpower = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[
            0
        ]["cash"]

        # Add price to cash
        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?",
            bpower + (price * share),
            session["user_id"],
        )

        # Subtract sold shares from previous share number
        new = check[0]["shares"] - share

        # update shares in portfolio table
        db.execute(
            "UPDATE portfolio SET shares = ? WHERE id = ? AND company = ?",
            new,
            session["user_id"],
            company,
        )

        # update transactions table
        db.execute(
            "INSERT INTO transactions (id, company, shares, type, price) VALUES (?, ?, ?, ?, ?)",
            session["user_id"],
            company,
            share,
            "sell",
            price,
        )

        return redirect("/")

    # Render the template page
    else:
        symbols = db.execute(
            "SELECT company FROM portfolio WHERE id = ?", session["user_id"]
        )
        return render_template("sell.html", symbols=symbols)


@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    """deposit cash to buy more stock"""
    # When there are inputs into the form
    if request.method == "POST":
        # Get deposit amount
        try:
            deposit = int(request.form.get("deposit"))
        except:
            return apology("Please enter a whole number deposit amount")

        # Error catching
        if deposit <= 0:
            return apology("Please enter a whole number deposit amount")

        old = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0][
            "cash"
        ]

        new = deposit + old

        # Add price to cash
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new, session["user_id"])

        return redirect("/")

    # Render the template page
    else:
        return render_template("deposit.html")
