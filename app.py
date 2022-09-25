import os
import datetime
from dateutil import tz
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


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
    # Get data from database
    purchases = db.execute("SELECT purchases.* FROM purchases WHERE user_id = %s", session["user_id"])
    userCash = db.execute("SELECT cash FROM users WHERE id = %s", session["user_id"])
    cash = usd(userCash[0]["cash"])
    total = db.execute(
        "SELECT symbol, name, SUM(shares), price, SUM(total) FROM purchases WHERE user_id = %s GROUP BY symbol ORDER BY purchaseID ASC", session["user_id"])

    # Format floats into USD
    totalCash = 0
    for i in range(len(total)):
        totalCash = totalCash + int(total[i]["SUM(total)"])
        total[i]["SUM(total)"] = usd(total[i]["SUM(total)"])

    # Get change in user's balance
    totalCash += userCash[0]["cash"]

    return render_template("index.html", purchases=purchases, cash=cash, total=total, totalCash=usd(totalCash))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # 'Purchases' table was created for the buy function. Purchase table consists of purchaseid, symbol, name, shares, price, total, and user_id.
    if request.method == "POST":

        # Get information from form.
        stock = request.form.get("symbol")
        shares = request.form.get("shares", type=int)

        # Look up symbol
        stockStrip = stock.strip()
        stock = lookup(stockStrip)

        # Get datestamp
        date = datetime.datetime.now()

        # Check if the symbol provided is valid.
        if stock == None:
            return apology("Invalid stock.", 400)
        elif shares == None:
            return apology("Invalid quantity.", 400)
        elif int(shares) < 1:
            return apology("Invalid quantity.", 400)

        symbol = stock["symbol"]
        name = stock["name"]
        value = stock["price"]

        # Format price to USD
        price = usd(value)

        # Get total amount being spent
        total = value * float(shares)

        # Get the amount of cash that the user currently has and then check if they have enough funds to purchase the amount of shares.
        userCash = db.execute("SELECT cash FROM users WHERE id = %s", session["user_id"])

        # If they do, then subtract the amount of the purchase from their total cash pool.
        if userCash[0]["cash"] >= total:
            userCash[0]["cash"] -= total
            db.execute(
                "UPDATE users SET cash = %s WHERE id = %s", userCash[0]["cash"], session["user_id"])

            # Insert the transaction into the purchases table and then render template where user can explicitly see what they purchased.
            db.execute("INSERT INTO purchases (symbol, name, shares, price, total, user_id, date) VALUES(?, ?, ?, ?, ?, ?, ?)",
                       symbol, name, shares, price, total, session["user_id"], date)
            purchases = db.execute(
                "SELECT purchases.* FROM purchases WHERE user_id = %s ORDER BY purchaseID DESC LIMIT 1", session["user_id"])

            # Change total into USD to limit decimals to only two places while also adding a dollar sign for formatting.

            purchases[0]["total"] = usd(purchases[0]["total"])

            # Get data from database
            cash = usd(userCash[0]["cash"])
            total = db.execute(
                "SELECT symbol, name, SUM(shares), price, SUM(total) FROM purchases WHERE user_id = %s GROUP BY symbol ORDER BY purchaseID ASC", session["user_id"])
            # Format floats into USD
            totalCash = 0
            for i in range(len(total)):
                totalCash = totalCash + int(total[i]["SUM(total)"])
                total[i]["SUM(total)"] = usd(total[i]["SUM(total)"])
            totalCash += userCash[0]["cash"]

            return render_template("bought.html", purchases=purchases, cash=cash, totalCash=usd(totalCash))

        # If they do not have enough funds, then let member know they do not have enough funds.
        else:
            return apology("You do not have enough funds!", 400)

    # If GET, then show user form to make purchase.
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    transactions = db.execute("SELECT * FROM purchases WHERE user_id = (?) ORDER BY purchaseID DESC", session["user_id"])

    for i in range(len(transactions)):
        transactions[i]["total"] = usd(transactions[i]["total"])

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

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

        # Get user input from form. Strip whitespace to ensure search still functions so long as they provide a valid symbol.
        quote = request.form.get("symbol")
        quoteStrip = quote.strip()

        # Look up symbol.
        quote = lookup(quoteStrip)

        # If lookup(quoteStrip) returns an empty list, then render apology. Otherwise, render template with price formatted
        if quote == None:
            return apology("Invalid quote", 400)
        else:
            quote["price"] = usd(quote["price"])
            return render_template("quoted.html", quote=quote)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Get user input from form.
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure user submitted a user name
        if not request.form.get("username"):
            return apology("must provide username", 400)
        # Ensure user submitted a password
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        elif confirmation != password:
            return apology("passwords must match", 400)

        # Validate usernames and password
        if len(username) < 5 or len(username) > 20:
            return apology("username must be between 5 and 20 characters", 403)
        elif len(password) < 8:
            return apology("password must be at least 8 characters", 403)
        elif len(rows) > 0:
            return apology("User already exists", 400)

        # If user does not exist in database, then insert them
        elif len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):

            # Prepare to create user after retrieving user from form and hashing password.
            user = request.form.get("username")

            # validate_username(user, rows) // for some reason, flask is not accepting the arguments I've inserted.
            hash = generate_password_hash(request.form.get("password"))

            # Insert new user into users table and then return to homepage
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", user, hash)
            return render_template("registered.html"), {"Refresh": "1; /"}

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # Get amount of owned stocks from user and their current balance
    owned = db.execute(
        "SELECT symbol, name, SUM(shares), price, SUM(total) FROM purchases WHERE user_id = (?) GROUP BY symbol ORDER BY purchaseID ASC", session["user_id"])
    totalCash = db.execute(
        "SELECT cash FROM users WHERE id = (?)", session["user_id"])

    # Sell
    if request.method == "POST":

        # Look up details of the stock that they want to sell
        stockGet = request.form.get("symbol")

        # if they do not select a symbol, return apology
        if stockGet == None:
            return apology("Please select a symbol", 400)

        stock = lookup(stockGet)
        quantity = request.form.get("shares", type=int)
        symbol = stock["symbol"]

        # Check the amount of shares they have for the share they are trying to sell
        ownedQuantity = db.execute(
            "SELECT SUM(shares) FROM purchases WHERE user_id = (?) GROUP BY symbol HAVING symbol = (?)", session["user_id"], symbol)

        # Else if the user enters anything other than an integer, return apology
        if quantity == None:
            return apology("Invalid quantity")

        name = stock["name"]
        value = stock["price"]
        price = usd(value)

        date = datetime.datetime.now()

        # Total is amount of shares they want to sell, and totalPayout is the amount of money they receive for sale
        total = value * float(quantity) * -1
        totalPayout = value * float(quantity)

        # Else if the quantity they are trying to sell is greater than the amount they own, return apology
        if int(quantity) > ownedQuantity[0]["SUM(shares)"]:
            return apology("You do not have sufficient stocks to sell", 400)

        # Else if user does not input amount greater than 0, return apology
        elif int(quantity) < 1:
            return apology("Invalid quantity", 400)

        # Else execute sale
        else:
            # Amount being sold is inserted as a negative amount
            sellQuantity = -int(quantity)

            # Insert transaction into purchases table
            db.execute(
                "INSERT INTO purchases (symbol, name, shares, price, total, user_id, date) VALUES(?, ?, ?, ?, ?, ?, ?)", symbol, name, sellQuantity, price, total, session["user_id"], date)

            # Adjust user's balance
            newCash = totalCash[0]["cash"] + totalPayout
            db.execute("UPDATE users SET cash = (?) WHERE id = (?)", newCash, session["user_id"])
            ownedAll = db.execute(
                "SELECT * FROM purchases WHERE user_id = (?) ORDER BY purchaseID DESC LIMIT 1", session["user_id"])
            ownedAll[0]["total"] = usd(ownedAll[0]["total"])

            # Get data from database
            userCash = db.execute(
                "SELECT cash FROM users WHERE id = %s", session["user_id"])
            cash = usd(userCash[0]["cash"])
            total = db.execute(
                "SELECT symbol, name, SUM(shares), price, SUM(total) FROM purchases WHERE user_id = %s GROUP BY symbol ORDER BY purchaseID ASC", session["user_id"])
            totalCash = 0

            # Format floats into USD
            for i in range(len(total)):
                totalCash = totalCash + int(total[i]["SUM(total)"])
                total[i]["SUM(total)"] = usd(total[i]["SUM(total)"])
                totalCash += userCash[0]["cash"]

            return render_template("sold.html", ownedAll=ownedAll, cash=cash, totalCash=usd(totalCash))
    else:
        return render_template("sell.html", owned=owned)

if __name__ == '__main__':
    app.run()