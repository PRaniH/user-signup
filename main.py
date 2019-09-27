
from flask import Flask, request, redirect, render_template
import cgi, re

app = Flask(__name__)

app.config['DEBUG'] = True

username = ""
password = ""
verify = ""
email = ""

"""If the user's form submission is not valid, you should reject it and re-render the form with some feedback to inform the user
 of what they did wrong. The following things should trigger an error:
 
The user leaves any of the following fields empty: username, password, verify password.
The user's username or password is not valid -- for example, it contains a space character or it consists of less than 3 
characters or more than 20 characters (e.g., a username or password of "me" would be invalid).
The user's password and password-confirmation do not match.
The user provides an email, but it's not a valid email. Note: the email field may be left empty, but if there is content in it,
 then it must be validated. The criteria for a valid email address in this assignment are that it has a single @, a single ., 
 contains no spaces, and is between 3 and 20 characters long.
Each feedback message should be next to the field that it refers to.

For the username and email fields, you should preserve what the user typed, so they don't have to retype it. With the password 
fields, you should clear them, for security reasons. """


#The user leaves any of the following fields empty: username, password, verify password. Below is generic function to check.
def is_not_empty(input_string):
    if input_string == "":
        return False
    else:
        return True
    
def is_ok_characters(input_string):
    if (len(input_string) >= 3) and (len(input_string) <= 20):
        if input_string.isalnum(): #Unclear if this working, seems to be
            return True
        else:
            return False
    else:
        return False

#The user's username or password is not valid -- for example, it contains a space character or it consists of less than 3 
#characters or more than 20 characters (e.g., a username or password of "me" would be invalid).


@app.route("/", methods=['POST'])
def validate_user_input(): 
    username = request.form['username'] #Note that this does not seem to be saving the spaces if any entered by user
    password = request.form['password']
    verify = request.form['verify']
    email = request.form['email']

    if not is_not_empty(username):
        username_error="Username is a required field."
    elif not is_ok_characters(username):
        username_error="Username must be alphanumeric, must not contain any spaces, and must be between 3 and 20 characters long."
    else:
        username_error="" #unclear if this is needed but putting for now

    if not is_not_empty(password):
        password_error="Password is a required field."
    elif not is_ok_characters(password):
        password_error="Password must be alphanumeric, must not contain any spaces, and must be between 3 and 20 characters long."
    else:
        password_error="" #unclear if this is needed but putting for now

    if not is_not_empty(verify):
        verify_error="Verify Password is a required field."
    elif verify != password:
        verify_error="Verify Password must match the Password field."
    else:
        verify_error="" #unclear if this is needed but putting for now

    if not is_not_empty(email): #If there is nothing in e-mail field
        email_error=""
    else:
        if not ((len(email) >= 3) and (len(email) <= 20)): #Check length
            email_error="E-mail is too short. E-mail must be between 3 and 20 characters long, contain no spaces, contain a single @, and contain a single . (period)."
        else:
            if not re.match("^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$", email):
                email_error="E-mail must be between 3 and 20 characters long, contain no spaces, contain a single @, and contain a single . (period)."
            else:
                email_error=""


            """Old unused and incomplete code, left here for posterity:
            at_count = 0
            period_count = 0

            for char in email:
                if char==" ":
                    email_error="Email contains a space. E-mail must be between 3 and 20 characters long, contain no spaces, contain a single @, and contain a single . (period)." #Turn the last part of this into a string
                    break
                else:
                    if char == "@":
                        at_count += 1
                        if at_count > 1:
                            email_error="Email contains more than one @."
                            break
                    else:
                        if char==".":
                            period_count += 1
                            if period_count > 1:
                                email_error="Email contains more than one . (period)."
                                break

            if (at_count == 0 or period_count == 0) and (email_error==""): #Have to check there is at least one!
                email_error="You are missing an @ or a ."
            else:
                email_error=""

If all the input is valid, then you should show the user a welcome page that uses the username input to display a welcome 
message of: "Welcome, [username]!" """

    if (username_error or password_error or verify_error or email_error):
        return render_template('index.html', username=username, username_error=username_error, password_error=password_error, verify_error=verify_error, email=email, email_error=email_error)
    else:
        return redirect("/welcome?username=" + username)

@app.route("/welcome")
def welcome():
    username = request.args.get("username")
    return render_template('welcome.html', username=username)

@app.route("/")
def index():

    encoded_error = request.args.get("error")

    #Use templates (one for the index/home page and one for the welcome page) to render the HTML for your web app.
    return render_template('index.html', error=encoded_error and cgi.escape(encoded_error, quote=True))


app.run()

