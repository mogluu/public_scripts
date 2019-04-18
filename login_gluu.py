#!/usr/bin/env python
"""
Login script per interval of time
Author : Mohammad Abudayyeh
Email : support@gluu.org

"""
import ssl
import time
import datetime
import mechanize
import requests
import cookielib
import os
import sys
import string
import signal
ssl._create_default_https_context = ssl._create_unverified_context
exit_now = False
# This is a dictionary that will hold all errors and their counts.
errors = {}
# This variable will hold the count of users through the loop
count = 0
# This variable will hold the failed logins
failedlogins = 0
# Function that will stop python and print error report


def login_report(totalstarttime, count, errors, failedlogins, all):
        print "\nSending results to login_report.log\n"
        totalendtime = time.time()
        loginreport = open("login_report.log", "w+")
        loginreport.write("Total time for all " + str(count) + " users to login was " +
                          str(totalendtime - totalstarttime) + "\n" + "Average Login time " +
                          str(count/(totalendtime - totalstarttime)) + " users per second " + "\n" +
                          "Users logged In:" + str(count) + "\n"+ "Users left / iterations skipped before exit:" +
                          str(all-count) + "\n" + "Number of failed logins:" +
                          str(failedlogins) +
                          "Errors Report : \nNote : Detailed error report can be found ./login_error.log ")
        print "done \n"
        for e in errors : loginreport.write(str(e) + " : " + str(errors[e]) + "\n" )
        print "Total time for all " + str(count) + " users to login was " + str(totalendtime - totalstarttime)
        print "Average Login time " + str(count/(totalendtime - totalstarttime)) + " users per second "
        print "Users logged In:" + str(count) + "\n"+ "Iterations skipped before exit:" + \
              str(all-count) + "\n" + "Number of failed logins:" + str(failedlogins)
        print "Errors Report : \nNote : Detailed error report can be found ./login_error.log "
        for e in errors : print str(e) + " : " + str(errors[e]) + "\n"
        loginreport.close()


def signalReciever(sig, frame):
    global exit_now
    # Warn user a signal has been recieved
    print '\nReceived: ' + str(sig) + '\n'
    exit_now = True


# Function that will handle progress bar and print out dynamically
def progress(count, total, status=''):
        # Length of bar
        bar_len = 5
        # Calculate length  filled so far
        filled_len = int(round(bar_len * count / float(total)))
        # Calculate the finished percent
        percents = round(100.0 * count / float(total), 1)
        # Fill bar with result
        bar = '=' * filled_len + '-' * (bar_len - filled_len)
        # Write to consol line results
        sys.stdout.write('Progress Bar[%s] %s%s|%s\r' % (bar, percents, '%', status))
        # Flush results
        sys.stdout.flush()

# TODO : ADD estimated time to finish
def login(gotourl, gluuurl, username, password, all, waitfor, totalstarttime):
    global exit_now
    # This is a dictionary that will hold all errors and their counts.
    global errors
    # This variable will hold the count of users through the loop
    global count
    # This variable will hold the failed logins
    global failedlogins
    # We start the timer for the login process
    start = time.time()
    # Browser
    br = mechanize.Browser()
    # Cookie Jar
    cj = cookielib.LWPCookieJar()
    br.set_cookiejar(cj)
    # Browsanize.HTTPErrorr options
    br.set_handle_equiv(True)
    br.set_handle_gzip(True)
    br.set_handle_redirect(True)
    br.set_handle_referer(True)
    br.set_handle_robots(False)
    # Follows refresh 0 but not hangs on refresh > 0
    br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)
    br.addheaders = [('user-agent', '   Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.3) Gecko/20100423 '
                                    'Ubuntu/10.04 (lucid) Firefox/3.6.3'),
                     ('accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')]
    printstatus = ''
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    count += 1
    try:
        response = br.open(gotourl)
        br.select_form(nr=0)
        # Let's Login
        br.form['loginForm:username'] = username
        br.form['loginForm:password'] = password
        response = br.submit()
        status = 'Success'
        if 'Failed to authenticate' in response.read():
            failedlogins += 1
            status = 'Failed'
        # Get code from url
        cur_url = br.geturl()
        n = cur_url.find('#code')
        url = br.geturl()[n + 1:]
        # Final Brwosing
        logintime = 0
        logout = "True  "
        if count % 2 == 0:
            br.open(gotourl + '/identity/authentication/getauthcode?' + url)
            br.open(gotourl + '/identity/profile/person/view')
            br.close()
            logout = "False "
        else:
            br.open(gotourl + '/identity/authentication/getauthcode?' + url)
            br.open(gotourl + '/identity/profile/person/view')
            br.open(gluuurl + '/identity/logout')
            br.close()
        end = time.time()
        logintime = end - start
        estimatedtimetofinish = (logintime * (all-count)) / 60

        printstatus = "T:" + str(st) + "|L(s):" + str(round(logintime, 3)) + "|LO:" + str(logout) + "|U:" + \
                      str(count) + "|UL/IL:" + str(all - count) + "|UN:" + \
                      str(username[:username.find("@")]) + "|P:" + str(password) + "|S:" + str(status) + "|ETF:" + \
                      str(round(estimatedtimetofinish)) + " mins"
        if not waitfor:
            time.sleep(60)
        else:
            time.sleep(float(waitfor))
    except Exception as e:
        # Open file to write errors to
        logerrors = open("login_error.log", "w+")
        if not errors.get(str(e)):
            errors[str(e)] = 0
        errors[str(e)] += 1
        failedlogins += 1
        logerrors.write(str(st) + " : " + str(e) + " : " + str(errors[str(e)]) + "\n")
        printstatus = str(st) + " : " + str(e) + " : " + str(errors[str(e)]) + " | Failed User Logins : " \
                      + str(failedlogins)
        # This closes the error log file
        logerrors.close()
    progress(count, all, status=printstatus)
    check_signal()
    if exit_now:
        login_report(totalstarttime, count, errors, failedlogins, all)
        sys.exit(0)


def check_signal():
    signal.signal(signal.SIGHUP, signalReciever)
    signal.signal(signal.SIGINT, signalReciever)
    signal.signal(signal.SIGQUIT, signalReciever)
    signal.signal(signal.SIGILL, signalReciever)
    signal.signal(signal.SIGTRAP, signalReciever)
    signal.signal(signal.SIGABRT, signalReciever)
    signal.signal(signal.SIGBUS, signalReciever)
    signal.signal(signal.SIGFPE, signalReciever)
    signal.signal(signal.SIGUSR1, signalReciever)
    signal.signal(signal.SIGSEGV, signalReciever)
    signal.signal(signal.SIGUSR2, signalReciever)
    signal.signal(signal.SIGPIPE, signalReciever)
    signal.signal(signal.SIGALRM, signalReciever)
    signal.signal(signal.SIGTERM, signalReciever)


def main():
        # This is a dictionary that will hold all errors and their counts.
        global errors
        global count
        # This variable will hold the failed logins
        global failedlogins
        password_list = []
        numberofusers = 0
        iterationnumber = 0
        password = ''
        username = ''
        f = ''
        choices = ['y', 'Y', 'YES', 'yes', '']
        # start timer for the whole process
        totalstarttime = time.time()
        # Gluu URL
        gluuurl = raw_input("Enter the Gluu URL (https://example.gluu.com) : \n")
        # This can be the same as the above going through Gluu directly, SP URL, or RP URL
        gotourl = raw_input('Enter the URL for SP or RP that you are testing through.\n'
                            'This can be the same as the URL you provided above'
                            ' if you are testing through Gluu identity directly\n')
        choice = raw_input('Are you loading users through gluu_people.txt generated '
                           'from the user addition script?[Y|N]\n')
        choice_bool = False
        choice_pass = False
        if choice.strip() in choices:
            choicepass = raw_input('Are you loading passwords through gluu_password.txt ?[Y|N]\n')
            choice_bool = True
            try:
                numberofusers = sum([1 for i in open("gluu_people.txt", "r").readlines() if i.strip()])
                if choicepass.strip() in choices:
                    choice_pass = True
                    p = open("gluu_password.txt", "r")
                    for line in p:
                        password_list.append(line.strip())
                    if numberofusers == len(password_list):
                        print "You have " + str(numberofusers) + " users and " + str(len(password_list)) + " passwords."
                    else:
                        print "Error: You have " + str(numberofusers) + " users and " + str(len(password_list)) + \
                              " passwords. Please make sure that all users have passwords or vice versa. \n " \
                              "Hint: if user Arnold was on line 1 in the gluu_people.txt his password 1234 would " \
                              "be on line 1 in the gluu_password.txt.\nExiting now..."
                        sys.exit(0)
                f = open("gluu_people.txt", "r")

            except Exception as e:
                print e
        else:
            username = raw_input("Enter the username (me.blah@sun.com) : \n")
            password = raw_input("Enter password, If left empty it will extract the "
                                 "password (user.password@gmail.com) from the username : \n")
            iterationnumber = int(input("Enter how many times you want this user to login : \n"))
        waitfor = raw_input("Enter time interval in seconds between each login "
                            "(If left empty 60s is the default) : \n")
        rerun = int(input("How many times do you want to rerun this test"
                            "(If left empty 1000 is the default) : \n"))
        if not rerun :
                rerun = 1000
        # Print descriptions of the progress bar

        print "T = Time of login\nL(s) = Time to login\nLO = logout boolean\nU = Users logged " \
              "in so far\nUL/IL = Users left/Iterations left \nUN = Username\nP = Password\nS = Status" \
              "\nETF = Estimated time until finish"
        # User is using gluu_people.txt
        if choice_bool:
                i = 0
                print " Rerunning again"
                while i < rerun:
                    i += 1
                    for username in f:
                        # Extract password from the username
                        # user does not have a gluu_password.txt so will extract pass
                        if not choice_pass:
                            password = username[username.find(".") + 1: username.find("@")]
                        else:
                            password = password_list[count]
                            if not password:
                                password = ''
                        login(gotourl, gluuurl, username, password, numberofusers, waitfor, totalstarttime)
                    login_report(totalstarttime, count, errors, failedlogins, numberofusers)
        else:
            # Start loop of usernames with analysis of users
            while count < iterationnumber:
                if not password:
                    password = username[username.find(".") + 1: username.find("@")]
                login(gotourl, gluuurl, username, password, iterationnumber, waitfor, totalstarttime)
            login_report(totalstarttime, count, errors, failedlogins, iterationnumber)
        # -------------------------------


if __name__ == "__main__":
    main()
