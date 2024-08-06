# Project Name: Sploosh
# 
# Statement of Purpose:
# The purpose of this program is to ease the process of parsing through access
# log files. This program utilizes the TKinter library to create a GUI for the
# process. The program will read a file chosen by the user, determine whether it
# is a valid access log file when the user attempts to read it. If it is not, the 
# user will be notified to change the chosen file. If it is valid, however, the
# two main functionalities of the program "count" and "search" will be enabled.
#
# search:
#   The search functionality will allow the user to choose a field to search by
#   and then a value to search for. The program will then search through the
#   stored log file data and return every instance where the search value matches.
#   This information will be outputted to the user and stored in a file:
#   output.txt
#
# count:
#   The count functionality will allow the user to choose a field by which to
#   count the number of instances of a value in that field. The program will
#   then output these values and the number of instances to the user.
#
# The program also utilizes SQL as its backend storage method throught the use of
# the SQLLite3 library.
#
# Authors:  Noah Bender
#           Joseph Dabkowski
# Starting: 7/25/2024

# import statement(s)
import os
import re as regex
import tkinter as tk
#import customtkinter as ctk
from tkinter import *
from tkinter import filedialog
from tkinter import Button
from tkinter import ttk
import sqlite3

# global variables

global file_path    # keeps track of the file path for the logs being analyzed.
global file_status  # keeps track of the status of the file being analyzed.

# regex pattern for logs

re_pat = regex.compile(
    r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>[A-Z]+) (?P<endpoint>[^ ]+) HTTP/1.1" '
    r'(?P<status>\d+) (?P<packet_size>\d+) "(?P<referrer>[^"]+)" "(?P<user_agent>[^"]+)" (?P<response_time>\d+)'
)

# legend for dictionary

dict_legend = {
  1: 'ip: ',
  2: 'timestamp: ',
  3: 'method: ',
  4: 'endpoint: ',
  5: 'status: ',
  6: 'packet size: ',
  7: 'referrer: ',
  8: 'user agent: ',
  9: 'response time: '
}

# legend for dropdown menu

dropdown_dict = {
  "IP Address": "ip_addr",
  "Timestamp": "timestamp",
  "Method": "method",
  "Endpoint": "endpoint",
  "Status": "status",
  "Packet Size": "packet_size",
  "Referrer": "referrer",
  "User Agent": "user_agent",
  "Response Time": "response_time"
}

### FUNCTIONS START HERE ###

# function to get the file path for a log file
# uses a standard file explorer window as part of the tkinter library
def browse_files():
  # using global file_path
  global file_path 
  # sets file_path to the user's chosen file
  file_path = filedialog.askopenfilename()
  # Enter the file_path into the text box after it is selected
  t.insert(tk.END, file_path)


# read file takes in a text box and SQLLite3 cursor as parameters
def read_file(t, cursor):
  # global variables
  global file_status  # The file_status global variable determines whether the read_file function can function
  global file_path    # The global file_path will allow for the reading of the chosen file.

  # if the file_path is set to "none", there cannot be an attempt to read it. 
  if file_path == "none":
    t.insert(tk.END, "\nPlease select a file before attempting to read it.")
    return # End function early
  
  # Try to open the selected file
  try:
    # open the file from file_path in read mode
    file = open(file_path,'r')
    # get the lines of the file in an array
    lines = file.readlines()

    # for loop iterates through each line within lines array
    for line in lines:
      # temporary empty variables for SQL command
      ip_addr = ''
      timestamp = ''
      method = ''
      endpoint = ''
      status = ''
      packet_size = ''
      referrer = ''
      user_agent = ''
      response_time = ''

      # check if the line can be split based on the previously defined regex command
      if re_pat.match(line):
        # split the line up based on the re_pat regex command
        match = re_pat.match(line)
        # if match returns true, there was a match found
        if match:
          # set the results of match into a dictionary object line_dict
          line_dict = match.groupdict()
          # Enter the values of the dictionary into the temporary variables
          ip_addr = line_dict['ip']
          timestamp = line_dict['timestamp']
          method = line_dict['method']
          endpoint = line_dict['endpoint']
          status = line_dict['status']
          packet_size = line_dict['packet_size']
          referrer = line_dict['referrer']
          user_agent = line_dict['user_agent']
          response_time = line_dict['response_time']

        # formulate an SQL command with fields for each field of the logs 
        sql_command = "INSERT INTO logs (ip_addr, timestamp, method, endpoint, status, packet_size, referrer, user_agent, response_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        # try to execute the command
        try:
            # execute the command whilst filling in the slots for each field
            cursor.execute(sql_command,
                         (ip_addr, timestamp, method, endpoint, status, int(packet_size),
                          referrer, user_agent, int(response_time)))
        # if the execution failed, it is likely due to an improper command
        except:
          # Output an error statement to the text box
          t.insert("\nInvalid log format detected,\n please attempt again with a different file.")
        # commit the changes to the database connection.
        conn.commit()
        # set the file status to 1, valid
        file_status = 1 # Valid Status
      # if the regex command fails
      else:
        # set the file status to -1, meaning Wrong File Format
        file_status = -1 # Invalid Status - Wrong File Format
    # If the file_status was set to 1
    if (file_status == 1):
      # print a successful read statement
      t.insert(tk.END, "\nFile Read Successfully.")
    # If the file_status was set to -1 (Wrong File Format)
    if (file_status == -1):
      # Output an error statement to the text box
      t.insert(tk.END, "\nInvalid Log Format.")
  # If the file cannot be read (ex. deleted after file_path was chosen)
  except:
    # print error statement to text box
    t.insert(tk.END, "\nInvalid File. Please try again.")
    # set the file status to -2, meaning FNF
    file_status = -2 #Invalid Status - File Not Found

# The count function will count the occurences of each type of log field and return them in dictionary format
def count(search_cur, term):
  # Using search cursor execute the below command to collect all of each column based on the chosen term
  search_cur.execute('SELECT ' + term + ' FROM logs')
  # take the results from the command and store them in rows
  rows = search_cur.fetchall()
  # create an empty dictionary
  count_dict = {}
  # for loop iterates through row in the collected rows
  for row in rows:
    # get the first item in the row and set it as the key
    key = row[0]
    # if the key is in the dictionary
    if key in count_dict:
      # increment the dictionary based on that key by 1
      count_dict[key] += 1
    # if the key is not in the dictionary
    else:
      # create a new dictionary entry based on the key and set it to 1
      count_dict[key] = 1
  # sort the dictionary
  sorted_dict = {key: value for key, value in sorted(count_dict.items(), key=lambda item: item[1], reverse=True)}
  # return the sorted dictionary
  return sorted_dict

# the count_button_click function takes in the cursor as a parameter, it is used from the count button created in the menu
def count_button_click(cursor):
  # using global file_path variable
  global file_path
  # if the file_path is set to none, it indicates that the user has not attempted to select a file, thus it cannot be read
  if (file_path == "none"):
    # send a warning message to the user via the text box
    t.insert(tk.END, "\nPlease select a file before attempting to count.")
    # end the function
    return
  # if the chosen file is found to be in the wrong format, file_status is set to -1
  elif (file_status == -1):
    # send a warning message to the user via the text box
    t.insert(tk.END, "\nThe chosen file is not in the proper format.\nPlease retry with an access log file.")
    # end the function
    return
  # if the chosen file does not exist, file_status is set to -2
  elif (file_status == -2):
    # send a warning message to the user via the text box
    t.insert(tk.END, "\nThe chosen file does not exist.\nPlease retry with an access log file.")
    # end the function
    return
  # if none of the previous conditions are met, it means the file is valid
  else:
    # create a new window for the count functionality
    count_window = tk.Toplevel(window)
    count_window.geometry("300x150")
    # create a label for the count window
    label = tk.Label(count_window, text="Select an option from the dropdown")
    label.pack()
    # set a list of options for the dropdown menu
    options = ["IP Address", "Timestamp", "Method", "Endpoint", "Status", "Packet Size", "Referrer", "User Agent", "Response Time"]
    # create the combo (dropdown) object
    combo = ttk.Combobox(count_window, values=options, state="readonly")
    combo.pack()
    # create a bottomframe to separate the window
    bottom_frame = tk.Frame(count_window)
    bottom_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    # create a textbox within bottom_frame
    text_box = tk.Text(bottom_frame, wrap=tk.WORD)
    text_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    # create a scrollbar so that long outputs can be read
    scrollbar = ttk.Scrollbar(bottom_frame, orient=tk.VERTICAL, command=text_box.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    text_box.config(yscrollcommand=scrollbar.set)
    
    # inner function on_select activates when the combo (dropdown menu) selects an item
    def on_select(event):
      # clear the text box
      text_box.delete("1.0",tk.END)
      # get the selected option from the combo (dropdown menu)
      selected_option = combo.get()
      # Change the label to the selected option
      label.config(text=f"Selected: {selected_option}")
      # get the proper variable name for the selected option via dropdown_dict
      selected_option = dropdown_dict[selected_option]
      # insert the results of the count into the text box 
      text_box.insert(tk.END, outputDict(count(cursor, selected_option)))
    # bind the combo (dropdown menu) to the on_select function
    combo.bind("<<ComboboxSelected>>", on_select)

# debug function - prints a dictionary in a formatted manner given a dictionary as a parameter
def printDict(dict):
  # for every key and value in dictionary's items
  for key, value in dict.items():
    # print the key and respective value
    print(f"{key}:\t\t\t{value}")

# returns a string with a formatted dictionary
def outputDict(dict):
  # create an empty string for output return
  out = ""
  # for every key and value in dictionary's items
  for key, value in dict.items():
    # store the key and respective value in out
    out += f"{key}:\t\t\t{value}\n"
  # return the out
  return out

# searchFile performs a search in the database based on a given term and category and the cursor for the SQL database
def searchFile(cursor, term, cat):
  # create an empty string 
  out = ""
  # open a new file 'output.txt' in write mode
  file = open("output.txt", "w")
  # create an SQL command with an empty place for the category and term
  query = f'SELECT * FROM logs WHERE {cat} LIKE ?'
  # execute the command with the fields filled in
  cursor.execute(query, (f'%{term}%',))
  # retrieve the results from the command into rows
  rows = cursor.fetchall()
  # create a counter variable set to 0
  x = 0
  # loop through the length of the output
  while x < len(rows):
    # for the length of the subarray
    for i in range(1, len(rows[x])):
      # write the output to the file
      file.writelines(dict_legend[i] + str(rows[x][i]) + "\n")
      # append the output to the out variable
      out += dict_legend[i] + str(rows[x][i]) + "\n"
    # write two newlines to the file for formatting
    file.writelines('\n\n')
    # append two newlines to the out variable for formatting
    out += '\n\n'
    # increment the counter variable by 1
    x += 1
  # return the output variable
  return out

# searchFileRange performs a search in the database based on a range of terms (defined by term1 and term2) and category and the cursor for the SQL database
def searchFileRange(cursor, term, term2, cat):
  # create an empty output variable
  out = ""
  # open a new output file in write format
  file = open("output.txt", "w")
  # create a SQL command to retrieve items based on a range in a category
  query = f'SELECT * FROM logs WHERE {cat} BETWEEN {term} AND {term2};'
  # execute the command
  cursor.execute(query)
  # retrieve the results of the command
  rows = cursor.fetchall()
  # create a new counter variable
  x = 0
  # loop throught the length of the output
  while x < len(rows):
    # for the length of the subarray
    for i in range(1, len(rows[x])):
      # write the output to the file
      file.writelines(dict_legend[i] + str(rows[x][i]) + "\n")
      # append the output to the out variable
      out += dict_legend[i] + str(rows[x][i]) + "\n"
    # write two newlines to the file for formatting
    file.writelines('\n\n')
    # append two newlines to the out variable for formatting
    out += '\n\n'
    # increment the counter variable by 1
    x += 1
  # return the output variable
  return out
# search_button_click takes in one parameter cursor and enables the functionality of the search feature
def search_button_click(cursor):
    # using the global file_path variable
    global file_path
    # if the file_path is not defined
    if file_path == "none":
        # write an error statement to the text box
        t.insert(tk.END, "\nPlease select a file before attempting to search.")
        # end the function
        return
    # if the file_status is -1, the file is in the wrong format
    elif file_status == -1:
        # output an error message through the text box
        t.insert(tk.END, "\nThe chosen file is not in the proper format.\nPlease retry with an access log file.")
        # end the function
        return
    # if the file_status is -2, the file DNE
    elif file_status == -2:
        # output an error message through the text box
        t.insert(tk.END, "\nThe chosen file does not exist.\nPlease retry with an access log file.")
        # end the function
        return
    # in any other scenario, the file should be defined and valid
    else:
        # create a new window
        count_window = tk.Toplevel(window)
        count_window.geometry("400x300")
        # Create a new instructional label
        label = tk.Label(count_window, text="Select an option from the dropdown")
        label.pack(pady=10)
        # define the options for the dropdown menu
        options = ["IP Address", "Timestamp", "Method", "Endpoint", "Status", "Packet Size", "Referrer", "User Agent", "Response Time"]
        combo = ttk.Combobox(count_window, values=options, state="readonly")
        combo.pack(pady=10)
        # create a frame for user input
        input_frame = tk.Frame(count_window)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        # create a label to instruct the user to enter a search term
        user_input_label = tk.Label(input_frame, text="Enter your search:")
        user_input_label.pack(side=tk.LEFT, padx=5)
        # create a text box to recieve input from the user
        user_input_text_box = tk.Entry(input_frame)
        user_input_text_box.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        # Create Submit button 
        submit_button = tk.Button(master=count_window, text="Submit", width=10, bg='white', fg='black', activebackground='#AFAFAF', command=lambda: process_input(cursor, combo, user_input_text_box, text_box))
        submit_button.pack(pady=10)
        # inner function for the combo (dropdown box)
        def on_select(event):
            # get the selected option from the dropdown box
            selected_option = combo.get()
            # check if the selected option is "Packet Size" or "Response Time"
            if selected_option == "Packet Size" or selected_option == "Response Time":
                # set the input label to add instructions asking for a range
                user_input_label.config(text="Enter your search range (X-Y):")
            # if it is anything else
            else:
                # set the input label to be what it normally is
                user_input_label.config(text="Enter your search:")
        # set the combo to the on_select inner function
        combo.bind("<<ComboboxSelected>>", on_select)
        # create a bottom frame for the window
        bottom_frame = tk.Frame(count_window)
        bottom_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        # create a text box for the output
        text_box = tk.Text(bottom_frame, wrap=tk.WORD)
        text_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        #inform the user that the output will also be written to a file
        text_box.insert(tk.END, "Your output will also be written to output.txt")
        # create a scrollbar to enable the reading of the entire output
        scrollbar = ttk.Scrollbar(bottom_frame, orient=tk.VERTICAL, command=text_box.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        # set the text_box to have a scrollbar
        text_box.config(yscrollcommand=scrollbar.set)

# process_input takes in the cursor, combo (dropdown box), user input box, and output text box and allows for the usage of the
# search feature within the search window
def process_input(cursor, combo, user_input_text_box, text_box):
  # clear the output text box
  text_box.delete("1.0",tk.END)
  # get the selected option from the dropdown menu
  selected_option = combo.get()
  # set the selected option to its variable name via the dropdown_dict dictionary
  selected_option = dropdown_dict[selected_option]
  # get the user input from the text box
  user_input = user_input_text_box.get()
  # if the selected option is packet_size or response_time, it requires the usage of the searchFileRange function
  if (selected_option == "packet_size") or (selected_option == "response_time"):
    # Split the range by the '-' delimeter
    user_input_arr = user_input.split("-")
    # if the user input is proper (there are two values in the array), continue with the process
    if len(user_input_arr) == 2:
      # get the output of the searchFileRange function
      x = searchFileRange(cursor, user_input_arr[0], user_input_arr[1], selected_option)
      # send the output of the searchFileRange function to the output text box
      text_box.insert(tk.END, x)
    # if the user input is improper
    else:
      # send the output of the regular search file function to the text box
      #   we treat the inserted value as one (which will likely output nothing)
      text_box.insert(tk.END, searchFile(cursor, user_input_arr[0], selected_option))
  # if the chosen category is not packet size or response time
  else:
    # send the output of the regular search file function to the text box
    text_box.insert(tk.END, searchFile(cursor, user_input, selected_option))

### END OF FUNCTIONS SECTION ###

### SET UP SECTION ###

# path variable
path = os.getcwd()
print(path)
# set a directory name
directory = "sploosh"
# if in the working directory, there is not already a sploosh folder
if not os.path.exists(directory):
    # Create the directory based on the directory name
    os.makedirs(directory)
# change the directory to within sploosh directory
os.chdir("sploosh")
# create an SQL database 'logs.db' within sploosh and connect a cursor to the database
conn = sqlite3.connect('logs.db')
# create a cursor to interact with the database
cursor = conn.cursor()
# execute a command that drops the table if the logs database already exists (this is to prevent information overflow)
cursor.execute('''DROP TABLE IF EXISTS logs;''')
# create a new logs table with all of the proper sections
cursor.execute('''CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_addr TEXT, timestamp TEXT, method TEXT, endpoint TEXT, status TEXT, packet_size INT, referrer TEXT, user_agent TEXT, response_time INT)''')

### END OF SET UP SECTION ###

# main function - program driver
if __name__ == '__main__':
  # the file_path is set initially to "none"
  file_path = "none"
  # the file_status is set to 0, meaning that nothing is selected
  file_status = 0
  # create the main window
  window = tk.Tk()
  window.title("Sploosh")
  # set the window background to light blue
  window.configure(bg="lightblue")
  # create a text box and stringVar
  v = StringVar()
  t = Text(window, height = 5, width = 52)
  # create, configure, and pack the buttons
  button_explore = Button(window, text="Browse Files", command=browse_files)
  button_explore.configure(bg="gray")
  button_count = Button(window, text="Count By...", command=lambda: count_button_click(cursor))
  button_count.configure(bg="gray")
  button_read = Button(window, text="Read File", command=lambda: read_file(t,cursor))
  button_read.configure(bg="gray")
  button_search = Button(window, text="Search By...",command=lambda: search_button_click(cursor))
  button_search.configure(bg="gray")
  button_explore.pack()
  button_read.pack()
  button_count.pack()
  button_search.pack()
  # create a new label
  l = Label(window, text = "none")
  # pack the text box
  t.pack()
  # create and pack the label
  l = Label(window, textvariable=v)
  l.pack()
  # start the mainloop
  window.mainloop()
### END OF PROGRAM ###