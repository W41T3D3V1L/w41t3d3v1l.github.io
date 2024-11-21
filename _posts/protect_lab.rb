require 'io/console'

# Set your desired password
PASSWORD = "iamniigs"

def display_protected_file(file_path)
  print "Enter the password to access the content: "
  input_password = STDIN.noecho(&:gets).chomp
  puts "\n" # Newline after password input for neatness

  if input_password == PASSWORD
    if File.exist?(file_path)
      puts "\nAccess granted! Here is the content:\n\n"
      puts File.read(file_path)
    else
      puts "File not found: #{file_path}"
    end
  else
    puts "\nAccess denied! Incorrect password."
  end
end

# Specify the file you want to protect
file_path = "2024-01-05-tryhackme-dodge.md"
display_protected_file(file_path)
