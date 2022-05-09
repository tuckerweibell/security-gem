require_relative "gem/builder"

# Sample SQL input
input = "or 1=1"

# Using the gem to log injection attempts
SecurityLogger::Sql_Injection.new().check_input(input)