require_relative "gem/security"

# Sample SQL input
input = "JOIN"

# Using the gem to log injection attempts
SecurityLogger::Sql_Injection.new(ip_origin: "123.123.123.1").check_input(input)

input = "<svg"

# Using gem to log xss attempts
SecurityLogger::Xss_Injection.new(ip_origin: "123.123.123.1").check_input(input)

input = "evilhacker"

# Using gem to log xss attempts
SecurityLogger::User_Agent.new(ip_origin: "123.123.123.1").check_input(input)