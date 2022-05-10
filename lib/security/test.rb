require_relative "gem/security"

# Sample SQL input
input = "or 1=1"

# Using the gem to log injection attempts
SecurityLogger::Sql_Injection.new(ip_origin: "123.123.123.1").check_input(input)

input = "<script>alert(0)</script>"

# Using gem to log xss attempts
SecurityLogger::Xss_Injection.new(ip_origin: "123.123.123.1").check_input(input)