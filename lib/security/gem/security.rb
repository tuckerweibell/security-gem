=begin   

    SecurityLogger 
    ______________

    Description:
    This module provides a simple and unified format to log security events

    Owner:
    Tucker Weibell - 05/09/2022

=end

require 'json'
require 'logger'
require 'logger/formatter'
require 'net/http'
require 'dotenv'
Dotenv.load

module SecurityLogger

=begin  

    Sql_Injection Class
    ___________________
    
    Description:
    - Checks inputs against most commonly used sql injection commands.
    - Inputs that match or contain probably sql commands will be logged.
    - Payloads to verify against can be replaced by simply changing the ENV varibles
      and pointing the URI to any custom text file

    Usage: SecurityLogger::Sql_Injection.new(ip_origin: request.ip).check_input(input)

=end 

    class Sql_Injection
        def initialize (ip_origin:)
            @ip_origin = ip_origin
        end

        def log(input)
            logger = Logger.new(STDOUT)
            logger.formatter = proc do |severity, datetime, progname, msg|
                {
                  severity: severity,
                  timestamp: datetime.to_s,
                  app: progname,
                  message: msg
                }.to_json + $/  
            end

            message = {:threat => "sql_injection_attack", :input => input, :ip_origin => @ip_origin}
            logger.warn(JSON.parse(message.to_json))
            return
        end

        def check_input(input)
          uri = ENV['PATH_TO_SQL_PAYLOAD']
          uri = URI(uri)
          file = Net::HTTP.get(uri)
            file.each_line do |file|
                if file.strip == input.strip
                    self.log(input.strip)
                    return
                end
            end

          uri = ENV['PATH_TO_SQL_COMMON_COMMANDS']
          uri = URI(uri)
          file = Net::HTTP.get(uri)
            file.each_line do |file|
                if  input.strip.downcase.include?(file.strip.downcase)
                    self.log(input.strip)
                    return
                end
            end  

        end
    end


=begin  

    Xss_Injection Class
    ___________________
    
    Description:
    - Checks inputs against most commonly used xss scripts.
    - Inputs that match or contain probably scripts will be logged.
    - Payloads to verify against can be replaced by simply changing the ENV varibles
      and pointing the URI to any custom text file

    Usage: SecurityLogger::Sql_Injection.new(ip_origin: request.ip).check_input(input)

=end 

    class Xss_Injection
        def initialize (ip_origin:)
            @ip_origin = ip_origin
        end

        def log(input)
            logger = Logger.new(STDOUT)
            logger.formatter = proc do |severity, datetime, progname, msg|
                {
                  severity: severity,
                  timestamp: datetime.to_s,
                  app: progname,
                  message: msg
                }.to_json + $/  
            end

            message = {:threat => "xss_attack", :input => input, :ip_origin => @ip_origin}
            logger.warn(JSON.parse(message.to_json))
        end

        def check_input(input)
          uri = ENV['PATH_TO_XSS_PAYLOAD']
          uri = URI(uri)
          file = Net::HTTP.get(uri)
            file.each_line do |file|
                if file.strip == input.strip
                    self.log(input.strip)
                    return
                end
            end

          uri = ENV['PATH_TO_XSS_COMMON_SCRIPTS']
          uri = URI(uri)
          file = Net::HTTP.get(uri)
            file.each_line do |file|
                if  input.strip.downcase.include?(file.strip.downcase)
                    self.log(input.strip)
                    return
                end
            end 

        end
    end

    class User_Agent
        def initialize (ip_origin:)
            @ip_origin = ip_origin
        end

        def log(input)
            logger = Logger.new(STDOUT)
            logger.formatter = proc do |severity, datetime, progname, msg|
                {
                  severity: severity,
                  timestamp: datetime.to_s,
                  app: progname,
                  message: msg
                }.to_json + $/  
            end

            message = {:threat => "uncommon_user_agent", :input => input, :ip_origin => @ip_origin}
            logger.warn(JSON.parse(message.to_json))
        end

        def check_input(input)
          uri = ENV['PATH_TO_USER_AGENT_PAYLOAD']
          uri = URI(uri)
          file = Net::HTTP.get(uri)
            file.each_line do |file|
                if file.strip == input.strip
                    self.log(input.strip)
                    return
                end
            end

        end
    end
end