=begin   

    SecurityLogger 
    ______________

    Description:
    This module provides a simple and unified format to log security events

    Classes: 
    Sql_Injection, Xss_Injection, User_Agent

    Owner:
    Tucker Weibell - 05/09/2022

=end

require 'json'
require 'logger'
require 'logger/formatter'
require 'net/http'
require 'dotenv'
require 'colored'
require 'fuzzystringmatch'
Dotenv.load

module SecurityLogger

=begin

    Sql_Injection Class
    ___________________
    
    Description:
    - Checks inputs against most commonly used sql injection commands.
    - Inputs that match or contain probably sql commands will be logged.
    - Payloads can be replaced by simply changing the ENV varibles
      and pointing the URI to any custom text file

    Usage: SecurityLogger::Sql_Injection.new(ip_origin: request.ip).check_input(input)

=end 

    class Sql_Injection

        def initialize (ip_origin:)
            @ip_origin = ip_origin
        end

        # Logs injection attemps in json format to STDOUT
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

        # Checks for fuzzy string match using Levenshtein distance
        def check_input(input)
            uri = ENV['PATH_TO_SQL_COMPLETE_LIST']
            uri = URI(uri)
            file = Net::HTTP.get(uri)
            fuzzy = FuzzyStringMatch::JaroWinkler.create( :pure )
            file.each_line do |line|
                distance = fuzzy.getDistance(input, line)
                if distance >= 0.75
                    self.log(input)
                    break
                end
            end

        end
    end


=begin  

    Xss_Injection Class
    ___________________
    
    Description:
    - Checks inputs against most commonly used xss scripts.
    - Inputs that match or contain common keywords will be logged.
    - Payloads can be replaced by simply changing the ENV varibles
      and pointing the URI to any custom text file

    Usage: SecurityLogger::Xss_Injection.new(ip_origin: request.ip).check_input(input)

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
            puts
            logger.warn(JSON.parse(message.to_json))
            puts
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


=begin  

    User_Agent Class
    ___________________
    
    Description:
    - Checks inputs against most common user_agents (approx. top 1000).
    - Inputs that DO NOT match any of the most common user agents will be logged.
    - Payloads can be replaced by simply changing the ENV varibles
      and pointing the URI to any custom text file

    Usage: SecurityLogger::User_Agent.new(ip_origin: request.ip).check_input(input)

=end 

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
            puts
            logger.warn(JSON.parse(message.to_json))
            puts
        end

        def check_input(input)
          uri = ENV['PATH_TO_USER_AGENT_PAYLOAD']
          uri = URI(uri)
          file = Net::HTTP.get(uri)
          @matches = 0
            file.each_line do |file|
                if file.strip == input.strip
                @matches += 1
                end
            end

            if @matches == 0
                self.log(input.strip)
                return
            end
        end
    end
end