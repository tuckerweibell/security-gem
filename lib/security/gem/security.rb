require 'json'
require 'logger'
require 'logger/formatter'
require 'net/http'
require 'open-uri'
require 'dotenv'
Dotenv.load

module SecurityLogger

    #Create logs used for SQL Injection detections
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

            error = {:input => input, :ip_origin => @ip_origin}
            logger.warn(JSON.parse(error.to_json))
        end

        def check_input(input)
          uri = ENV['PATH_TO_SQL_PAYLOAD']
          uri = URI(uri)
          file = Net::HTTP.get(uri)
            file.each_line do |file|
                if file.strip == input.strip
                    self.log(input.strip)
                    break
                end
            end

        end
    end

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

            error = {:input => input, :ip_origin => @ip_origin}
            logger.warn(JSON.parse(error.to_json))
        end

        def check_input(input)
          uri = ENV['PATH_TO_SQL_PAYLOAD']
          uri = URI(uri)
          file = Net::HTTP.get(uri)
            file.each_line do |file|
                if file.strip == input.strip
                    self.log(input.strip)
                    break
                end
            end

        end
    end
end