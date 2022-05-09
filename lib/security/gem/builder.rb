require 'json'
require 'logger'
require 'logger/formatter'
require 'open-uri'


module SecurityLogger

    #Create logs used for SQL Injection detections
    class Sql_Injection
        def initialize
            
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

            error = {:input => input}
            logger.warn(JSON.parse(error.to_json))
        end

        def check_input(input)
            File.foreach('payloads.txt') do |file|
                if file.strip == input.strip
                    self.log(input.strip)
                    break
                end
              end
        end
    end
end