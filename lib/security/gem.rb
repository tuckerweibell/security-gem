# frozen_string_literal: true

require_relative "gem/version"
require_relative "gem/builder"
require 'socket'

module Security
  module Gem
    class Error < StandardError; end
  end
end

input = "delete"

SecurityLogger::Sql_Injection.new().check_input(input)

