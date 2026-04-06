$LOAD_PATH.unshift File.join(__dir__, 'lib')
require 'dotenv/load'
require 'dashboard/app'
run SentinelIAM::Dashboard::App
