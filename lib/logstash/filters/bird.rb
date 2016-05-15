# encoding: utf-8
require "socket"
require "logstash/filters/base"
require "logstash/namespace"

# This reads BGP route data from BIRD to add to your flows
#
class LogStash::Filters::Bird < LogStash::Filters::Base
  config_name "bird"

  # Verifications
  #This requires to specify logstash IP field reference as address
  #Path to bird.ctl file, default of /var/run/bird.ctl if not specified
  #Target field path for this data, default output is bgp.fieldname
  config :address, :validate => :string
  config :path, :validate => :string, :default => '/var/run/bird.ctl'
  config :target, :validate => :string, :default => 'bgp'
  def register
    #Nothing
  end # def register

  def filter(event)
    if File.exist?("#{@path}")
      event[@target] = {} if event[@target].nil?
      @addresstry = event.sprintf(event.sprintf(@address))
      @s = UNIXSocket.new("#{@path}")
      @s.puts "show route for #{@addresstry} all"
      @logger.debug("Bird Command  - \"show route for #{@addresstry} all\"")
      #Collect the output and watch for complete / error status codes
      @route_output = ""
      while (@route_output.scan(/\n0000/) == []) and (@route_output.scan(/\n0013/) == []) and (@route_output.scan(/\n[89][0-9]{3}/) == []) do
        if File.exist?("#{@path}")
        @route_output += @s.recvfrom(1024)[0]
        @logger.debug("Bird response:  #{@route_output}")
        end
      end
      #parse the output if successfull code '0000'
      if @route_output.include? "\n0000"
        @netblock = @route_output.scan(/-(\d+\.\d+\.\d+\.\d+\/\d+)/)[0][0]
        @communities = @route_output.scan(/BGP.community: (.*)\n/)
        @communities = "" if @communities.length == 0 or @communities[0][0].empty?
        @communities = @communities[0][0].tr(',',':').delete ")(" if @communities != ""
        @origin = @route_output.scan(/BGP.origin: (\w+)\n/)[0][0]
        @origin = 'Unknown' if @origin.length == 0 or @origin.empty?
        @aspath = @route_output.scan(/BGP.as_path: (.*)\n/)[0][0]
        @aspath = 'Internal' if @aspath.length == 0 or @aspath.empty?
        event[@target]["aspath"] = @aspath
        event[@target]["origin"] = @origin
        event[@target]["communities"] = @communities
        event[@target]["netblock"] = @netblock
        # filter_matched should go in the last line of our successful code
        filter_matched(event)      
      elsif @route_output.include? "\n9001"
        @logger.warn("Bird error: #{@route_output.scan(/9001 (.*)/)[0][0]}")
      elsif @route_output.include? "\n8001"
        @logger.warn("Bird error: #{@route_output.scan(/8001 (.*)/)[0][0]}")
      else
        @logger.warn("Bird error: Unexpected Error")
      end
    end # if file exists
  end #def filter
end # class LogStash::Filters::Bird
