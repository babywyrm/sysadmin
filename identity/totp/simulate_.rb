# A proof of concept to demonstrate TOTP bruteforcing concepts

# Parameters to control simulation behavior###
request_rate = 4
totp_validity_window = 90 #in seconds
totp_guesses_per_auth_session = request_rate * totp_validity_window # number of totp guesses per auth session
simulated_logins = 100 # number of simulated logins to help determine average rate of TOTP collision
##############################################

# Helper Methods
def get_totp(totp_size = 6)
  totp = ""
  totp_size.times { totp << Random.rand(10).to_s }
  return totp
end

def seconds_to_units(seconds)
  '%d days, %d hours, %d minutes, %d seconds' %
    # the .reverse lets us put the larger units first for readability
    [24,60,60].reverse.inject([seconds]) {|result, unitsize|
      result[0,0] = result.shift.divmod(unitsize)
      result
    }
end
##############################################

# Run simulation
samples = []

simulated_logins.times do |simulation_number|
  puts "Running sumulation #{simulation_number + 1}..."
  # Keep going until we get a token collision
  1.step do |i|
    # Login Attempt
    secret_token = get_totp
    guessed = false

    totp_guesses_per_auth_session.times do
      # Token guess in login
      guess_token = get_totp
      if secret_token == get_totp
        samples << i
        guessed = true
        break
      end
    end
    break if guessed == true
  end
end
##############################################

# Reporting
average_logins_to_collision = (samples.inject{ |sum, el| sum + el }.to_f / samples.size)
lowest_logins_to_collision = samples.sort[0]
highest_logins_to_collision = samples.sort[-1]

# Number of requests required to break
request_average = (totp_guesses_per_auth_session + 1) * average_logins_to_collision
request_low = (totp_guesses_per_auth_session + 1) * lowest_logins_to_collision
request_high = (totp_guesses_per_auth_session + 1) * highest_logins_to_collision

# Time to break is based on request rate in the window + one login request
time_average = request_average / request_rate.to_f
time_lowest = request_low / request_rate.to_f
time_highest = request_high / request_rate.to_f

puts "Test Parameters:"
puts "  - Request Rate: #{request_rate} requests/second"
puts "  - TOTP Validity Window: #{totp_validity_window} seconds"
puts "  - TOTP Guesses Per Login: #{totp_guesses_per_auth_session}"
puts "  - Simulations Run: #{simulated_logins}"
puts ""
puts "On average, an attacker requires the following to guess a TOTP:"
puts "  - Logins: #{average_logins_to_collision.ceil}"
puts "  - Requests: #{request_average.ceil}"
puts "  - Time: #{seconds_to_units(time_average)}"
puts ""
puts "Best case, an attacker requires the following to guess a TOTP:"
puts "  - Logins: #{lowest_logins_to_collision.ceil}"
puts "  - Requests: #{request_low.ceil}"
puts "  - Time: #{seconds_to_units(time_lowest)}"
puts ""
puts "Worst case, an attacker requires the following to guess a TOTP:"
puts "  - Logins: #{highest_logins_to_collision.ceil}"
puts "  - Requests: #{request_high.ceil}"
puts "  - Time: #{seconds_to_units(time_highest)}"
##############################################
