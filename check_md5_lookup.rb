#!/usr/bin/env ruby

# Simple syntax checker for md5_lookup.rb
puts "Checking Ruby syntax for md5_lookup.rb..."

begin
  # Try to load the file to check for syntax errors
  load '/workspace/tools/password/md5_lookup.rb'
  puts "✓ Syntax check passed"
  
  # Check if the expected module exists
  if defined?(Md5LookupUtility)
    puts "✓ Md5LookupUtility module defined"
    
    # Check if expected classes exist
    classes_to_check = ['Disclaimer', 'Md5Lookup', 'Driver', 'OptsConsole']
    classes_to_check.each do |class_name|
      if Md5LookupUtility.const_defined?(class_name)
        puts "✓ #{class_name} class defined"
        
        # Try to instantiate the class (except OptsConsole which has class methods)
        if class_name != 'OptsConsole'
          begin
            klass = Md5LookupUtility.const_get(class_name)
            instance = klass.new
            puts "✓ #{class_name} can be instantiated"
          rescue => e
            puts "✗ #{class_name} instantiation failed: #{e.message}"
          end
        else
          # Check if OptsConsole has expected class methods
          klass = Md5LookupUtility.const_get(class_name)
          methods_to_check = ['parse', 'extract_db_names', 'get_database_symbols', 'get_database_names']
          methods_to_check.each do |method_name|
            if klass.respond_to?(method_name)
              puts "✓ OptsConsole.#{method_name} method exists"
            else
              puts "✗ OptsConsole.#{method_name} method missing"
            end
          end
        end
      else
        puts "✗ #{class_name} class not defined"
      end
    end
  else
    puts "✗ Md5LookupUtility module not defined"
  end
  
rescue SyntaxError => e
  puts "✗ Syntax error: #{e.message}"
rescue LoadError => e
  puts "✗ Load error: #{e.message}"
rescue => e
  puts "✗ Other error: #{e.message}"
end